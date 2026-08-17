package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/go-logr/logr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configstreamv1 "github.com/kubewarden/gateway-protector/internal/configstream/v1"
)

// ConfigServer implements the controller side of the config stream (see
// proto/configstream/v1/config_stream.proto): it holds the latest
// processor configuration and pushes it to every currently connected
// processor replica over a long-lived gRPC stream. This is what makes
// GRPCPublisher's Publish calls actually reach the data plane; register
// ConfigServer with configstreamv1.RegisterConfigStreamServiceServer on the
// controller's own gRPC server (see cmd/controller/main.go).
//
// A processor replica dialing in gets pushed the current config
// immediately, and again every time GRPCPublisher.Publish is called, and
// sends back a per-replica ConfigAck reporting whether it applied
// successfully.
type ConfigServer struct {
	configstreamv1.UnimplementedConfigStreamServiceServer

	mu          sync.Mutex
	latest      *configstreamv1.ConfigSnapshot
	subscribers map[*subscription]struct{}
}

// NewConfigServer creates an empty ConfigServer: it starts serving no
// config until the first Publish call.
func NewConfigServer() *ConfigServer {
	return &ConfigServer{subscribers: make(map[*subscription]struct{})}
}

// subscription is one connected processor replica's outgoing snapshot
// queue. It is single-slot and latest-wins (see enqueue): a subscriber
// that's slow to drain its stream should skip straight to the newest
// config rather than working through a backlog of already-superseded
// ones.
type subscription struct {
	id string
	ch chan *configstreamv1.ConfigSnapshot
}

func newSubscription(id string) *subscription {
	return &subscription{id: id, ch: make(chan *configstreamv1.ConfigSnapshot, 1)}
}

// enqueue replaces whatever snapshot is queued but not yet sent with
// snapshot.
func (s *subscription) enqueue(snapshot *configstreamv1.ConfigSnapshot) {
	for {
		select {
		case s.ch <- snapshot:
			return
		default:
		}

		select {
		case <-s.ch:
		default:
		}
	}
}

// Publish stores snapshot as the latest configuration and pushes it to
// every currently connected subscriber, skipping the no-op case where
// snapshot's version (a content hash - see GRPCPublisher.Publish) matches
// what was last published.
func (s *ConfigServer) Publish(snapshot *configstreamv1.ConfigSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.latest != nil && s.latest.GetVersion() == snapshot.GetVersion() {
		return
	}
	s.latest = snapshot

	for sub := range s.subscribers {
		sub.enqueue(snapshot)
	}
}

// latestForTest returns the most recently Published snapshot, or nil if
// none has been published yet. It exists only so envtest specs (see
// processor_config_reconciler_test.go) can assert on what ConfigServer
// would push to a subscriber without needing a real subscriber connected.
func (s *ConfigServer) latestForTest() *configstreamv1.ConfigSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.latest
}

// StreamConfig implements configstreamv1.ConfigStreamServiceServer. The
// subscriber's first message must be a Subscribe; ConfigServer then pushes
// the latest snapshot (if any) plus every subsequent Publish to it, and
// logs every ConfigAck it sends back.
func (s *ConfigServer) StreamConfig(stream configstreamv1.ConfigStreamService_StreamConfigServer) error {
	ctx := stream.Context()

	initial, err := stream.Recv()
	if err != nil {
		logf.FromContext(ctx).Error(err, "Failed to receive the config stream's initial subscribe message")
		return fmt.Errorf("failed to receive the config stream's initial subscribe message: %w", err)
	}
	subscribeMsg := initial.GetSubscribe()
	if subscribeMsg == nil {
		return status.Error(codes.InvalidArgument, "the first message on the config stream must be Subscribe") //nolint:wrapcheck // a gRPC status error is the correct thing to return unwrapped from a gRPC handler
	}

	logger := logf.FromContext(ctx).WithValues("subscriber", subscribeMsg.GetSubscriberId())
	sub := s.register(subscribeMsg.GetSubscriberId())
	defer s.unregister(sub)

	logger.Info("Processor subscribed to config stream")
	defer logger.Info("Processor unsubscribed from config stream")

	acks, recvErrs := s.receiveAcks(ctx, stream)

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-recvErrs:
			if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled {
				// io.EOF: the subscriber called CloseSend. Canceled: the
				// far more common case in practice - Subscriber.Run just
				// cancels its own context and closes the connection on
				// shutdown, which surfaces here as a Canceled status, not
				// io.EOF. Both are routine disconnects (a processor pod
				// stopping/restarting), already covered by the
				// "unsubscribed" log line below; logging them as errors
				// would turn every ordinary rollout into log noise.
				return nil
			}
			logger.Error(err, "Config stream receive failed")
			return fmt.Errorf("config stream receive failed: %w", err)
		case ack := <-acks:
			logAck(logger, ack)
		case snapshot := <-sub.ch:
			if err := stream.Send(&configstreamv1.StreamConfigResponse{Snapshot: snapshot}); err != nil {
				logger.Error(err, "Failed to send config snapshot", "version", snapshot.GetVersion())
				return fmt.Errorf("failed to send config snapshot: %w", err)
			}
		}
	}
}

// register adds a new subscription for subscriberID, immediately enqueuing
// the latest published snapshot (if any) for it.
func (s *ConfigServer) register(subscriberID string) *subscription {
	sub := newSubscription(subscriberID)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.subscribers[sub] = struct{}{}
	if s.latest != nil {
		sub.enqueue(s.latest)
	}

	return sub
}

// unregister removes sub from s.subscribers.
func (s *ConfigServer) unregister(sub *subscription) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.subscribers, sub)
}

// receiveAcks starts a goroutine that reads every ConfigAck off stream,
// forwarding it on the returned channel, until ctx is done or stream.Recv
// fails - in which case that error is sent on the second returned channel
// (buffered, so the goroutine can always exit even if nothing ever reads
// from it). This goroutine never logs the error itself: StreamConfig's
// select loop is the sole consumer of recvErrs, and it has the
// subscriber-scoped logger (see StreamConfig's own logger.Error calls).
func (s *ConfigServer) receiveAcks(ctx context.Context, stream configstreamv1.ConfigStreamService_StreamConfigServer) (<-chan *configstreamv1.ConfigAck, <-chan error) {
	acks := make(chan *configstreamv1.ConfigAck)
	recvErrs := make(chan error, 1)

	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				select {
				case recvErrs <- err:
				case <-ctx.Done():
				}
				return
			}
			if ack := req.GetAck(); ack != nil {
				select {
				case acks <- ack:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return acks, recvErrs
}

// logAck logs a subscriber's ConfigAck: an Info line for a successfully
// applied config, an Error line (with the subscriber-reported reason) for
// a rejected one. See docs/processor.md's "Config stream" section: a
// rejection is expected and harmless in isolation (the subscriber keeps
// serving its previous config), but repeated rejections across replicas is
// worth alerting on - hence logging both outcomes here rather than only
// failures.
func logAck(logger logr.Logger, ack *configstreamv1.ConfigAck) {
	if ack.GetApplied() {
		logger.Info("Processor applied config", "version", ack.GetVersion())
		return
	}
	logger.Error(errors.New(ack.GetError()), "Processor rejected config", "version", ack.GetVersion())
}
