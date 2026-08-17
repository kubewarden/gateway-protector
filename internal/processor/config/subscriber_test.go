package config

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	configstreamv1 "github.com/kubewarden/gateway-protector/internal/configstream/v1"
)

const subscriberTestBufSize = 1024 * 1024

const validConfigJSON = `{
  "directives": {"a": "SecRuleEngine On"},
  "routes": [
    {"host": "example.com", "pathPrefix": "/", "waf": {"engineKey": "a"}}
  ]
}`

// fakeConfigStreamServer is a minimal, test-only implementation of
// configstreamv1.ConfigStreamServiceServer standing in for
// internal/controller.ConfigServer: it lets tests push snapshots to
// exactly one connected subscriber and record every ConfigAck it sends
// back, without depending on the controller package (which would be an
// import cycle-free but layering-inverting dependency from this package).
type fakeConfigStreamServer struct {
	configstreamv1.UnimplementedConfigStreamServiceServer

	snapshots chan *configstreamv1.ConfigSnapshot

	mu   sync.Mutex
	acks []*configstreamv1.ConfigAck
}

func newFakeConfigStreamServer() *fakeConfigStreamServer {
	return &fakeConfigStreamServer{snapshots: make(chan *configstreamv1.ConfigSnapshot, 4)}
}

func (f *fakeConfigStreamServer) push(snapshot *configstreamv1.ConfigSnapshot) {
	f.snapshots <- snapshot
}

func (f *fakeConfigStreamServer) recordedAcks() []*configstreamv1.ConfigAck {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]*configstreamv1.ConfigAck(nil), f.acks...)
}

func (f *fakeConfigStreamServer) StreamConfig(stream configstreamv1.ConfigStreamService_StreamConfigServer) error {
	// The first message must be Subscribe, mirroring the real
	// ConfigServer's contract; this test double doesn't need the
	// subscriber ID for anything.
	if _, err := stream.Recv(); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			if ack := req.GetAck(); ack != nil {
				f.mu.Lock()
				f.acks = append(f.acks, ack)
				f.mu.Unlock()
			}
		}
	}()

	for {
		select {
		case snapshot := <-f.snapshots:
			if err := stream.Send(&configstreamv1.StreamConfigResponse{Snapshot: snapshot}); err != nil {
				return err
			}
		case err := <-errCh:
			return err
		case <-stream.Context().Done():
			return nil
		}
	}
}

// startTestSubscriber starts a fakeConfigStreamServer over an in-memory
// bufconn listener and returns a Subscriber dialed to it.
func startTestSubscriber(t *testing.T) (*Subscriber, *fakeConfigStreamServer) {
	t.Helper()

	server := newFakeConfigStreamServer()

	lis := bufconn.Listen(subscriberTestBufSize)
	grpcServer := grpc.NewServer()
	configstreamv1.RegisterConfigStreamServiceServer(grpcServer, server)

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	dialer := grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() })
	subscriber := NewSubscriber("passthrough:///bufnet", "test-replica", nil, dialer, grpc.WithTransportCredentials(insecure.NewCredentials()))

	return subscriber, server
}

func TestSubscriberAppliesInitialSnapshot(t *testing.T) {
	subscriber, server := startTestSubscriber(t)

	server.push(&configstreamv1.ConfigSnapshot{Version: "v1", ConfigJson: []byte(validConfigJSON)})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	received := make(chan *Snapshot, 1)
	go func() { _ = subscriber.Run(ctx, func(s *Snapshot) { received <- s }) }()

	select {
	case snapshot := <-received:
		_, matched := snapshot.Match("example.com", "/")
		assert.True(t, matched, "expected the applied snapshot to match example.com")
	case <-ctx.Done():
		t.Fatal("timed out waiting for the subscriber to apply the initial snapshot")
	}

	require.Eventually(t, func() bool {
		acks := server.recordedAcks()
		return len(acks) == 1 && acks[0].GetApplied() && acks[0].GetVersion() == "v1"
	}, 2*time.Second, 10*time.Millisecond, "expected a single applied ack for v1")
}

func TestSubscriberAppliesSubsequentSnapshot(t *testing.T) {
	subscriber, server := startTestSubscriber(t)

	server.push(&configstreamv1.ConfigSnapshot{Version: "v1", ConfigJson: []byte(validConfigJSON)})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	received := make(chan *Snapshot, 2)
	go func() { _ = subscriber.Run(ctx, func(s *Snapshot) { received <- s }) }()

	<-received // initial snapshot

	updatedJSON := `{
  "directives": {"a": "SecRuleEngine On"},
  "routes": [
    {"host": "updated.example.com", "pathPrefix": "/", "waf": {"engineKey": "a"}}
  ]
}`
	server.push(&configstreamv1.ConfigSnapshot{Version: "v2", ConfigJson: []byte(updatedJSON)})

	select {
	case snapshot := <-received:
		_, matched := snapshot.Match("updated.example.com", "/")
		assert.True(t, matched, "expected the second applied snapshot to match updated.example.com")
	case <-ctx.Done():
		t.Fatal("timed out waiting for the subscriber to apply the updated snapshot")
	}
}

func TestSubscriberRejectsInvalidSnapshotAndKeepsPrevious(t *testing.T) {
	subscriber, server := startTestSubscriber(t)

	server.push(&configstreamv1.ConfigSnapshot{Version: "v1", ConfigJson: []byte(validConfigJSON)})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	received := make(chan *Snapshot, 2)
	go func() { _ = subscriber.Run(ctx, func(s *Snapshot) { received <- s }) }()

	<-received // initial (valid) snapshot

	server.push(&configstreamv1.ConfigSnapshot{Version: "v2", ConfigJson: []byte("not valid json at all")})

	require.Eventually(t, func() bool {
		for _, ack := range server.recordedAcks() {
			if ack.GetVersion() == "v2" {
				return !ack.GetApplied() && ack.GetError() != ""
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "expected a rejected ack for v2")

	select {
	case <-received:
		t.Fatal("onChange must not be called for an invalid snapshot")
	case <-time.After(200 * time.Millisecond):
		// Expected: no second onChange call.
	}
}

func TestSubscriberSkipsDuplicateVersion(t *testing.T) {
	subscriber, server := startTestSubscriber(t)

	server.push(&configstreamv1.ConfigSnapshot{Version: "v1", ConfigJson: []byte(validConfigJSON)})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	received := make(chan *Snapshot, 4)
	go func() { _ = subscriber.Run(ctx, func(s *Snapshot) { received <- s }) }()

	<-received // initial

	server.push(&configstreamv1.ConfigSnapshot{Version: "v1", ConfigJson: []byte(validConfigJSON)})

	require.Eventually(t, func() bool {
		return len(server.recordedAcks()) == 2
	}, 2*time.Second, 10*time.Millisecond, "expected a second ack for the duplicate push")

	select {
	case <-received:
		t.Fatal("onChange must not be called again for a duplicate version")
	case <-time.After(200 * time.Millisecond):
		// Expected: no second onChange call, but the duplicate still got acked.
	}
}
