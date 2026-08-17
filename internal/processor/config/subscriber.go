package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	configstreamv1 "github.com/kubewarden/gateway-protector/internal/configstream/v1"
)

// initialBackoff/maxBackoff bound Subscriber's reconnect backoff (see
// Subscriber.Run): every connection error is followed by a growing delay,
// capped at maxBackoff, before trying again.
const (
	initialBackoff = time.Second
	maxBackoff     = 30 * time.Second
)

// Subscriber dials the controller's config stream (see
// proto/configstream/v1) and keeps a single long-lived subscription open
// for the processor's whole lifetime, reconnecting with backoff on any
// error. This mirrors the platform's fail-safe principle: a bad or
// unreachable config never disables protection or crashes the data plane -
// the processor keeps running whatever the last successfully compiled
// Snapshot was (or none, if it hasn't received one yet) until the problem
// is fixed.
type Subscriber struct {
	address      string
	subscriberID string
	logger       *slog.Logger
	dialOpts     []grpc.DialOption

	lastVersion string
}

// NewSubscriber creates a Subscriber that will dial address (the
// controller's config stream gRPC service) once Run is called.
// subscriberID identifies this processor replica to the controller (e.g.
// its pod name) for the controller's own logs/metrics only. A nil logger
// defaults to [slog.Default]. Extra dialOpts are appended after the
// default (insecure, production TLS is not implemented yet - see the
// repository's top-level TODO file) transport credentials, letting tests
// inject a custom dialer (e.g. bufconn).
func NewSubscriber(address, subscriberID string, logger *slog.Logger, dialOpts ...grpc.DialOption) *Subscriber {
	if logger == nil {
		logger = slog.Default()
	}

	opts := append([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, dialOpts...)

	return &Subscriber{
		address:      address,
		subscriberID: subscriberID,
		logger:       logger,
		dialOpts:     opts,
	}
}

// Run dials the controller and streams config snapshots until ctx is
// done, calling onChange with a newly compiled Snapshot every time the
// controller pushes one that parses, validates, and compiles
// successfully - including the first one received. Parse/validate/compile
// errors are logged and reported back to the controller as a rejected
// ConfigAck; the subscriber keeps running with whatever Snapshot (if any)
// onChange last received.
//
// Run only returns once ctx is done (or dialing fails outright); any
// stream-level error in between is followed by a backoff and a
// reconnect attempt on the same connection.
func (s *Subscriber) Run(ctx context.Context, onChange func(*Snapshot)) error {
	conn, err := grpc.NewClient(s.address, s.dialOpts...)
	if err != nil {
		return fmt.Errorf("failed to create config stream client for %q: %w", s.address, err)
	}
	defer conn.Close()

	client := configstreamv1.NewConfigStreamServiceClient(conn)

	backoff := initialBackoff
	for {
		if ctx.Err() != nil {
			return nil
		}

		if err := s.streamOnce(ctx, client, onChange); err != nil && ctx.Err() == nil {
			s.logger.ErrorContext(ctx, "Config stream disconnected, reconnecting",
				slog.Any("error", err), slog.Duration("backoff", backoff))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// streamOnce opens a single StreamConfig call, subscribes, and processes
// snapshots until the stream ends (with an error, or ctx being done).
func (s *Subscriber) streamOnce(ctx context.Context, client configstreamv1.ConfigStreamServiceClient, onChange func(*Snapshot)) error {
	stream, err := client.StreamConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to open config stream: %w", err)
	}

	if err := stream.Send(&configstreamv1.StreamConfigRequest{
		Message: &configstreamv1.StreamConfigRequest_Subscribe{
			Subscribe: &configstreamv1.Subscribe{SubscriberId: s.subscriberID},
		},
	}); err != nil {
		return fmt.Errorf("failed to send subscribe message: %w", err)
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("config stream receive failed: %w", err)
		}

		ack := s.applySnapshot(ctx, resp.GetSnapshot(), onChange)
		if err := stream.Send(&configstreamv1.StreamConfigRequest{
			Message: &configstreamv1.StreamConfigRequest_Ack{Ack: ack},
		}); err != nil {
			return fmt.Errorf("failed to send config ack: %w", err)
		}
	}
}

// applySnapshot parses, validates, and compiles snapshot (skipping the
// no-op case where its version matches the last one this Subscriber
// applied), calling onChange and returning an "applied" ConfigAck on
// success. On any failure, it logs the error, leaves the Subscriber's
// state untouched (so the processor keeps serving whatever Snapshot
// onChange last received), and returns a rejected ConfigAck carrying the
// error for the controller's own logs.
func (s *Subscriber) applySnapshot(ctx context.Context, snapshot *configstreamv1.ConfigSnapshot, onChange func(*Snapshot)) *configstreamv1.ConfigAck {
	version := snapshot.GetVersion()

	if version != "" && version == s.lastVersion {
		return &configstreamv1.ConfigAck{Version: version, Applied: true}
	}

	cfg, err := parseConfig(snapshot.GetConfigJson())
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to parse config from controller, keeping previous config",
			slog.String("version", version), slog.Any("error", err))
		return &configstreamv1.ConfigAck{Version: version, Applied: false, Error: err.Error()}
	}

	compiled, err := Compile(cfg, s.logger)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to compile config from controller, keeping previous config",
			slog.String("version", version), slog.Any("error", err))
		return &configstreamv1.ConfigAck{Version: version, Applied: false, Error: err.Error()}
	}

	s.lastVersion = version
	s.logger.InfoContext(ctx, "Applied config from controller", slog.String("version", version))
	onChange(compiled)

	return &configstreamv1.ConfigAck{Version: version, Applied: true}
}
