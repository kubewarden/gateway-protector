package controller

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	configstreamv1 "github.com/kubewarden/gateway-protector/internal/configstream/v1"
)

// ConfigStreamRunnable runs a ConfigServer as its own gRPC server, bound to
// BindAddress, as a manager.Runnable (see cmd/controller/main.go).
//
// It implements manager.LeaderElectionRunnable with NeedLeaderElection
// returning true: only the active leader's ProcessorConfigReconciler ever
// calls GRPCPublisher.Publish, so a non-leader's ConfigServer would accept
// subscribers and then never have anything to push them. The chart always
// enables leader election (--leader-elect is hardcoded in the controller
// Deployment, even at its default single replica), so in practice the
// config stream only serves once the pod holds the lease - including
// during pod replacement, where the stream stays down until the new pod
// acquires it, which is exactly when its reconciler starts publishing.
// Only when the manager runs without --leader-elect (e.g. the binary run
// by hand in local dev) does this declaration become a no-op: per
// manager.LeaderElectionRunnable's own doc comment, "the default behavior
// when leaderelection is not enabled is to run LeaderElectionRunnables
// immediately".
type ConfigStreamRunnable struct {
	Server      *ConfigServer
	BindAddress string
}

var _ interface {
	Start(context.Context) error
	NeedLeaderElection() bool
} = &ConfigStreamRunnable{}

// NeedLeaderElection implements manager.LeaderElectionRunnable.
func (r *ConfigStreamRunnable) NeedLeaderElection() bool {
	return true
}

// Start implements manager.Runnable: it serves the config stream gRPC
// service until ctx is done.
func (r *ConfigStreamRunnable) Start(ctx context.Context) error {
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", r.BindAddress)
	if err != nil {
		return fmt.Errorf("failed to bind config stream gRPC listener on %q: %w", r.BindAddress, err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer()
	configstreamv1.RegisterConfigStreamServiceServer(grpcServer, r.Server)

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	errCh := make(chan error, 1)
	go func() { errCh <- grpcServer.Serve(lis) }()

	select {
	case <-ctx.Done():
		grpcServer.GracefulStop()
		return nil
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("config stream gRPC server failed: %w", err)
		}
		return nil
	}
}
