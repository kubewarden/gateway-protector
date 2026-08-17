package controller

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	configstreamv1 "github.com/kubewarden/gateway-protector/internal/configstream/v1"
	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
)

const configStreamIntegrationBufSize = 1024 * 1024

// startIntegrationConfigServer starts a real ConfigServer over an
// in-memory bufconn listener and returns a grpc.DialOption that dials it,
// for a real procconfig.Subscriber to connect through (see
// TestConfigStreamEndToEnd). Unlike startTestConfigServer (this package's
// other bufconn helper), nothing here talks to the wire protocol directly:
// the whole point of this test is exercising the real client and real
// server against each other, not a hand-rolled stand-in for either side.
func startIntegrationConfigServer(t *testing.T) (*ConfigServer, grpc.DialOption) {
	t.Helper()

	server := NewConfigServer()

	lis := bufconn.Listen(configStreamIntegrationBufSize)
	grpcServer := grpc.NewServer()
	configstreamv1.RegisterConfigStreamServiceServer(grpcServer, server)

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	dialer := grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() })

	return server, dialer
}

// TestConfigStreamEndToEnd is the one test in this package that runs the
// real production chain end to end: GRPCPublisher.Publish (marshal +
// hash) -> ConfigServer (fan-out over a real gRPC server) -> a real
// procconfig.Subscriber (parse/validate/compile) -> onChange. Every other
// test in this package (configstream_server_test.go,
// processor_config_publisher_test.go) exercises one side of this chain
// against a minimal hand-rolled stand-in for the other, which is
// deliberately fast and focused - but means the two real
// implementations, written against the same proto, are never actually
// checked against each other below this test and test/e2e. This is the
// idiomatic middle layer for gRPC: real client, real server, in-memory
// transport (bufconn) instead of a real socket.
//
// What this doesn't cover: independently observing a subscriber's
// ConfigAck. Its only production effect is a log line on the controller
// side (see logAck) - there's no assertable side effect yet, so ack
// correctness stays covered by each side's own unit tests
// (TestConfigServerAcceptsAcks, TestSubscriberAppliesInitialSnapshot).
func TestConfigStreamEndToEnd(t *testing.T) {
	server, dialer := startIntegrationConfigServer(t)
	publisher := &GRPCPublisher{Server: server}

	subscriber := procconfig.NewSubscriber("passthrough:///bufnet", "test-replica", nil,
		dialer, grpc.WithTransportCredentials(insecure.NewCredentials()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	received := make(chan *procconfig.Snapshot, 2)
	go func() { _ = subscriber.Run(ctx, func(s *procconfig.Snapshot) { received <- s }) }()

	firstCfg := &procconfig.Config{
		Directives: map[string]string{"a": "SecRuleEngine On"},
		Routes: []procconfig.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &procconfig.WAFRef{EngineKey: "a"}},
		},
	}
	require.NoError(t, publisher.Publish(ctx, firstCfg))

	select {
	case snapshot := <-received:
		_, matched := snapshot.Match("example.com", "/")
		assert.True(t, matched, "expected the first published config to reach the subscriber and match example.com")
	case <-ctx.Done():
		t.Fatal("timed out waiting for the subscriber to receive the first published config")
	}

	updatedCfg := &procconfig.Config{
		Directives: map[string]string{"a": "SecRuleEngine On"},
		Routes: []procconfig.Route{
			{Host: "updated.example.com", PathPrefix: "/", WAF: &procconfig.WAFRef{EngineKey: "a"}},
		},
	}
	require.NoError(t, publisher.Publish(ctx, updatedCfg))

	select {
	case snapshot := <-received:
		_, matched := snapshot.Match("updated.example.com", "/")
		assert.True(t, matched, "expected the updated published config to reach the subscriber and match updated.example.com")
	case <-ctx.Done():
		t.Fatal("timed out waiting for the subscriber to receive the updated published config")
	}
}
