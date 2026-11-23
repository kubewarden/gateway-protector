package controller

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	configstreamv1 "github.com/kubewarden/gateway-protector/internal/configstream/v1"
	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
)

const configStreamBufSize = 1024 * 1024

// testSnapshot builds a ConfigSnapshot carrying a realistic processor
// config (an engine plus a binding referencing it, keyed off version so
// different versions produce genuinely different payloads) rather than a
// placeholder string. ConfigServer itself treats ConfigJson as opaque
// bytes - parsing/validation happen subscriber-side, see
// internal/processor/config/subscriber_test.go - so these tests don't
// depend on the payload's content, but a realistic one keeps the fixtures
// representative of what production actually pushes.
func testSnapshot(t *testing.T, version string) *configstreamv1.ConfigSnapshot {
	t.Helper()

	engineKey := "engine-" + version
	cfg := &procconfig.Config{
		SchemaVersion: procconfig.SchemaVersion,
		Directives:    map[string]string{engineKey: "SecRuleEngine On"},
		Bindings: []procconfig.Binding{
			{Kind: procconfig.KindGateway, Namespace: "infra", Name: version + "-gw", WAF: &procconfig.WAFRef{EngineKey: engineKey}},
		},
	}

	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	return &configstreamv1.ConfigSnapshot{Version: version, ConfigJson: data}
}

// startTestConfigServer starts a ConfigServer over an in-memory bufconn
// listener, returning a connected ConfigStreamServiceClient and the ConfigServer
// itself (so tests can call Publish directly).
func startTestConfigServer(t *testing.T) (configstreamv1.ConfigStreamServiceClient, *ConfigServer) {
	t.Helper()

	server := NewConfigServer()

	lis := bufconn.Listen(configStreamBufSize)
	grpcServer := grpc.NewServer()
	configstreamv1.RegisterConfigStreamServiceServer(grpcServer, server)

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return configstreamv1.NewConfigStreamServiceClient(conn), server
}

// subscribe opens a StreamConfig call and sends the initial Subscribe
// message, announcing the config schema version this controller publishes,
// returning the stream.
func subscribe(ctx context.Context, t *testing.T, client configstreamv1.ConfigStreamServiceClient, id string) configstreamv1.ConfigStreamService_StreamConfigClient {
	t.Helper()

	return subscribeWithSchemaVersion(ctx, t, client, id, procconfig.SchemaVersion)
}

func subscribeWithSchemaVersion(ctx context.Context, t *testing.T, client configstreamv1.ConfigStreamServiceClient, id string, schemaVersion uint32) configstreamv1.ConfigStreamService_StreamConfigClient {
	t.Helper()

	stream, err := client.StreamConfig(ctx)
	require.NoError(t, err)

	err = stream.Send(&configstreamv1.StreamConfigRequest{
		Message: &configstreamv1.StreamConfigRequest_Subscribe{
			Subscribe: &configstreamv1.Subscribe{SubscriberId: id, SchemaVersion: schemaVersion},
		},
	})
	require.NoError(t, err)

	return stream
}

func TestConfigServerPushesLatestOnSubscribe(t *testing.T) {
	client, server := startTestConfigServer(t)

	want := testSnapshot(t, "v1")
	server.Publish(want)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream := subscribe(ctx, t, client, "replica-1")

	resp, err := stream.Recv()
	require.NoError(t, err)
	snapshot := resp.GetSnapshot()
	assert.Equal(t, "v1", snapshot.GetVersion())
	assert.JSONEq(t, string(want.GetConfigJson()), string(snapshot.GetConfigJson()))
}

// TestConfigServerRejectsSubscriberOfAnotherSchemaVersion pins that a
// processor of another version, including one that predates the schema
// version field (0), never receives a config it would misread: its stream
// ends with FailedPrecondition before any snapshot is sent, and it is not
// registered for later publishes.
func TestConfigServerRejectsSubscriberOfAnotherSchemaVersion(t *testing.T) {
	for _, schemaVersion := range []uint32{0, procconfig.SchemaVersion + 1} {
		client, server := startTestConfigServer(t)
		server.Publish(testSnapshot(t, "v1"))

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		stream := subscribeWithSchemaVersion(ctx, t, client, "old-replica", schemaVersion)

		_, err := stream.Recv()
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err), "schema version %d", schemaVersion)

		server.mu.Lock()
		assert.Empty(t, server.subscribers, "schema version %d", schemaVersion)
		server.mu.Unlock()

		cancel()
	}
}

func TestConfigServerPushesOnPublishAfterSubscribe(t *testing.T) {
	client, server := startTestConfigServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream := subscribe(ctx, t, client, "replica-1")

	server.Publish(testSnapshot(t, "v1"))

	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, "v1", resp.GetSnapshot().GetVersion())
}

func TestConfigServerSkipsNoOpPublish(t *testing.T) {
	_, server := startTestConfigServer(t)

	server.Publish(testSnapshot(t, "v1"))
	server.Publish(testSnapshot(t, "v1"))

	require.NotNil(t, server.latestForTest())
	assert.Equal(t, "v1", server.latestForTest().GetVersion())
}

func TestConfigServerFansOutToMultipleSubscribers(t *testing.T) {
	client, server := startTestConfigServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	streamA := subscribe(ctx, t, client, "replica-a")
	streamB := subscribe(ctx, t, client, "replica-b")

	server.Publish(testSnapshot(t, "v1"))

	respA, err := streamA.Recv()
	require.NoError(t, err)
	assert.Equal(t, "v1", respA.GetSnapshot().GetVersion())

	respB, err := streamB.Recv()
	require.NoError(t, err)
	assert.Equal(t, "v1", respB.GetSnapshot().GetVersion())
}

func TestConfigServerAcceptsAcks(t *testing.T) {
	client, server := startTestConfigServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream := subscribe(ctx, t, client, "replica-1")

	server.Publish(testSnapshot(t, "v1"))

	_, err := stream.Recv()
	require.NoError(t, err)

	err = stream.Send(&configstreamv1.StreamConfigRequest{
		Message: &configstreamv1.StreamConfigRequest_Ack{
			Ack: &configstreamv1.ConfigAck{Version: "v1", Applied: true},
		},
	})
	require.NoError(t, err)

	// There's no observable side effect of a successful ack besides the
	// controller's own logs (see logAck) - this spec exists to prove
	// sending one doesn't break or hang the stream, by immediately
	// publishing again and confirming the subscriber still gets it.
	server.Publish(testSnapshot(t, "v2"))

	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, "v2", resp.GetSnapshot().GetVersion())
}

func TestConfigServerRemovesSubscriberOnDisconnect(t *testing.T) {
	client, server := startTestConfigServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	stream := subscribe(ctx, t, client, "replica-1")

	server.Publish(testSnapshot(t, "v1"))
	_, err := stream.Recv()
	require.NoError(t, err)

	cancel()

	require.Eventually(t, func() bool {
		server.mu.Lock()
		defer server.mu.Unlock()

		return len(server.subscribers) == 0
	}, 5*time.Second, 10*time.Millisecond, "subscriber should be removed once its stream's context is done")
}
