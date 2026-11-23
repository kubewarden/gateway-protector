package config

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	configstreamv1 "github.com/kubewarden/gateway-protector/internal/configstream/v1"
)

const subscriberTestBufSize = 1024 * 1024

const validConfigJSON = `{
  "schemaVersion": 2,
  "directives": {"a": "SecRuleEngine On"},
  "bindings": [
    {"kind": "Gateway", "namespace": "infra", "name": "gw", "waf": {"engineKey": "a"}}
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

	mu         sync.Mutex
	acks       []*configstreamv1.ConfigAck
	subscribes []*configstreamv1.Subscribe
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

func (f *fakeConfigStreamServer) recordedSubscribes() []*configstreamv1.Subscribe {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]*configstreamv1.Subscribe(nil), f.subscribes...)
}

func (f *fakeConfigStreamServer) StreamConfig(stream configstreamv1.ConfigStreamService_StreamConfigServer) error {
	// The first message must be Subscribe, mirroring the real
	// ConfigServer's contract; it is recorded so tests can assert on it.
	initial, err := stream.Recv()
	if err != nil {
		return err
	}

	f.mu.Lock()
	f.subscribes = append(f.subscribes, initial.GetSubscribe())
	f.mu.Unlock()

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
	subscriber := NewSubscriber("passthrough:///bufnet", "test-replica", nil, nil, dialer)

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
		_, matched := snapshot.Resolve(gatewayIdentity("gw"))
		assert.True(t, matched, "expected the applied snapshot to bind the infra/gw Gateway")
	case <-ctx.Done():
		t.Fatal("timed out waiting for the subscriber to apply the initial snapshot")
	}

	require.Eventually(t, func() bool {
		acks := server.recordedAcks()
		return len(acks) == 1 && acks[0].GetApplied() && acks[0].GetVersion() == "v1"
	}, 2*time.Second, 10*time.Millisecond, "expected a single applied ack for v1")

	subscribes := server.recordedSubscribes()
	require.Len(t, subscribes, 1)
	assert.Equal(t, "test-replica", subscribes[0].GetSubscriberId())
	assert.EqualValues(t, SchemaVersion, subscribes[0].GetSchemaVersion(),
		"the subscriber must announce the config schema version it accepts")
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
  "schemaVersion": 2,
  "directives": {"a": "SecRuleEngine On"},
  "bindings": [
    {"kind": "Gateway", "namespace": "infra", "name": "updated-gw", "waf": {"engineKey": "a"}}
  ]
}`
	server.push(&configstreamv1.ConfigSnapshot{Version: "v2", ConfigJson: []byte(updatedJSON)})

	select {
	case snapshot := <-received:
		_, matched := snapshot.Resolve(gatewayIdentity("updated-gw"))
		assert.True(t, matched, "expected the second applied snapshot to bind the infra/updated-gw Gateway")
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

// TestSubscriberRejectsConfigOfAnotherSchemaVersion covers a processor that
// receives a config in the previous format (schema version 1: no
// schemaVersion field, a table of hosts and paths) from an older
// controller: it must reject the config, not read it as an empty set of
// bindings that leaves every request uninspected.
func TestSubscriberRejectsConfigOfAnotherSchemaVersion(t *testing.T) {
	subscriber, server := startTestSubscriber(t)

	server.push(&configstreamv1.ConfigSnapshot{Version: "v1", ConfigJson: []byte(`{
  "directives": {"a": "SecRuleEngine On"},
  "routes": [
    {"host": "example.com", "pathPrefix": "/", "waf": {"engineKey": "a"}}
  ]
}`)})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	received := make(chan *Snapshot, 1)
	go func() { _ = subscriber.Run(ctx, func(s *Snapshot) { received <- s }) }()

	require.Eventually(t, func() bool {
		acks := server.recordedAcks()
		return len(acks) == 1 && !acks[0].GetApplied() && strings.Contains(acks[0].GetError(), "schemaVersion")
	}, 2*time.Second, 10*time.Millisecond, "expected a rejected ack that names the schema version")

	select {
	case <-received:
		t.Fatal("onChange must not be called for a config of another schema version")
	case <-time.After(200 * time.Millisecond):
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

// TestSubscriberForwardsCompileOptionsToCompile is a regression test for
// SetCompileOptions: options set on a Subscriber must actually reach every
// Compile call it makes (including the very first config it applies), not
// just be stored and ignored.
func TestSubscriberForwardsCompileOptionsToCompile(t *testing.T) {
	subscriber, server := startTestSubscriber(t)

	var buf bytes.Buffer
	subscriber.SetCompileOptions(WithMatchedRuleWriter(&buf))

	configJSON, err := json.Marshal(Config{
		SchemaVersion: SchemaVersion,
		Directives: map[string]string{
			"a": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403,log"` + "\n",
		},
		Bindings: []Binding{gatewayBinding("gw", "a")},
	})
	require.NoError(t, err)

	server.push(&configstreamv1.ConfigSnapshot{Version: "v1", ConfigJson: configJSON})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	received := make(chan *Snapshot, 1)
	go func() { _ = subscriber.Run(ctx, func(s *Snapshot) { received <- s }) }()

	var snapshot *Snapshot
	select {
	case snapshot = <-received:
	case <-ctx.Done():
		t.Fatal("timed out waiting for the subscriber to apply the config")
	}

	waf, matched := snapshot.Resolve(gatewayIdentity("gw"))
	require.True(t, matched)

	tx := waf.NewTransaction()
	defer tx.Close()

	tx.ProcessURI("/?test=malicious", "GET", "HTTP/1.1")
	interruption := tx.ProcessRequestHeaders()
	require.NotNil(t, interruption)

	assert.Contains(t, buf.String(), `[id "1000"]`)
}
