package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
)

func TestGRPCPublisherPublishesToConfigServer(t *testing.T) {
	server := NewConfigServer()
	publisher := &GRPCPublisher{Server: server}

	cfg := &procconfig.Config{
		Directives: map[string]string{"a": "SecRuleEngine On"},
		Routes: []procconfig.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &procconfig.WAFRef{EngineKey: "a"}},
		},
	}

	require.NoError(t, publisher.Publish(context.Background(), cfg))

	snapshot := server.latestForTest()
	require.NotNil(t, snapshot)
	assert.NotEmpty(t, snapshot.GetVersion())
	assert.Contains(t, string(snapshot.GetConfigJson()), "SecRuleEngine On")
}

func TestGRPCPublisherIsDeterministic(t *testing.T) {
	server := NewConfigServer()
	publisher := &GRPCPublisher{Server: server}

	cfg := &procconfig.Config{Directives: map[string]string{"a": "SecRuleEngine On"}}

	require.NoError(t, publisher.Publish(context.Background(), cfg))
	first := server.latestForTest().GetVersion()

	require.NoError(t, publisher.Publish(context.Background(), cfg))
	second := server.latestForTest().GetVersion()

	assert.Equal(t, first, second, "publishing the same config twice must produce the same version")
}
