package config

import (
	"errors"
	"testing"

	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeWAF is a minimal coraza.WAF implementation used to assert engine
// identity (by pointer) without compiling a real Coraza engine.
type fakeWAF struct{ name string }

func (f *fakeWAF) NewTransaction() ctypes.Transaction             { return nil }
func (f *fakeWAF) NewTransactionWithID(string) ctypes.Transaction { return nil }

// closableFakeWAF is a fakeWAF that also implements experimental.WAFCloser,
// recording whether (and how many times) Close was called and optionally
// returning a canned error, to test Snapshot.Close without compiling real
// Coraza engines.
type closableFakeWAF struct {
	fakeWAF

	closeErr   error
	closeCalls int
}

func (f *closableFakeWAF) Close() error {
	f.closeCalls++
	return f.closeErr
}

// gatewayIdentity returns the Identity of a request that the "infra/<name>"
// Gateway accepted on its "http" listener and sent to the unnamed rule of
// the "app/web" HTTPRoute.
func gatewayIdentity(name string) Identity {
	return Identity{
		GatewayNamespace: "infra",
		GatewayName:      name,
		ListenerName:     "http",
		RouteKind:        KindHTTPRoute,
		RouteNamespace:   "app",
		RouteName:        "web",
	}
}

// gatewayBinding binds the whole "infra/<name>" Gateway to engineKey.
func gatewayBinding(name, engineKey string) Binding {
	return Binding{Kind: KindGateway, Namespace: "infra", Name: name, WAF: &WAFRef{EngineKey: engineKey}}
}

func TestSnapshotResolve(t *testing.T) {
	engineGateway := &fakeWAF{name: "gateway"}
	engineListener := &fakeWAF{name: "listener"}
	engineRoute := &fakeWAF{name: "route"}
	engineRule := &fakeWAF{name: "rule"}
	engineOther := &fakeWAF{name: "other"}
	engines := map[string]coraza.WAF{
		"gateway":  engineGateway,
		"listener": engineListener,
		"route":    engineRoute,
		"rule":     engineRule,
		"other":    engineOther,
	}

	bindings := []Binding{
		gatewayBinding("shared-gw", "gateway"),
		{Kind: KindGateway, Namespace: "infra", Name: "shared-gw", SectionName: "admin", WAF: &WAFRef{EngineKey: "listener"}},
		{Kind: KindHTTPRoute, Namespace: "team-shop", Name: "shop", WAF: &WAFRef{EngineKey: "route"}},
		{Kind: KindHTTPRoute, Namespace: "team-shop", Name: "shop", SectionName: "checkout", WAF: &WAFRef{EngineKey: "rule"}},
		// A binding without an engine: its policy failed to compile.
		{Kind: KindHTTPRoute, Namespace: "team-shop", Name: "shop", SectionName: "broken"},
		gatewayBinding("other-gw", "other"),
	}

	snapshot := newSnapshot(engines, bindings)

	request := func(listener, routeNamespace, routeName, rule string) Identity {
		return Identity{
			GatewayNamespace: "infra",
			GatewayName:      "shared-gw",
			ListenerName:     listener,
			RouteKind:        KindHTTPRoute,
			RouteNamespace:   routeNamespace,
			RouteName:        routeName,
			RouteRule:        rule,
		}
	}

	tests := []struct {
		name       string
		identity   Identity
		wantMatch  bool
		wantEngine coraza.WAF
	}{
		{
			name:       "rule binding wins",
			identity:   request("http", "team-shop", "shop", "checkout"),
			wantMatch:  true,
			wantEngine: engineRule,
		},
		{
			name:       "route binding covers the other rules of the route",
			identity:   request("http", "team-shop", "shop", "browse"),
			wantMatch:  true,
			wantEngine: engineRoute,
		},
		{
			name:       "route binding covers an unnamed rule",
			identity:   request("http", "team-shop", "shop", ""),
			wantMatch:  true,
			wantEngine: engineRoute,
		},
		{
			name:       "route binding wins over the listener binding",
			identity:   request("admin", "team-shop", "shop", ""),
			wantMatch:  true,
			wantEngine: engineRoute,
		},
		{
			name:      "a binding without an engine stops the resolution",
			identity:  request("http", "team-shop", "shop", "broken"),
			wantMatch: true,
		},
		{
			name:       "listener binding wins over the gateway binding",
			identity:   request("admin", "team-blog", "blog", ""),
			wantMatch:  true,
			wantEngine: engineListener,
		},
		{
			name:       "gateway binding covers the other listeners",
			identity:   request("http", "team-blog", "blog", ""),
			wantMatch:  true,
			wantEngine: engineGateway,
		},
		{
			name:       "the gateway of the request selects the engine",
			identity:   Identity{GatewayNamespace: "infra", GatewayName: "other-gw", ListenerName: "http", RouteKind: KindHTTPRoute, RouteNamespace: "team-blog", RouteName: "blog"},
			wantMatch:  true,
			wantEngine: engineOther,
		},
		{
			name: "route bindings apply only to HTTPRoute requests",
			identity: Identity{
				GatewayNamespace: "infra", GatewayName: "shared-gw", ListenerName: "http",
				RouteKind: "GRPCRoute", RouteNamespace: "team-shop", RouteName: "shop", RouteRule: "checkout",
			},
			wantMatch:  true,
			wantEngine: engineGateway,
		},
		{
			name:      "no binding for the gateway",
			identity:  Identity{GatewayNamespace: "infra", GatewayName: "unknown-gw", ListenerName: "http", RouteKind: KindHTTPRoute, RouteNamespace: "team-blog", RouteName: "blog"},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf, matched := snapshot.Resolve(tt.identity)
			require.Equal(t, tt.wantMatch, matched)
			if tt.wantEngine == nil {
				assert.Nil(t, waf)
			} else {
				assert.Same(t, tt.wantEngine, waf)
			}
		})
	}
}

func TestSnapshotResolveNoBindings(t *testing.T) {
	snapshot := newSnapshot(map[string]coraza.WAF{}, nil)

	_, matched := snapshot.Resolve(gatewayIdentity("shared-gw"))
	assert.False(t, matched)
}

// TestSnapshotResolveListenerWithoutName pins that an empty listener name
// never matches a listener binding: the whole-Gateway binding, whose
// sectionName is also empty, is the only Gateway-level candidate.
func TestSnapshotResolveListenerWithoutName(t *testing.T) {
	engineGateway := &fakeWAF{name: "gateway"}
	engineListener := &fakeWAF{name: "listener"}
	snapshot := newSnapshot(map[string]coraza.WAF{"gateway": engineGateway, "listener": engineListener}, []Binding{
		gatewayBinding("shared-gw", "gateway"),
		{Kind: KindGateway, Namespace: "infra", Name: "shared-gw", SectionName: "http", WAF: &WAFRef{EngineKey: "listener"}},
	})

	identity := gatewayIdentity("shared-gw")
	identity.ListenerName = ""

	waf, matched := snapshot.Resolve(identity)
	require.True(t, matched)
	assert.Same(t, engineGateway, waf)
}

func TestSnapshotClose(t *testing.T) {
	t.Run("closes every engine implementing WAFCloser", func(t *testing.T) {
		closableA := &closableFakeWAF{fakeWAF: fakeWAF{name: "a"}}
		closableB := &closableFakeWAF{fakeWAF: fakeWAF{name: "b"}}
		engines := map[string]coraza.WAF{"a": closableA, "b": closableB}

		snapshot := newSnapshot(engines, nil)

		require.NoError(t, snapshot.Close())
		assert.Equal(t, 1, closableA.closeCalls)
		assert.Equal(t, 1, closableB.closeCalls)
	})

	t.Run("skips engines that don't implement WAFCloser", func(t *testing.T) {
		plain := &fakeWAF{name: "plain"}
		engines := map[string]coraza.WAF{"plain": plain}

		snapshot := newSnapshot(engines, nil)

		assert.NoError(t, snapshot.Close())
	})

	t.Run("joins errors and still closes every engine", func(t *testing.T) {
		errA := errors.New("engine a failed to close")
		errB := errors.New("engine b failed to close")
		closableA := &closableFakeWAF{fakeWAF: fakeWAF{name: "a"}, closeErr: errA}
		closableB := &closableFakeWAF{fakeWAF: fakeWAF{name: "b"}, closeErr: errB}
		engines := map[string]coraza.WAF{"a": closableA, "b": closableB}

		snapshot := newSnapshot(engines, nil)

		err := snapshot.Close()
		require.Error(t, err)
		require.ErrorIs(t, err, errA)
		require.ErrorIs(t, err, errB)
		assert.Equal(t, 1, closableA.closeCalls)
		assert.Equal(t, 1, closableB.closeCalls)
	})

	t.Run("empty snapshot", func(t *testing.T) {
		snapshot := newSnapshot(map[string]coraza.WAF{}, nil)

		assert.NoError(t, snapshot.Close())
	})
}
