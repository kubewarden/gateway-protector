package processorconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
)

// The outcomes of selectionAttack.
const (
	attackBlocked     = "blocked"
	attackUninspected = "not inspected"
	attackNoEngine    = "no engine"
)

// selectionSnapshot builds the processor config from policies, as the
// controller does, and compiles it with the processor's own code.
func selectionSnapshot(t *testing.T, policies ...*gwpv1alpha1.WAFPolicy) *procconfig.Snapshot {
	t.Helper()

	result := Build(Input{Policies: policies}, CorazaDryCompile)
	for _, policyResult := range result.PolicyResults {
		require.NoError(t, policyResult.Err)
	}

	require.NoError(t, procconfig.Validate(result.Config))

	snapshot, err := procconfig.Compile(result.Config, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = snapshot.Close() })

	return snapshot
}

// selectionAttack sends one XSS attack in the query string through the
// engine that the processor resolves for a request with the given
// identity - the identity agentgateway reports for the route and rule it
// selected - and reports the outcome.
func selectionAttack(t *testing.T, snapshot *procconfig.Snapshot, identity procconfig.Identity) string {
	t.Helper()

	waf, matched := snapshot.Resolve(identity)
	if !matched || waf == nil {
		return attackNoEngine
	}

	tx := waf.NewTransaction()
	defer func() { _ = tx.Close() }()

	tx.ProcessConnection("10.0.0.1", 40000, "10.0.0.2", 80)
	tx.ProcessURI("/anything?q=<script>alert(1)</script>", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "shop.example.com")

	interruption := tx.ProcessRequestHeaders()
	if interruption == nil {
		var err error
		interruption, err = tx.ProcessRequestBody()
		require.NoError(t, err)
	}

	if interruption != nil {
		return attackBlocked
	}

	return attackUninspected
}

func selectionPolicy(name string, ref gwpv1alpha1.PolicyTargetReference, mode gwpv1alpha1.WAFEngineMode) *gwpv1alpha1.WAFPolicy {
	policy := newPolicy(name, ref)
	policy.Spec.Engine.Mode = mode

	return policy
}

// shopRequest is the identity of a request that the infra/<gateway>
// Gateway accepted on its "http" listener and sent to the given rule of
// the team-shop/<route> HTTPRoute ("" for an unnamed rule).
func shopRequest(gateway, route, rule string) procconfig.Identity {
	return procconfig.Identity{
		GatewayNamespace: "infra",
		GatewayName:      gateway,
		ListenerName:     "http",
		RouteKind:        procconfig.KindHTTPRoute,
		RouteNamespace:   "team-shop",
		RouteName:        route,
		RouteRule:        rule,
	}
}

// TestPolicySelection covers the cases where the former table of hosts and
// path prefixes selected the policy of another rule or Gateway, and with
// it an Off engine. agentgateway selects the route with the full Gateway
// API matching rules and reports the selected route and rule; the
// processor must then apply the policy of exactly that rule.
func TestPolicySelection(t *testing.T) {
	blocking, off := gwpv1alpha1.WAFEngineModeBlocking, gwpv1alpha1.WAFEngineModeOff

	t.Run("an Off rule does not cover a path that only starts with the same string", func(t *testing.T) {
		// Rules: "health" (PathPrefix /health) and an unnamed catch-all
		// (PathPrefix /). agentgateway sends /health/live to "health",
		// and /healthz-admin to the catch-all, since a PathPrefix
		// matches whole path segments.
		snapshot := selectionSnapshot(t,
			selectionPolicy("gateway-blocking", gatewayTargetRef("infra", "shared-gw", nil), blocking),
			selectionPolicy("health-off", httpRouteTargetRef("shop", new(gatewayv1.SectionName("health"))), off),
		)

		assert.Equal(t, attackUninspected, selectionAttack(t, snapshot, shopRequest("shared-gw", "shop", "health")), "/health/live")
		assert.Equal(t, attackBlocked, selectionAttack(t, snapshot, shopRequest("shared-gw", "shop", "")), "/healthz-admin")
		assert.Equal(t, attackBlocked, selectionAttack(t, snapshot, shopRequest("shared-gw", "shop", "")), "/orders")
	})

	t.Run("an Off rule with a header match does not cover requests without the header", func(t *testing.T) {
		// Rules: "beta" (PathPrefix /api, header x-beta: 1) and an
		// unnamed rule (PathPrefix /api).
		snapshot := selectionSnapshot(t,
			selectionPolicy("gateway-blocking", gatewayTargetRef("infra", "shared-gw", nil), blocking),
			selectionPolicy("beta-off", httpRouteTargetRef("shop", new(gatewayv1.SectionName("beta"))), off),
		)

		assert.Equal(t, attackUninspected, selectionAttack(t, snapshot, shopRequest("shared-gw", "shop", "beta")), "with the header")
		assert.Equal(t, attackBlocked, selectionAttack(t, snapshot, shopRequest("shared-gw", "shop", "")), "without the header")
	})

	t.Run("the gateway of the request selects the policy", func(t *testing.T) {
		// Two routes for the same hostname, one per Gateway.
		snapshot := selectionSnapshot(t,
			selectionPolicy("public-blocking", gatewayTargetRef("infra", "public-gw", nil), blocking),
			selectionPolicy("internal-off", gatewayTargetRef("infra", "internal-gw", nil), off),
		)

		assert.Equal(t, attackBlocked, selectionAttack(t, snapshot, shopRequest("public-gw", "shop-public", "")))
		assert.Equal(t, attackUninspected, selectionAttack(t, snapshot, shopRequest("internal-gw", "shop-internal", "")))

		// One route attached to both Gateways.
		assert.Equal(t, attackBlocked, selectionAttack(t, snapshot, shopRequest("public-gw", "shop", "")))
		assert.Equal(t, attackUninspected, selectionAttack(t, snapshot, shopRequest("internal-gw", "shop", "")))
	})

	t.Run("the listener of the request selects the policy", func(t *testing.T) {
		snapshot := selectionSnapshot(t,
			selectionPolicy("gateway-off", gatewayTargetRef("infra", "shared-gw", nil), off),
			selectionPolicy("https-blocking", gatewayTargetRef("infra", "shared-gw", new(gatewayv1.SectionName("https"))), blocking),
		)

		viaHTTPS := shopRequest("shared-gw", "shop", "")
		viaHTTPS.ListenerName = "https"

		assert.Equal(t, attackBlocked, selectionAttack(t, snapshot, viaHTTPS))
		assert.Equal(t, attackUninspected, selectionAttack(t, snapshot, shopRequest("shared-gw", "shop", "")))
	})

	t.Run("a request that no policy covers gets no engine", func(t *testing.T) {
		snapshot := selectionSnapshot(t,
			selectionPolicy("gateway-blocking", gatewayTargetRef("infra", "shared-gw", nil), blocking),
		)

		assert.Equal(t, attackNoEngine, selectionAttack(t, snapshot, shopRequest("other-gw", "shop", "")))
	})
}
