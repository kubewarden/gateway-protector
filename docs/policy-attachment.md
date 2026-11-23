# Policy attachment: how a WAFPolicy matches traffic

This document is the deep dive on **which `WAFPolicy` governs a given piece of
traffic**, and how that decision reaches the processor. See
[`docs/wafpolicy-lifecycle.md`](wafpolicy-lifecycle.md) for the `WAFPolicy`
object's own lifecycle (Accepted/Programmed conditions, conflicts,
re-evaluation triggers) and
[`docs/processor.md`](processor.md#engine-selection) for the request-time
details of engine selection.

The decision is split between two components:

- **agentgateway** selects the route and the rule of each request with the
  full Gateway API matching rules (hostnames, path matches, header, query
  parameter, and method matches), and reports the Gateway, the listener, the
  route, and the rule to the processor (see
  [Request identity](processor.md#request-identity)).
- **The processor** maps that identity to the `WAFPolicy` that governs it,
  with the precedence below (`Snapshot.Resolve` in
  `internal/processor/config/snapshot.go`).

The controller prepares the two sides. Its code is `processorconfig.Build`
in `internal/controller/processorconfig`, and it runs in the
[Programming](wafpolicy-lifecycle.md#3-programming-implemented) step. The
controller does two things:

- It publishes one binding for each Accepted `WAFPolicy`. A binding connects
  the target of the policy to the engine that the controller compiled from
  the policy.
- It generates one `AgentgatewayPolicy` for each route that a policy can
  apply to. This object makes agentgateway send the traffic of the route,
  and the identity of each request, to the processor.

The controller never works out the hosts or the paths of a route. This code
does not call the Kubernetes API: the reconciler gives it the objects. No
admission check runs this logic when you apply a policy, because the result
depends on other objects that can change later. See
[Why validation is split between admission and the reconciler](wafpolicy-lifecycle.md#why-validation-is-split-between-admission-and-the-reconciler).

## Attachment basics

A `WAFPolicy`'s `spec.targetRef` points at exactly one `Gateway` or one
`HTTPRoute`, optionally narrowed to a single listener (`Gateway`) or route
rule (`HTTPRoute`) via `sectionName`. Four attachment shapes are possible:

| `targetRef.kind` | `sectionName` | Scope |
| --- | --- | --- |
| `Gateway` | unset | Default for every request this Gateway accepts |
| `Gateway` | a listener name | Default for every request this listener accepts |
| `HTTPRoute` | unset | Overrides the Gateway defaults for this route, every rule |
| `HTTPRoute` | a rule name | Overrides everything else for that one rule only |

Resolution across these is **most-specific-wins, full replacement, never
merging** - see [Which policy governs a request](#which-policy-governs-a-request)
below for the exact order. `examples/route-override/` has one worked manifest
per common scenario (`gateway-default.yaml`, `route-override.yaml`,
`route-opt-out.yaml`).

## Which policy governs a request

The processor resolves the one `WAFPolicy` that governs a request by trying
four levels, most to least specific, and stopping at the first match:

| Order | Attachment | Matches |
| --- | --- | --- |
| 1 | `HTTPRoute` + `sectionName` | Requests that agentgateway sends to this exact rule (only possible when the rule has a `name`) |
| 2 | `HTTPRoute`, no `sectionName` | Requests to every rule of this route not covered by (1) |
| 3 | `Gateway` + `sectionName` | Requests that this listener accepts, not covered by (1)-(2) |
| 4 | `Gateway`, no `sectionName` | Requests that this Gateway accepts, not covered by (1)-(3) |

A request with no match at any level is unprotected - not an error, simply no
`WAFPolicy` currently applies to it.

The rule and the listener are the ones agentgateway selected for the request.
For example, with a rule `health` that matches `PathPrefix /health` and an
unnamed catch-all rule, a policy on `health` covers `/health/live` but not
`/healthz-admin`: agentgateway sends `/healthz-admin` to the catch-all rule,
because a `PathPrefix` matches whole path segments. In the same way, a policy
on a rule that also matches a header covers only the requests that carry the
header.

Given a Gateway-level default and a route-level override:

```yaml
# Gateway default: Detection mode for the whole shared-gw Gateway.
apiVersion: gateway-protector.kubewarden.io/v1alpha1
kind: WAFPolicy
spec:
  targetRef: {kind: Gateway, name: shared-gw, namespace: infra}
  engine: {mode: Detection}
---
# Route override: replaces the default above for the "admin" rule only.
apiVersion: gateway-protector.kubewarden.io/v1alpha1
kind: WAFPolicy
spec:
  targetRef: {kind: HTTPRoute, name: admin-portal, namespace: team-shop, sectionName: admin}
  engine: {mode: Blocking}
```

every other rule on `admin-portal`, and every other route under `shared-gw`,
still gets the Gateway default; the `admin` rule gets the stricter policy
instead, in full - the two are never combined.

### Multiple parentRefs

An `HTTPRoute` can list more than one `parentRef` (attached to more than one
`Gateway`, or the same `Gateway` on two listeners). Each request gets the
Gateway-level policy (levels 3-4 above) of the Gateway and listener that
actually accepted it: a route attached to a public Gateway with a `Blocking`
default and to an internal Gateway with an `Off` default is blocked through
the public Gateway and not inspected through the internal one.

The same holds for two separate routes for the same hostname, one per
Gateway: each Gateway's traffic gets that Gateway's policy.

### Listener policies

A listener policy (level 3) applies to every request that its listener
accepts, whether the route's `parentRef` names that listener in `sectionName`
or names no listener at all. A `parentRef` that names another listener of the
same Gateway never receives traffic through this listener, so the policy
never applies to it.

## From policy to the processor

The controller turns the policies into two things (see `processorconfig.Build`):

- **One binding per Accepted policy** in the processor's config (see
  [`docs/processor.md`](processor.md#configuration) for its shape): the
  attachment point of the policy's `targetRef` and the engine compiled from
  the policy. A policy whose directives fail to compile gets a binding
  without an engine, so the requests that resolve to it are not inspected -
  they never fall back to a less specific policy. The config depends only on
  `WAFPolicy` and `WAFRuleSet` objects, not on `HTTPRoute` objects.
- **One generated `AgentgatewayPolicy` per route that a compiled policy can
  apply to** (see
  [`docs/wafpolicy-lifecycle.md` §4](wafpolicy-lifecycle.md#4-gateway-wiring-implemented)),
  which sends the route's traffic, and its identity, to the processor.
  `candidatePolicies` in `internal/controller/processorconfig/attachment.go`
  decides which policies can apply to a route: its rule policies, its
  route-wide policy, and - when some rule can fall through to the Gateway
  levels - the listener and default policies of every Gateway in
  `spec.parentRefs`. The same set also sizes the generated object's body
  phases, and gives the route count of each policy's `Programmed`
  condition.

## Limitations

- **No merging across attachment levels.** A route-level policy always
  fully replaces a Gateway-level default for the rules it covers; there is
  no way to, say, keep the Gateway default's `paranoiaLevel` while only
  overriding `engine.mode` at the route level.
- **`HTTPRoute` only.** A `WAFPolicy` can target a `Gateway` or an
  `HTTPRoute`, and the controller only wires `HTTPRoute` objects. A request
  of another route kind that reaches the processor (through a user-written
  `AgentgatewayPolicy`) can only resolve to the Gateway levels.
- **No admission-time preview.** These rules only run inside the
  reconciler and the processor; there is currently no way to ask "which
  policy would govern this request?" without applying the objects and
  sending the request (the processor logs the identity of every blocked
  request, and of every request no policy covers at the `debug` level).
