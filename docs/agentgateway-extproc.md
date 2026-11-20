# agentgateway ↔ ext_proc Integration Notes

> **Status note, 2026-11-20.** These notes describe agentgateway at one commit
> from 2026-06-30. After that date, agentgateway closed the two gaps of
> section 4:
>
> - [#2369](https://github.com/agentgateway/agentgateway/pull/2369), merged
>   2026-07-01, added `metadataContext`, `requestAttributes`, and
>   `responseAttributes` to the ext_proc part of the `AgentgatewayPolicy` CRD.
> - [#2551](https://github.com/agentgateway/agentgateway/pull/2551), merged
>   2026-07-17, added `failureMode` to the same part.
>
> The sections below do not include these changes. As a result, section 4 and
> the section "Implications for gateway-protector" are out of date on these
> two points.

This is a research snapshot of how agentgateway wires traffic through an
`ext_proc` server (like this project's processor), gathered by reading the
agentgateway source directly. It exists to inform the design of the
"Gateway wiring" milestone, now implemented (see
`docs/wafpolicy-lifecycle.md`'s §4), specifically: what the controller can
put in a generated `AgentgatewayPolicy`, and whether the processor can be
told _which_ WAF engine to run directly instead of re-deriving it from
host+path (see `docs/processor.md`'s routing table).

**Pinned to:** agentgateway `v1.3.1-45-g8729cd04` (commit `8729cd04a85bd374701d00a7f2140e6408df7b1a`, 2026-06-30).
Everything below was read from a local checkout of that commit, not from
this repository - re-verify against whatever version is actually being
integrated with before relying on this for implementation, since none of
this is pinned as a dependency here and upstream can (and, given the gaps
below, likely will) change. All file paths quoted below (`crates/...`,
`controller/...`, `schema/...`) are relative to the **agentgateway**
repository, not this one.

Confidence is marked per claim: **confirmed** (read directly in code/proto/
CRD, with a path) vs **inferred** (a reasonable conclusion the source
doesn't state outright).

## 1. The `AgentgatewayPolicy` CRD surface today

**Confirmed.** Group/kind: `agentgateway.dev/v1alpha1`, kind
`AgentgatewayPolicy` (shortName `agpol`). The extProc-relevant part of the
spec, as actually defined in the Go API types:

```go
type ExtProc struct {
	// External Processor server to reach.
	// Supported types: `Service` and `Backend`.
	BackendRef *gwv1.BackendObjectReference `json:"backendRef,omitempty"`
	// How request and response phases are sent to ext_proc.
	ProcessingOptions *ProcessingOptions `json:"processingOptions,omitempty"`
}

type ExtProcConditional struct {
	Condition CELExpression `json:"condition,omitempty"` // optional; unset = fallback
	Policy    ExtProc       `json:"policy"`
}

// +kubebuilder:validation:ConditionalPolicy:fields=backendRef
type ExtProcOrConditional struct {
	ExtProc `json:",inline"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	Conditional []ExtProcConditional `json:"conditional,omitempty"`
}
```

`ProcessingOptions`: `requestBodyMode`/`responseBodyMode`
(`Buffered`/`BufferedPartial`/`FullDuplexStreamed`, default
`FullDuplexStreamed`), `requestHeaderMode`/`responseHeaderMode`
(`Send`/`Skip`, default `Send`), `requestTrailerMode`/`responseTrailerMode`
(`Skip`/`Send`, default `Send`), `allowModeOverride` (bool, default false).

That's the entire extProc surface: **`backendRef` + `processingOptions` +
an optional CEL-matched `conditional` list, nothing else.** No
`failureMode`, no metadata, no attributes (see §4).

Targeting: `spec.targetRefs`/`targetSelectors` may reference `Gateway`
(optionally `sectionName` = listener), `ListenerSet`, `HTTPRoute`/
`GRPCRoute` (optionally `sectionName` = route rule), or `InferencePool`.
`spec.strategy.inheritance` (`Default`/`Override`) controls whether a
more-specific policy can override a field a less-specific one set (see §5).

## 2. Data channels to the ext_proc server

**Confirmed.** The Rust runtime
(`crates/agentgateway/src/http/ext_proc.rs`) implements every data channel
Envoy's `ext_proc` protocol supports, all CEL-valued and configurable
per-policy - **in the underlying runtime and xDS proto**, independent of
whether the K8s CRD exposes them yet (it doesn't - see §4):

| Channel                                                         | Delivery                                                                                           | Notes                                                                                                                                                                                                                                                                                                      |
| --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `metadataContext` (namespace → key → CEL expr)                  | `ProcessingRequest.metadata_context` on **every** message (request headers, body chunks, trailers) | test: `test_cel_metadata_context_evaluation`                                                                                                                                                                                                                                                               |
| Reserved namespace **`agentgateway.dev.grpc_initial_metadata`** | **gRPC initial metadata**, sent once when the stream opens                                         | entries in this namespace are evaluated via CEL and excluded from the regular `metadata_context` payload; upstream's own test (`test_reserved_metadata_context_becomes_grpc_initial_metadata`) uses the example value `x-policy-ref: 'default/my-policy'` - functionally identical to an opaque engine key |
| `requestAttributes`/`responseAttributes` (key → CEL expr)       | `ProcessingRequest.attributes`, **first message only** per direction                               | namespace `envoy.filters.http.ext_proc`                                                                                                                                                                                                                                                                    |

A static CEL string literal (e.g. `"'<engineKey>'"`) in either
`metadataContext` or the reserved initial-metadata namespace is exactly the
mechanism needed to hand the processor an opaque, pre-computed selection
key instead of it re-deriving one from `:authority`/`:path`.

CEL identity roots available to these expressions (so a policy could also
carry _dynamic_ identity rather than a static key): `proxy.gateway.{namespace,name}`,
`proxy.listener.name`, `proxy.route.{namespace,name,kind,rule}`,
`proxy.bind`. `proxy.route` is populated at route selection, which happens
before route-phase policies run, so route-phase extProc CEL can reference
it.

Also confirmed: whatever the processor returns in
`ProcessingResponse.dynamic_metadata` is captured into request/response
extensions and made available to later CEL/logging as an `extproc`
variable - a round-trip channel, not just outbound.

## 3. Other channels considered and ruled out

**Confirmed, via filter ordering.** Within one phase, `ext_proc` runs
_before_ the transformation filter (both in the gateway-attached
`PreRouting` phase and the route-attached `PostRouting` phase). So a
route-level transformation/header-injection policy **cannot** inject a
header before route-level `ext_proc` sees the request - ruling out
"inject a header carrying the engine key" as a route-level workaround.

A gateway-attached (`PreRouting`) transformation _can_ inject a header
before a route-attached (`PostRouting`) `ext_proc` call, since the two are
different phases that don't merge (see §5) - but that only carries a value
that's constant per Gateway, not per route/policy, so it doesn't help
express per-route engine selection either.

An ext_authz server (also runs before `ext_proc`) could inject headers or
dynamic metadata visible to `ext_proc` via the `extauthz` CEL variable, but
that's a heavyweight detour for what §2's channels already do directly.

**Conclusion:** §2's `metadataContext` (or its reserved initial-metadata
namespace) is the clean channel. Nothing else comes close.

## 4. The gaps

**Confirmed.** Two real gaps stand between "the data plane supports this"
and "gateway-protector can use it":

1. **The CRD doesn't expose `metadataContext`/attributes.** The xDS proto
   backing `AgentgatewayPolicy` (`crates/protos/proto/resource.proto`) _has_
   `request_attributes`, `response_attributes`, and `metadata_context`
   fields on its `ExtProc` message, and the Rust runtime fully implements
   them (§2, with passing tests). The **Go controller that translates
   `AgentgatewayPolicy` into that proto never populates them** - it only
   sets target + processing options. The local, file-based agentgateway
   config format (`schema/config.json`) _does_ expose all of it. **Inferred:**
   this looks like an intended-but-not-yet-shipped part of the Kubernetes
   API surface, not a deliberate omission - the plumbing already exists
   end-to-end except for the one translation step.

2. **`failureMode` is hardcoded to `FAIL_CLOSED`.** The controller sets it
   unconditionally when building the proto:

   ```go
   // controller/pkg/agentgateway/plugins/traffic_plugin.go
   spec := &api.TrafficPolicySpec_ExtProc{
       Target: be,
       // always use FAIL_CLOSED to prevent silent data loss when ExtProc is unavailable.
       FailureMode: api.TrafficPolicySpec_ExtProc_FAIL_CLOSED,
   }
   ```

   There is no `failureMode` field on the `AgentgatewayPolicy` CRD's
   `ExtProc` type at all. In response, gateway-protector's own `WAFPolicy`
   API exposes **no failure-posture knob either** (see `WAFEngineSpec`'s doc
   comment in `api/v1alpha1/wafpolicy_types.go`): traffic is always failed
   closed when the processor is unreachable - the conservative direction -
   and the API doesn't promise a behavior the data plane can't deliver. A
   `failureMode` field can be reintroduced if upstream ever exposes one.

## 5. Attachment & merge semantics

**Confirmed.** Same-kind traffic policies (e.g. two `AgentgatewayPolicy`
objects both configuring `extProc`, one on a Gateway and one on a route)
**replace, not stack**: policies are collected from least- to
most-specific attachment point (Gateway → Listener → Service → Route →
RouteRule) and each kind is merged via a function whose entire body is,
in effect, "replace the whole field, unless a less-specific policy locked
it":

```rust
// crates/agentgateway/src/store/policy.rs
pub fn merge_with_inheritance(&mut self, policy: &RequestPolicy<T>, lock_inheritance: bool) {
    if self.inheritance_locked { return; }
    *self = policy.clone();
    self.inheritance_locked = lock_inheritance;
}
```

So a route-level `extProc` fully replaces a gateway-level one for that
route - field-level replacement of the whole block (including its
`conditional` list), never a deep merge. Setting
`spec.strategy.inheritance: Override` on the gateway-level policy locks
that field so more-specific (route-level) policies of the same kind can no
longer replace it.

**Exception:** `PreRouting` (gateway-attachable) and `PostRouting`
(route-attachable) are independent phases that never merge with each
other - a gateway-phase `extProc` and a route-phase `extProc` can both run
on the same request, as two separate ext_proc streams.

This matches (and confirms) the design assumption already documented in
this project: a route-level `WAFPolicy` is meant to fully replace, not
merge with, a Gateway-level default.

## 6. The conditional `extProc` and its 16-entry cap

**Confirmed.** `spec.traffic.extProc.conditional` is a list of
`{condition: <CEL>, policy: {backendRef, processingOptions}}` entries,
first-match-wins; at most one entry may omit `condition`, and it must be
last (used as a fallback). Bounded `MinItems=1`/`MaxItems=16` by CRD
validation. The same 16-entry cap applies to `targetRefs`/`targetSelectors`
and to the transformation policy's own conditional list - it's a
repo-wide convention, not something specific to `extProc`.

## Implications for gateway-protector

- **Engine selection by identity is validated end-to-end in the data
  plane, but gated on a small upstream change.** The reserved
  `agentgateway.dev.grpc_initial_metadata` namespace (or a plain
  `metadataContext` entry) would let a generated `AgentgatewayPolicy` carry
  its resolved engine key directly to the processor, eliminating the need
  for the processor's own host+path routing table (`docs/processor.md`)
  entirely - the controller would only ever need to publish
  `{engineKey → directives}`, not a routing table, and `HTTPRoute` churn
  would stop affecting the published config's _shape_ at all (see
  `docs/wafpolicy-lifecycle.md`'s scalability notes on the routing-table
  approach used today). This is worth raising upstream: the runtime and
  proto already do the work: only `ExtProc`'s translation into the
  `AgentgatewayPolicy` CRD (surfacing `metadataContext`, and populating it
  in the Go controller) is missing.
- **Until that lands, the host+path routing table stays.** It's the only
  selection mechanism expressible through today's `AgentgatewayPolicy`
  CRD, and the compile-memoization/watch-predicate work already done (see
  `docs/wafpolicy-lifecycle.md`) keeps its cost low even at route counts in
  the thousands.
- **The `failureMode` gap is resolved by not exposing the knob.** Generated
  `AgentgatewayPolicy` objects are fail-closed, period - and since
  `WAFPolicy` no longer has a `failureMode` field (removed precisely
  because of this finding, see §4), there is nothing left to silently
  contradict. Should upstream ever add a configurable failure mode, the
  field can be reintroduced on `WAFPolicy` alongside the wiring that
  honors it.
- **The replace-not-merge attachment model (§5) needs no design change** -
  it already matches what `docs/wafpolicy-lifecycle.md` describes for
  `WAFPolicy` attachment.
