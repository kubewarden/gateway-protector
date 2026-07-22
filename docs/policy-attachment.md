# Policy attachment: how a WAFPolicy matches traffic

This document is the deep dive on **which `WAFPolicy` governs a given piece of
traffic**, and how that decision becomes the processor's host+path routing
table. See [`docs/wafpolicy-lifecycle.md`](wafpolicy-lifecycle.md) for the
`WAFPolicy` object's own lifecycle (Accepted/Programmed conditions,
conflicts, re-evaluation triggers) and
[`docs/processor.md`](processor.md#matching-semantics) for how the processor
matches an *incoming request* against the table this document describes how
to build.

Everything here is implemented by
`internal/controller/processorconfig/table.go`, called from
`processorconfig.Build` while [Programming](wafpolicy-lifecycle.md#3-programming-implemented)
runs. It is pure, in-memory logic: no admission-time equivalent exists yet
(see that doc's notes on why validation is currently reconciler-only).

## Attachment basics

A `WAFPolicy`'s `spec.targetRef` points at exactly one `Gateway` or one
`HTTPRoute`, optionally narrowed to a single listener (`Gateway`) or route
rule (`HTTPRoute`) via `sectionName`. Four attachment shapes are possible:

| `targetRef.kind` | `sectionName` | Scope |
| --- | --- | --- |
| `Gateway` | unset | Default for every route attached to this Gateway |
| `Gateway` | a listener name | Default for routes attached to that one listener |
| `HTTPRoute` | unset | Overrides the Gateway default for this route, every rule |
| `HTTPRoute` | a rule name | Overrides everything else for that one rule only |

Resolution across these is **most-specific-wins, full replacement, never
merging** - see [Which policy governs a rule](#which-policy-governs-a-rule)
below for the exact order. `examples/route-override/` has one worked manifest
per common scenario (`gateway-default.yaml`, `route-override.yaml`,
`route-opt-out.yaml`).

## Which policy governs a rule

`effectivePolicyForRule` resolves the one `WAFPolicy` that governs a single
`HTTPRoute` rule by trying four levels, most to least specific, and stopping
at the first match:

| Order | Attachment | Matches |
| --- | --- | --- |
| 1 | `HTTPRoute` + `sectionName` | This exact rule (only possible when the rule has a `name`) |
| 2 | `HTTPRoute`, no `sectionName` | Every rule on this route not covered by (1) |
| 3 | `Gateway` + `sectionName` | Routes attached to that specific listener (`sectionName` matches the `parentRef`'s `sectionName`) |
| 4 | `Gateway`, no `sectionName` | Every route attached to this Gateway not covered by (1)-(3) |

A rule with no match at any level is unprotected - not an error, simply no
`WAFPolicy` currently applies to it.

Given a Gateway-level default and a route-level override:

```yaml
# Gateway default: Detection mode for the whole shared-gw Gateway.
apiVersion: gateway-protector.kubewarden.io/v1alpha1
kind: WAFPolicy
spec:
  targetRef: {kind: Gateway, name: shared-gw, namespace: infra}
  engine: {mode: Detection, failureMode: FailOpen}
---
# Route override: replaces the default above for the "admin" rule only.
apiVersion: gateway-protector.kubewarden.io/v1alpha1
kind: WAFPolicy
spec:
  targetRef: {kind: HTTPRoute, name: admin-portal, namespace: team-shop, sectionName: admin}
  engine: {mode: Blocking, failureMode: FailClosed}
```

every other rule on `admin-portal`, and every other route under `shared-gw`,
still gets the Gateway default; the `admin` rule gets the stricter policy
instead, in full - the two are never combined.

### Multiple parentRefs

An `HTTPRoute` can list more than one `parentRef` (attached to more than one
`Gateway`, or the same `Gateway` on two listeners). Levels 3-4 above are
tried against each `parentRef` **in `spec.parentRefs` list order**, and the
first one that produces any Gateway-level match wins - not one match "per
parent". A route attached to two Gateways with conflicting defaults for the
same rule is therefore resolved deterministically, but not with full
per-listener fidelity (a documented simplification; see the multi-parent-routes
open question in the project's design notes).

## From policy to routing table

Once a rule's governing policy is known, it still has to become a `host` +
`pathPrefix` entry in the processor's table (see
[`docs/processor.md`](processor.md#configuration) for the table's shape).
That requires resolving *which hostnames* and *which paths* the rule
actually covers.

### Hostnames (`routeHosts`)

Tried in order, stopping at the first that applies:

1. the route's own `spec.hostnames`, if it declares any;
2. otherwise, the hostname of the specific listener named by the route's
   `parentRef.sectionName` (or `"*"` if that listener has no `hostname`);
3. otherwise, if the referenced `Gateway` has exactly **one** listener, that
   listener's hostname (or `"*"` if it has none);
4. otherwise - no hostnames anywhere, or an ambiguous multi-listener
   `Gateway` with no `sectionName` to disambiguate - the catch-all `"*"`.

Step 4 is the same documented simplification as the multi-parentRef case
above: rather than guessing, an ambiguous route is registered as "protect
this on any host" instead of being left out entirely.

### Paths (`rulePaths`)

For each `match` in the rule's `spec.matches`:

- an `Exact` or `PathPrefix` match contributes its `value` (defaulting to
  `/` if the match has no `path` at all - the Gateway API default);
- a rule with **no** `matches` at all contributes `/` alone (again, the
  Gateway API default: no matches means "match every request");
- a `RegularExpression` path match is **skipped** - the processor's table is
  prefix-based and cannot represent a regular expression. This is a
  documented limitation, not an approximation: a regex-matched rule simply
  gets no routing-table entry of its own (it may still be covered by a
  broader entry from another match on the same rule, or from a different
  rule).

## Limitations

- **No merging across attachment levels.** A route-level policy always
  fully replaces a Gateway-level default for the rules it covers; there is
  no way to, say, keep the Gateway default's `paranoiaLevel` while only
  overriding `failureMode` at the route level.
- **Multi-parentRef and multi-listener ambiguity** resolve to "first
  matching parentRef" / `"*"` respectively, rather than full per-listener
  fidelity (see above).
- **`RegularExpression` path matches never get a table entry.**
- **No admission-time preview.** These rules only run inside the
  reconciler; there is currently no way to ask "which policy would govern
  this route?" without applying the objects and observing the published
  config (or the `Programmed` condition's route count).
