# Gateway Protector — WAFPolicy Lifecycle

A `WAFPolicy` attaches a Coraza + OWASP Core Rule Set WAF engine to a `Gateway`
(as the default for every route under it) or to a single `HTTPRoute` (as an
override of that default for that route only). This document walks through
everything that happens to a `WAFPolicy` object from the moment it is applied
to the moment it is deleted: admission, acceptance, programming, re-evaluation,
and garbage collection.

See also:

- `docs/crds/CRD-docs-for-docs-repo.md` — full field-by-field reference for
  `WAFPolicySpec`/`WAFPolicyStatus`.
- `api/v1alpha1/wafpolicy_types.go` and `api/v1alpha1/common_types.go` — the
  authoritative Go types and condition constants.
- `docs/processor.md` — the data-plane config schema the controller renders
  and publishes (§3 below).
- `docs/policy-attachment.md` — the deep dive on exactly which `WAFPolicy`
  governs a given `HTTPRoute` rule (precedence across attachment levels,
  multi-parentRef/multi-listener resolution, and how that decision becomes
  the processor's routing table).
- `docs/agentgateway-extproc.md` — research notes on how agentgateway wires
  `ext_proc` traffic, feeding the still-planned Gateway wiring (§4 below).
- `examples/route-override/` — worked examples of the three attachment
  scenarios described in [Attachment model](#attachment-model).

## Attachment model

A `WAFPolicy`'s `spec.targetRef` points at exactly one `Gateway` or one
`HTTPRoute` (optionally a single listener/route-rule via `sectionName`).
Resolution between the two attachment levels is **most-specific-wins**, with
**full replacement, never merging**:

- **No policy targets the Gateway or the route** → the route runs
  unprotected.
- **A policy targets the Gateway** → it becomes the default WAF engine for
  every `HTTPRoute` attached to it. This is the common case: one object
  protects an entire site.
- **A policy targets a specific `HTTPRoute`** → it fully replaces the Gateway
  default for that route only; every other route under the Gateway keeps the
  Gateway default unaffected.
- **A route-level policy with `spec.engine.mode: Off`** → the route opts out
  of the Gateway default entirely (still a platform decision: `WAFPolicy` is
  expected to live in a platform-owned namespace, not one app teams can write
  to).

`examples/route-override/` contains one manifest for each of the last three
scenarios (`gateway-default.yaml`, `route-override.yaml`,
`route-opt-out.yaml`). See `docs/policy-attachment.md` for the exact
precedence rules (including `sectionName` and multi-parentRef resolution)
behind this summary.

## Lifecycle overview

```
   apply/update                                        delete
        │                                                  │
        ▼                                                  ▼
 ┌──────────────┐   ┌───────────────┐   ┌──────────────┐  garbage-
 │  Admission   │──►│  Acceptance   │──►│  Programming │  collected
 │  (webhook)   │   │ (implemented) │   │(implemented) │  (no finalizer)
 └──────────────┘   └───────┬───────┘   └──────┬───────┘
                            │                  │
                     Accepted condition   Programmed condition
                            │                  │
                            └────────┬─────────┘
                                     ▼
                          re-evaluated whenever:
                    this policy / a sibling targeting the
                    same attachment point / the targeted
                    Gateway or HTTPRoute / a referenced
                    WAFRuleSet changes
```

### 1. Admission

The `WAFPolicy` admission webhook (`internal/webhook/v1alpha1/wafpolicy_webhook.go`)
is registered and reachable, but **today it accepts every object unchanged** —
neither the defaulter nor the validator perform any real logic yet. Planned
validation (not yet implemented):

- Dry-compiling the composed Coraza directives (embedded Core Rule Set +
  `paranoiaLevel` + `anomalyThreshold` + `exclusions` + referenced
  `WAFRuleSet.spec.rules`), so an invalid configuration fails the `apply`
  itself with the compile error, instead of being stored and only surfacing
  later as a status condition. This dry-compile step already exists - see
  `internal/controller/processorconfig.CorazaDryCompile` - but today only
  runs during [Programming](#3-programming-implemented), after the object
  is already stored (surfacing as `Programmed=False/CompileFailed`); moving
  it into the webhook remains a planned improvement for faster feedback.
- Rejecting a duplicate `targetRef` (another `WAFPolicy` already targeting the
  exact same attachment point) as an admission-time `Conflicted` rejection,
  rather than only a status condition after the fact.

Deliberately **not** planned for the webhook: verifying that
`spec.customRulesRefs` resolves to an existing `WAFRuleSet`. See
[Why the reconciler validates again](#why-the-reconciler-validates-again)
below for why that check belongs to the reconciler instead.

Until admission validation lands, invalid configuration and attachment-point
conflicts are only caught by the reconciler, one step later — see
[Acceptance](#2-acceptance-implemented).

### Why the reconciler validates again

It may look redundant that the reconciler re-checks things (target
resolution, `customRulesRefs`, conflicts) that the admission webhook is also
meant to validate. The overlap is deliberate — the two layers answer
different questions and neither can replace the other:

- **Admission is point-in-time; acceptance must hold continuously.** A
  webhook only fires when the `WAFPolicy` itself is created or updated. But a
  previously-accepted policy can stop being valid because something *else*
  changed: its target `Gateway`/`HTTPRoute` is deleted or its listener/rule is
  renamed, a referenced `WAFRuleSet` is deleted, or the winner of a conflict
  is removed and a loser needs to be promoted. None of that produces an
  admission event on the `WAFPolicy`. Only the reconciler's watches (see
  [Re-evaluation triggers](#re-evaluation-triggers)) keep `Accepted` truthful
  over time.
- **Conflict detection in a webhook is inherently racy.** Two `WAFPolicy`
  objects applied at nearly the same time (e.g. a GitOps sync applying both)
  can each pass admission because neither request sees the other yet —
  admission is not transactional across objects, and the webhook's view of
  the cluster can be momentarily stale. The reconciler's
  `creationTimestamp`-based tiebreak is the actual, race-free arbiter; the
  webhook's duplicate-`targetRef` rejection is only a fast-feedback
  best-effort layer on top of it.
- **Cross-object reference checks don't belong in admission.** If the webhook
  hard-rejected a `WAFPolicy` whose `WAFRuleSet` doesn't exist yet, applying a
  directory of manifests (`kubectl apply -f dir/`) would succeed or fail
  depending on file ordering, even though both objects are being applied
  together. This is why `customRulesRefs` existence is intentionally left out
  of the webhook's planned checks and is instead the reconciler's job
  (`Accepted=False/Invalid`, re-evaluated once the `WAFRuleSet` shows up).
- **Webhooks can be bypassed or absent.** Objects created before the webhook
  was installed, a webhook outage combined with a lenient failure policy, or
  a restore from backup can all leave invalid or conflicting objects in etcd
  without ever going through admission. The reconciler cannot assume
  everything it reads has been validated.

In short: the webhook exists for **fast feedback** at `apply` time on what is
knowable from the object alone (directive compilation, a best-effort
conflict check); the reconciler is the **continuous source of truth** for
everything that can only be known by looking at the rest of the cluster, and
is what actually drives the `status.conditions` operators rely on.

### 2. Acceptance (implemented)

This is what `internal/controller/wafpolicy_controller.go`'s `Reconcile` does
today, in order, for the `WAFPolicy` being reconciled:

1. **Conflict detection.** Every `WAFPolicy` targeting the exact same
   attachment point (same `kind` + `namespace` + `name`, and the same
   `sectionName` if any) is listed via a field index
   (`wafpolicyAttachmentIndexField`, see `internal/controller/wafpolicy_conflicts.go`).
   If more than one exists, the **oldest by `creationTimestamp` wins**; ties
   (e.g. simultaneous GitOps apply, since `creationTimestamp` only has
   second-level resolution) are broken deterministically by comparing
   `namespace/name` lexicographically. Every other policy sharing that
   attachment point gets `Accepted=False, reason=Conflicted` and reconciling
   stops there — nothing else about the losing policy is touched, so whatever
   engine it may have previously had accepted keeps running unchanged in the
   data plane.

   This is **not** the same thing as a Gateway-level policy being overridden
   by a Route-level one: those target *different* attachment points (different
   `kind`/`name`), which is the intended most-specific-wins behavior described
   above, not a conflict.

2. **`targetRef` resolution.** The winning policy's `spec.targetRef` is
   resolved against the live `Gateway` or `HTTPRoute` it names (cross-namespace
   lookup, since a `WAFPolicy` typically lives in a different namespace than
   its target). If `sectionName` is set, it must also match an existing
   listener name (`Gateway`) or route-rule name (`HTTPRoute`). Failure sets
   `Accepted=False, reason=TargetNotFound`.

3. **`customRulesRefs` resolution.** Every `WAFRuleSet` named in
   `spec.customRulesRefs` must exist in the same namespace as the `WAFPolicy`.
   Failure sets `Accepted=False, reason=Invalid`.

4. **Acceptance.** Once all of the above succeed, the policy gets
   `Accepted=True, reason=Accepted`. `Programmed` is left untouched by this
   step - see [Programming](#3-programming-implemented) below, which owns it
   from this point on.

### 3. Programming (implemented)

Once a `WAFPolicy` is `Accepted=True`, a second, singleton reconciler -
`ProcessorConfigReconciler` (`internal/controller/processor_config_reconciler.go`)
- rebuilds the processor's *entire* data-plane config from *every* currently
Accepted `WAFPolicy` (not just the one that changed: the published config is
one global artifact, not a per-policy one) and sets `Programmed` on each of
them accordingly:

1. **Render directives** (`internal/controller/processorconfig.RenderDirectives`)
   for each Accepted policy: the embedded Core Rule Set (skipped entirely for
   `mode: Off`, which renders just `SecRuleEngine Off`), tuned by
   `paranoiaLevel`/`anomalyThreshold`, `requestBody`/`responseBody` access
   directives, extended with every referenced `WAFRuleSet.spec.rules`
   directive, narrowed by `exclusions`. Rendering is canonical: referenced
   `WAFRuleSet`s are emitted in namespace/name order rather than
   `customRulesRefs` order (which isn't semantically meaningful - see that
   field's doc comment), and `exclusions` are pooled, deduplicated, and
   sorted before being emitted as a single `SecRuleRemoveById` line plus one
   `SecRuleRemoveByTag` per tag. This makes step 2's deduplication effective
   across policies that are semantically equivalent but were written (or
   merged by server-side-apply) with their refs/exclusions in a different
   order or split differently - not just across byte-identical specs. The
   `paranoiaLevel`/`anomalyThreshold` override `SecAction` uses rule id
   `10000001`, part of the `10000000`-`10000099` block gateway-protector
   reserves for its own generated directives; `WAFCustomRule.id` (used by
   `WAFRuleSet.spec.rules`) is validated at admission to the `1`-`99999`
   site-local range precisely so it can never collide with that block, or
   with the OWASP Core Rule Set's own `900000`-`999999` range.

2. **Deduplicate by engine key** - a hash of the rendered directives
   (`processorconfig.EngineKey`) - so byte-identical configuration from
   different policies shares one compiled engine.
3. **Dry-compile** each new engine's directives in isolation
   (`processorconfig.CorazaDryCompile`, the same Coraza compile path the
   processor itself uses). A policy whose directives fail to compile is
   **excluded** from the published config - along with every route it would
   have covered - rather than blocking every other policy's config from
   being published; it gets `Programmed=False, reason=CompileFailed` with
   the compiler error as the message.
4. **Build the host+path routing table** (`processorconfig.Build`): for
   every `HTTPRoute` rule, resolve the effective policy the same
   most-specific-wins way §2 describes (route-rule override > whole-route
   override > Gateway-listener default > Gateway default), then register an
   entry per hostname (the route's own `spec.hostnames`, falling back to the
   matched listener's hostname, or `"*"` when that's ambiguous) and per path
   match (skipping `RegularExpression` matches, which the processor's
   prefix-based table cannot represent) - see `docs/policy-attachment.md`
   for the exact precedence, fallback order, and documented limitations.
5. **Publish** the result (`ConfigPublisher`; `ConfigMapPublisher` is the
   only implementation today) by creating/updating a ConfigMap this
   controller owns (name: `controller.ProcessorConfigMapName`, currently
   `gateway-protector-processor-config`, in the controller's own namespace),
   which the processor Deployment mounts and hot-reloads from (see
   `docs/processor.md`).
6. **Set `Programmed`** on every Accepted policy considered in step 4:
   `True, reason=Programmed` once its engine is compiled and published -
   regardless of whether it currently covers any route (an Accepted policy
   on a `Gateway` with no `HTTPRoute`s yet is still fully live, simply
   unused for now) - or `False, reason=CompileFailed` per step 3.

Because this reconciler is a singleton watching `WAFPolicy`, `WAFRuleSet`,
`Gateway`, and `HTTPRoute` events (any of which can change what the config
should contain), any relevant change re-triggers the *entire* rebuild, not
just the changed object's slice of it. It also primes the processor's
ConfigMap once at startup (even before any `WAFPolicy` exists), so a fresh
install always starts with a valid, inert config instead of a missing
ConfigMap.

**Known limitation:** with ConfigMap + inotify-reload distribution, there is
no acknowledgment from the processor that a published config was actually
compiled and is live - `Programmed=True` means "published", and the engine
typically becomes live within the processor's reload latency (well under a
second in practice, see `docs/processor.md`'s "Hot reload"), not
synchronously with the condition update. A future gRPC config stream (see
the project's design notes) would let `Programmed=True` mean a real,
per-replica compiled acknowledgment instead.

**Scalability:** rebuilding the config touches every accepted policy and
every `HTTPRoute`, so keeping each rebuild cheap matters once either grows
into the thousands. Two things keep it that way:

- **Compile memoization** (`processorconfig.CompileCache`): dry-compiling a
  Core Rule Set engine costs tens of milliseconds and non-trivial
  allocations, so `ProcessorConfigReconciler` only ever compiles a given
  engine key once and reuses the outcome (success or failure) across
  reconciles, evicting only the keys that stopped being part of the current
  world on each pass. A rebuild triggered by, say, an unrelated `HTTPRoute`
  edit that doesn't change any policy's effective directives recompiles
  nothing.
- **Watch predicates** (see [Re-evaluation triggers](#re-evaluation-triggers)
  below) filter out status-only updates before they even reach the
  reconciler, so the gateway implementation's routine `HTTPRoute`/`Gateway`
  status churn - which can be very frequent - never triggers a rebuild at
  all.

### 4. Gateway wiring (planned)

Not implemented yet. For every route actually protected by an accepted
`WAFPolicy`, the reconciler is expected to render/reconcile a generated
`AgentgatewayPolicy` object that wires that route's traffic through the
processor's `ext_proc` service (`spec.traffic.extProc`): the shared processor
Service as `backendRef`, and `processingOptions` sized to what the engine
actually needs (e.g. only buffering the request body when
`spec.requestBody.enabled` is true). Each generated `AgentgatewayPolicy` is
owned by the route it protects, so deleting or unattaching the route garbage
collects the generated object automatically.

**Known constraint:** as of the agentgateway version inspected in
`docs/agentgateway-extproc.md`, `AgentgatewayPolicy`'s `extProc` has no
`failureMode` field at all - the agentgateway controller hardcodes
`FAIL_CLOSED` when translating it. This means
`WAFPolicy.spec.engine.failureMode: FailOpen` cannot actually be honored
through generated `AgentgatewayPolicy` objects yet; see that document for
the full finding and its implications, including a data-plane-validated
path (carrying a resolved engine key as `ext_proc` metadata) that could
eventually replace the processor's host+path routing table entirely.

### Re-evaluation triggers

A `WAFPolicy` is re-reconciled whenever any of the following changes. The
first four rows are `WAFPolicyReconciler`'s watches (owns `Accepted`, and
`Programmed` only while *not* Accepted); the last row is
`ProcessorConfigReconciler`'s (owns `Programmed` once `Accepted=True`) - see
`SetupWithManager` in `wafpolicy_controller.go` and
`processor_config_reconciler.go` respectively.

Every watch below is filtered by a predicate that skips **status-only**
updates: neither reconciler's output ever depends on a watched object's
status (only on specs, plus which objects exist), so a status-only change
- most commonly the gateway implementation's routine `Gateway`/`HTTPRoute`
status writes, or a reconciler's own status update triggering itself - is
never relevant and would otherwise be pure waste at scale. `Create`/`Delete`
events always pass through regardless, since those are what actually
add/remove attachment points, siblings, and targets. For `WAFRuleSet`,
`Gateway`, and `HTTPRoute` this is a plain
`predicate.GenerationChangedPredicate` (spec changes bump `generation`,
status changes don't); for `WAFPolicy` itself it's a custom predicate
(`wafPolicyRelevantChangePredicate`) that also passes through an `Accepted`
condition change, since that transition is status-only but is exactly what
`ProcessorConfigReconciler` needs to react to.

| Change                                          | Effect                                                                                                             |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| The `WAFPolicy` itself                          | Re-runs the full lifecycle above.                                                                                   |
| A sibling `WAFPolicy` targeting the same attachment point | Every policy sharing that attachment point is re-evaluated — e.g. deleting the winner of a conflict promotes the oldest remaining loser to `Accepted`. |
| The targeted `Gateway`/`HTTPRoute`              | Every `WAFPolicy` targeting that object (any `sectionName`) is re-evaluated, e.g. a renamed/removed listener flips `Accepted` to `TargetNotFound`. |
| A referenced `WAFRuleSet`                       | Every `WAFPolicy` whose `customRulesRefs` names it is re-evaluated.                                                 |
| Any `WAFPolicy`, `WAFRuleSet`, `Gateway`, or `HTTPRoute` change | The entire processor config is rebuilt from every currently Accepted `WAFPolicy` and republished; `Programmed` is refreshed on all of them (see [Programming](#3-programming-implemented)). |

### Deletion

`WAFPolicy` has no finalizer today: there is nothing external for the
reconciler to clean up yet (once `AgentgatewayPolicy` generation lands, that
will need one, so the generated objects can be reliably GC'd rather than
relying solely on owner references). Deleting a `WAFPolicy` that was the
winner of a conflict causes its former loser(s) to be re-evaluated (see the
table above) and, if still the oldest remaining policy for that attachment
point, promoted to `Accepted=True`. Deleting any `WAFPolicy` also
re-triggers `ProcessorConfigReconciler` (it watches `WAFPolicy` events),
which republishes the processor config without that policy's engine/routes
- no separate cleanup step is needed since the config is rebuilt from
scratch (every currently Accepted policy) on every reconcile, not patched
incrementally.

## Status conditions reference

| Condition   | Status  | Reason           | Meaning                                                                                          | What to do                                                                                     |
| ----------- | ------- | ---------------- | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `Accepted`  | `True`  | `Accepted`       | Target resolved, `customRulesRefs` resolved, no conflict.                                          | Nothing — the policy is valid.                                                                     |
| `Accepted`  | `False` | `TargetNotFound` | `spec.targetRef` doesn't resolve, or its `sectionName` doesn't match an existing listener/route rule. | Check the target `Gateway`/`HTTPRoute` name, namespace, and `sectionName` for typos, or that it exists yet. |
| `Accepted`  | `False` | `Invalid`        | A `spec.customRulesRefs` entry doesn't resolve to an existing `WAFRuleSet` in the same namespace.  | Create the missing `WAFRuleSet`, or fix the reference.                                             |
| `Accepted`  | `False` | `Conflicted`     | Another `WAFPolicy` (older by `creationTimestamp`) already targets the exact same attachment point. | Point one of the two policies at a different attachment point, or delete the redundant one.        |
| `Programmed`| `False` | `Pending`        | The policy is not (or no longer) `Accepted`; `ProcessorConfigReconciler` hasn't considered it.       | Fix whatever `Accepted` reports; `Programmed` follows automatically once it becomes `True`.        |
| `Programmed`| `True`  | `Programmed`     | The engine compiled successfully and was published to the processor's config, regardless of whether it currently covers any route. | Nothing — live (modulo the processor's own reload latency; see `docs/processor.md`'s "Hot reload"). |
| `Programmed`| `False` | `CompileFailed`  | The policy is `Accepted`, but its composed Coraza/SecLang directives (Core Rule Set + `paranoiaLevel`/`anomalyThreshold`/`exclusions` + referenced `WAFRuleSet.spec.rules`) failed to compile. Excluded from the published config; every route it would have covered is currently unprotected. | Read the compiler error in the condition message; it almost always points at a malformed custom `WAFRuleSet` directive. |

## Troubleshooting

`kubectl get wafpolicy` prints `Target Kind`, `Target Name`, `Mode`,
`Accepted`, `Programmed`, and `Age` as columns, so most issues are visible
without needing `-o yaml`.

| Symptom                                              | Likely reason                                     | Fix                                                                                     |
| ------------------------------------------------------ | ---------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `Accepted` never turns `True`                         | `TargetNotFound`, `Invalid`, or `Conflicted` — check `status.conditions[].message` | See the reference table above for the matching reason.                                     |
| Two policies for the same route, only one is `Accepted` | Expected: conflict resolution picked the older one | Not a bug — remove the redundant policy or repoint it at a different attachment point.     |
| A route-level policy isn't overriding the Gateway default | `targetRef` doesn't actually match the route (wrong `namespace`/`name`/`sectionName`), or it targets the Gateway again instead of the `HTTPRoute` | Verify `spec.targetRef.kind` is `HTTPRoute` and every field matches the intended route exactly. |
| `Programmed` stays `False/Pending` even though `Accepted=True` | `ProcessorConfigReconciler` hasn't run yet (should be within moments - it watches `WAFPolicy` changes) or is failing to publish (check its logs and RBAC on the processor's ConfigMap). | Check the controller's logs for `processor-config` reconcile errors.                       |
| `Programmed=False/CompileFailed`                      | The policy's composed directives don't compile - almost always a malformed custom `SecRule` in a referenced `WAFRuleSet`. | Read the condition message (the Coraza compiler error) and fix the offending `WAFRuleSet.spec.rules[].directive`. |
| The processor doesn't seem to be enforcing a policy that shows `Programmed=True` | The processor hasn't picked up the new ConfigMap yet (kubelet sync + inotify reload latency, typically well under a second - see `docs/processor.md`'s "Hot reload"), or nothing routes traffic through it yet (Gateway wiring - see [§4](#4-gateway-wiring-planned) - isn't implemented). | Check the processor's logs for a "Reloaded processor config" line; confirm `AgentgatewayPolicy` generation isn't the missing piece. |
