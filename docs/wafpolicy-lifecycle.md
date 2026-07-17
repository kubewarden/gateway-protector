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
- `docs/processor.md` — the data-plane config schema the controller pushes to
  the processor once engine compilation (§3 below) is implemented.
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
`route-opt-out.yaml`).

## Lifecycle overview

```
   apply/update                                        delete
        │                                                  │
        ▼                                                  ▼
 ┌──────────────┐   ┌───────────────┐   ┌──────────────┐  garbage-
 │  Admission   │──►│  Acceptance   │──►│  Programming │  collected
 │  (webhook)   │   │ (implemented) │   │  (planned)   │  (no finalizer)
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
  later as a status condition.
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
   `Accepted=True, reason=Accepted`. At this point `Programmed` is set to
   `False, reason=Pending` — see below, this is as far as the reconciler goes
   today.

### 3. Programming (planned)

Not implemented yet. Once a `WAFPolicy` is `Accepted=True`, the reconciler is
expected to:

- Render the effective Coraza/SecLang directives for the attachment point:
  the embedded Core Rule Set, tuned by `paranoiaLevel` and
  `anomalyThreshold`, narrowed by `exclusions`, and extended with every
  referenced `WAFRuleSet.spec.rules` directive.
- Compute an **engine key** — a hash of those rendered directives — so that
  two attachment points sharing byte-identical configuration reuse the same
  compiled engine in the data plane instead of one per policy/route.
- Push `{engineKey → directives}` plus a host+path routing table (mapping
  every route protected by this policy to its engine key) to the processor —
  see `docs/processor.md` for that config's exact schema and matching
  semantics.
- Once the processor acknowledges the new config is compiled and live, set
  `Programmed=True, reason=Programmed`.

### 4. Gateway wiring (planned)

Also not implemented yet. For every route actually protected by an accepted
`WAFPolicy`, the reconciler is expected to render/reconcile a generated
`AgentgatewayPolicy` object that wires that route's traffic through the
processor's `ext_proc` service (`spec.traffic.extProc`): the shared processor
Service as `backendRef`, `failureMode` set to the policy's
`spec.engine.failureMode`, and `processingOptions` sized to what the engine
actually needs (e.g. only buffering the request body when
`spec.requestBody.enabled` is true). Each generated `AgentgatewayPolicy` is
owned by the route it protects, so deleting or unattaching the route garbage
collects the generated object automatically.

### Re-evaluation triggers

A `WAFPolicy` is re-reconciled whenever any of the following changes, via the
watches registered in `SetupWithManager`
(`internal/controller/wafpolicy_controller.go`):

| Change                                          | Effect                                                                                                             |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| The `WAFPolicy` itself                          | Re-runs the full lifecycle above.                                                                                   |
| A sibling `WAFPolicy` targeting the same attachment point | Every policy sharing that attachment point is re-evaluated — e.g. deleting the winner of a conflict promotes the oldest remaining loser to `Accepted`. |
| The targeted `Gateway`/`HTTPRoute`              | Every `WAFPolicy` targeting that object (any `sectionName`) is re-evaluated, e.g. a renamed/removed listener flips `Accepted` to `TargetNotFound`. |
| A referenced `WAFRuleSet`                       | Every `WAFPolicy` whose `customRulesRefs` names it is re-evaluated.                                                 |

### Deletion

`WAFPolicy` has no finalizer today: there is nothing external for the
reconciler to clean up yet (once `AgentgatewayPolicy` generation lands, that
will need one, so the generated objects can be reliably GC'd rather than
relying solely on owner references). Deleting a `WAFPolicy` that was the
winner of a conflict causes its former loser(s) to be re-evaluated (see the
table above) and, if still the oldest remaining policy for that attachment
point, promoted to `Accepted=True`.

## Status conditions reference

| Condition   | Status  | Reason           | Meaning                                                                                          | What to do                                                                                     |
| ----------- | ------- | ---------------- | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `Accepted`  | `True`  | `Accepted`       | Target resolved, `customRulesRefs` resolved, no conflict.                                          | Nothing — the policy is valid.                                                                     |
| `Accepted`  | `False` | `TargetNotFound` | `spec.targetRef` doesn't resolve, or its `sectionName` doesn't match an existing listener/route rule. | Check the target `Gateway`/`HTTPRoute` name, namespace, and `sectionName` for typos, or that it exists yet. |
| `Accepted`  | `False` | `Invalid`        | A `spec.customRulesRefs` entry doesn't resolve to an existing `WAFRuleSet` in the same namespace.  | Create the missing `WAFRuleSet`, or fix the reference.                                             |
| `Accepted`  | `False` | `Conflicted`     | Another `WAFPolicy` (older by `creationTimestamp`) already targets the exact same attachment point. | Point one of the two policies at a different attachment point, or delete the redundant one.        |
| `Programmed`| `False` | `Pending`        | The policy is not yet (or no longer) accepted, or engine compilation/data-plane wiring hasn't happened yet (always true today — see [Programming](#3-programming-planned)). | If `Accepted=True` and this persists, engine compilation/wiring is not implemented yet in this milestone; otherwise fix whatever `Accepted` reports. |
| `Programmed`| `True`  | `Programmed`     | *(planned)* The engine is compiled and live in the data plane, and the route is wired to it.        | Nothing — fully live.                                                                               |

## Troubleshooting

`kubectl get wafpolicy` prints `Target Kind`, `Target Name`, `Mode`,
`Accepted`, `Programmed`, and `Age` as columns, so most issues are visible
without needing `-o yaml`.

| Symptom                                              | Likely reason                                     | Fix                                                                                     |
| ------------------------------------------------------ | ---------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `Accepted` never turns `True`                         | `TargetNotFound`, `Invalid`, or `Conflicted` — check `status.conditions[].message` | See the reference table above for the matching reason.                                     |
| Two policies for the same route, only one is `Accepted` | Expected: conflict resolution picked the older one | Not a bug — remove the redundant policy or repoint it at a different attachment point.     |
| A route-level policy isn't overriding the Gateway default | `targetRef` doesn't actually match the route (wrong `namespace`/`name`/`sectionName`), or it targets the Gateway again instead of the `HTTPRoute` | Verify `spec.targetRef.kind` is `HTTPRoute` and every field matches the intended route exactly. |
| `Programmed` stays `False/Pending` even though `Accepted=True` | Expected in this milestone: engine compilation and processor config push are not implemented yet | Nothing to fix — this is current, expected behavior, not an error.                          |
