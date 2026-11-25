|              |                                 |
| :----------- | :------------------------------ |
| Feature Name | Gateway namespace rule          |
| Start Date   | 2026-11-24                      |
| Category     | Security                        |
| RFC PR       | [fill this in after opening PR] |
| State        | **ACCEPTED**                    |

# Summary

[summary]: #summary

<!---
Brief (one-paragraph) explanation of the feature.
--->

In this document, a policy is a `WAFPolicy` object.

Today a policy in any namespace can target a `Gateway` or an `HTTPRoute` in
any other namespace. As a result, a user who can write a policy in one
namespace controls the WAF of the full cluster.

This RFC proposes the Gateway namespace rule. A policy has an effect only on
the traffic of the `Gateway` objects in the namespace of the policy. The owner
of a namespace then controls the WAF of the Gateways of this namespace, and of
no other Gateway.

The rule needs no configuration and no fixed namespace. It changes the steps
that accept a policy in the controller. It also changes the key that the
processor uses to select a route policy.

# Motivation

[motivation]: #motivation

<!---
- Why are we doing this?
- What use cases does it support?
- What is the expected outcome?

Describe the problem you are trying to solve, and its constraints, without
coupling them too closely to the solution you have in mind. If this RFC is not
accepted, the motivation can be used to develop alternative solutions.
--->

## The goal that is at risk

RFC 0001 has this goal: the platform team owns the protection, and an
application team cannot weaken it or disable it. The platform team is the team
that operates the gateways. An application team owns the routes of its
applications.

RFC 0001, `ARCHITECTURE.md`, and `docs/wafpolicy-lifecycle.md` give the same
advice for this goal. The platform team keeps the policies in one namespace,
and the application teams get no write access to this namespace.

This advice is not sufficient.

## The current behavior

The controller has no limit on the namespace of a policy:

- The controller reads the policies of every namespace. `CacheOptions` in
  `internal/controller/transform.go` limits only `Secret` and `ConfigMap`
  objects to one namespace.
- The controller asks for no permission from the namespace of the target.
  `resolveTarget` in `internal/controller/wafpolicy_target.go` makes sure only
  that the target exists.
- A current test expects this behavior. In
  `internal/controller/wafpolicy_controller_test.go`, a policy in `default`
  targets a `Gateway` in another namespace and gets `Accepted=True`.

As a result, the rule that protects a cluster today is different from the
advice. The rule is: no user outside the platform team can write a policy in
any namespace.

## What a user can do with write access in one namespace

| Action of the user                                                   | Result                                                                                           |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Attach a policy with `mode: Off` to the route of another team        | The WAF does not inspect this route. A route policy replaces the gateway policy.                 |
| Attach a `Blocking` policy with a rule set that denies every request | The route of the other team is out of service.                                                   |
| Create a policy for a target before the platform team does           | The policy of the platform team stays `Conflicted`, because the oldest policy wins a conflict.   |
| Write `Accepted=True` in the status of a policy                      | The controller publishes the policy. `ProcessorConfigReconciler` reads this condition as a fact. |

The third action also works for a target that does not exist yet. The
controller looks for a conflict before it looks for the target.

The first three actions need write access to `wafpolicies`. The second action
also needs write access to `wafrulesets`. The last action needs write access
to `wafpolicies/status`.

## How a user gets this access

The Helm chart has no aggregated roles. An aggregated role adds its rules to
the built-in roles of Kubernetes. As a result, the built-in roles `admin` and
`edit` do not include the two policy kinds.

A user gets the access in two ways:

- An administrator gives an explicit grant for the policy kinds
- An administrator gives a wildcard role in one namespace

A wildcard role is a role that permits every resource kind.

The effect of such a grant is not obvious. An administrator who reads a `Role`
in the namespace `team-shop` expects an effect in `team-shop` only. The real
effect is on every `Gateway` and `HTTPRoute` of the cluster.

## The Gateway API guideline

[GEP-713](https://gateway-api.sigs.k8s.io/geps/gep-713/) is the guideline of
the Gateway API for policy attachment. It discourages a target in another
namespace:

> Cross namespace references can often lead to escalation of privileges
> associated with the Confused deputy problem.

In a confused deputy problem, a program with wide rights acts for a user with
narrow rights. Here the controller is this program.

GEP-713 permits a target in another namespace only with a handshake. A
handshake is an agreement that the owners of the two namespaces both state.
The guideline gives this condition:

> The policy is paired with ReferenceGrants or some other form of equivalent
> handshake that ensures that the target is accepting the policy.

The current API has no handshake.

## Constraints

A solution must obey these constraints:

- The platform team can write a policy for a route in the namespace of an
  application team
- An application team cannot weaken the protection of the platform team, even
  with write access to the policy kinds in its own namespace
- The code contains no fixed namespace name, because each cluster puts its
  `Gateway` objects in different namespaces

## Status of these findings

The findings in this section come from the code. No test reproduces the four
actions yet. A test that reproduces them is the first step of the work.

## Examples / User Stories

[examples]: #examples

<!---
Examples of how the feature will be used. Interactions should show the action
and the response. When appropriate, provide user stories in the form of "As a
[role], I want [feature], so [that]."
--->

- As a platform engineer, I want one policy in the namespace of my `Gateway`,
  so that every route of this `Gateway` gets the same protection.
- As a platform engineer, I want to write a policy for one route of an
  application team, so that I can tune its rules.
- As a platform engineer, I want policies of other namespaces to have no
  effect on my `Gateway`, so that a wrong grant does no damage.
- As an application engineer with my own `Gateway`, I want to manage its WAF,
  so that I do not depend on the platform team.
- As a cluster administrator, I want a grant to have an effect on its
  namespace only, so that I can review each namespace alone.

The section [Five cases](#five-cases) shows the result of the rule for these
stories.

# Detailed design

[design]: #detailed-design

<!---
This is the bulk of the RFC. Explain the design in enough detail for somebody
familiar with the product to understand, and for somebody familiar with the
internals to implement.

This section should cover architecture aspects and the rationale behind
disruptive technical decisions (when applicable), as well as corner-cases and
warnings.
--->

## The rule

The rule has two parts: acceptance and scope.

For acceptance, the controller accepts a policy only in one of these
conditions:

- The target is a `Gateway`, and this `Gateway` is in the namespace of the
  policy
- The target is an `HTTPRoute`, and this route names in `spec.parentRefs` at
  least one `Gateway` in the namespace of the policy

For scope, a route policy applies only to the requests that a `Gateway` in the
namespace of the policy accepts.

A `parentRef` without a namespace names a `Gateway` in the namespace of the
route. This is the default of the Gateway API.

The rule gives one statement for the threat model. A user who can write
policies in a namespace controls the WAF of the Gateways of this namespace.
This user controls no other traffic.

## Why the Gateway namespace

The Gateway API gives each object kind an owner. A cluster operator owns the
`Gateway` objects, and application developers own the routes. As a result, the
`Gateway` objects are in a small number of namespaces, and the routes are in
many namespaces.

The Gateway API already has a handshake between the two owners:

- The owner of the route names the `Gateway` in `spec.parentRefs`
- The owner of the `Gateway` admits the route with `allowedRoutes`

`allowedRoutes` is a field of a `Gateway` listener. It selects the namespaces
that routes can come from. Traffic flows only when the two owners agree.

The rule uses the first half of this handshake. A route owner who names a
`Gateway` accepts the rules of the owner of this `Gateway`. GEP-713 does not
name this handshake. This RFC treats it as an equivalent one.

The controller does not read `allowedRoutes`, and the rule does not need it.
If a `Gateway` does not admit a route, the route gets no traffic through this
`Gateway`. A policy in the namespace of this `Gateway` then has no effect on
the route.

## Five cases

This section shows only the relevant fields of each manifest. All the cases
use these objects:

```yaml
# The platform team owns this Gateway.
kind: Gateway
metadata: {name: shared-gw, namespace: infra}
---
# The shop team owns this route.
kind: HTTPRoute
metadata: {name: shop, namespace: team-shop}
spec:
  parentRefs:
    - {name: shared-gw, namespace: infra}
```

| Case | Namespace of the policy | Target                 | Mode        | Result                                            |
| ---- | ----------------------- | ---------------------- | ----------- | ------------------------------------------------- |
| 1    | `infra`                 | Route `team-shop/shop` | `Blocking`  | Accepted. The route names `infra/shared-gw`.      |
| 2    | `team-evil`             | Route `team-shop/shop` | `Off`       | Not accepted. The route names no `Gateway` there. |
| 3    | `team-shop`             | Route `team-shop/shop` | `Off`       | Not accepted. The `Gateway` is in `infra`.        |
| 4    | `team-blog`             | Route `team-blog/blog` | `Detection` | Accepted. The route names `team-blog/blog-gw`.    |
| 5    | `team-shop`             | Route `team-shop/shop` | `Off`       | Accepted, with a limited scope. See the text.     |

Case 2 shows the protection against another team. The team in `team-evil`
cannot change the result, because only the shop team can edit the
`parentRefs` of the route.

Case 3 shows that the owner of a route does not own the protection of the
route.

Case 4 shows a team with its own `Gateway`. The blog team has the `Gateway`
`team-blog/blog-gw`, and its route `team-blog/blog` names this `Gateway`. The
blog team manages the WAF of this `Gateway`. It has no effect on the shop
route, as in case 2.

In case 5, the shop team creates a second `Gateway` and adds it to the route:

```yaml
kind: Gateway
metadata: {name: local-gw, namespace: team-shop}
---
kind: HTTPRoute
metadata: {name: shop, namespace: team-shop}
spec:
  parentRefs:
    - {name: shared-gw, namespace: infra}
    - {name: local-gw}
```

The route then names a `Gateway` in `team-shop`, so the controller accepts the
`Off` policy of the shop team. The scope part of the rule limits this policy:

| The request arrives through | Policy that applies               |
| --------------------------- | --------------------------------- |
| `infra/shared-gw`           | The policy of the platform team   |
| `team-shop/local-gw`        | The `Off` policy of the shop team |

A policy that targets a `Gateway` follows the same rule. The controller does
not accept a policy in `team-evil` that targets `infra/shared-gw`. It accepts
a policy in `infra` that targets `infra/shared-gw`.

## How the processor selects a policy today

Case 5 depends on the selection in the processor. This section describes the
current code.

agentgateway sends the identity of each request to the processor.
`wiringMetadataContext` in `internal/controller/processor_config_wiring.go`
asks agentgateway for these values:

- The namespace and the name of the `Gateway`
- The name of the listener
- The kind, the namespace, and the name of the route
- The name of the rule

If the namespace of the `Gateway` is absent, the processor rejects the request
(`identityFromMetadata` in `internal/processor/identity.go`).

The controller publishes one binding for each accepted policy. A binding
connects a target to a WAF engine. Its fields are the kind, the namespace, the
name, and the section name of the target (`Binding` in
`internal/processor/config/types.go`). A binding does not contain the
namespace of the policy.

`Snapshot.Resolve` in `internal/processor/config/snapshot.go` looks for a
binding in this order and uses the first one that it finds:

| Order | Binding of         | Values of the request that the lookup uses     |
| ----- | ------------------ | ---------------------------------------------- |
| 1     | A route rule       | Route namespace, route name, rule name         |
| 2     | A route            | Route namespace, route name                    |
| 3     | A Gateway listener | Gateway namespace, Gateway name, listener name |
| 4     | A Gateway          | Gateway namespace, Gateway name                |

Levels 3 and 4 use the `Gateway` of the request. The test `TestPolicySelection`
in `internal/controller/processorconfig/selection_test.go` covers a route with
two Gateways for these levels.

Levels 1 and 2 do not use the `Gateway` of the request. As a result, a route
policy applies to the route through every `Gateway`. `TestSnapshotResolve`
shows the same: a route binding wins for each request of its route.

This has one consequence for case 5. With the acceptance part of the rule
alone, the `Off` policy of the shop team applies to the traffic of
`infra/shared-gw` too. A team that can create a `Gateway` can then turn the
platform WAF off. The scope part of the rule is necessary.

## Changes

### Acceptance in the controller

`resolveTarget` in `internal/controller/wafpolicy_target.go` gets the
acceptance part of the rule:

- For a `Gateway` target, it compares `targetRef.namespace` with the namespace
  of the policy
- For an `HTTPRoute` target, it reads the route and looks for a `parentRef` of
  the kind `Gateway` in the namespace of the policy

The cache of the controller already keeps the `parentRefs` of each route
(`TransformStripHTTPRoute`). A change of the route already starts a new
reconcile of the policies that target it.

If the rule rejects a policy, the policy gets `Accepted=False` with the new
reason `NotAllowed`. The message names the cause, for example:

```text
HTTPRoute team-shop/shop names no Gateway in the namespace team-evil of this policy
```

### Conflicts

Today two policies conflict when they have the same target. With the rule, two
policies conflict when they have the same target and the same namespace.

`attachmentKey` in `internal/controller/wafpolicy_conflicts.go` gets the
namespace of the policy as one more value. This change has two results:

- Two route policies of two namespaces on the same route do not conflict. Each
  one applies to the traffic of the Gateways of its namespace.
- A policy of another namespace cannot win a conflict against the policy of
  the owner. This closes the third action in the Motivation section.

### The binding and the selection

A binding of the kind `HTTPRoute` gets one more field, `gatewayNamespace`. Its
value is the namespace of the policy. A binding of the kind `Gateway` does not
need it, because its `namespace` field is already the namespace of the
`Gateway`.

```json
{
  "kind": "HTTPRoute",
  "namespace": "team-shop",
  "name": "shop",
  "gatewayNamespace": "infra",
  "waf": { "engineKey": "e38d463ff79fd7b2" }
}
```

`AttachmentPoint` gets the same field, and `Identity.attachmentPoints` fills it
with the `Gateway` namespace of the request for levels 1 and 2. The order of
the four levels does not change.

In case 5, the result is as follows:

| The request arrives through | Levels 1 and 2 look for a binding with | Result                       |
| --------------------------- | -------------------------------------- | ---------------------------- |
| `infra/shared-gw`           | `gatewayNamespace: infra`              | No binding. Level 4 applies. |
| `team-shop/local-gw`        | `gatewayNamespace: team-shop`          | The `Off` binding applies.   |

The format of the configuration changes, so `SchemaVersion` in
`internal/processor/config/types.go` becomes 3. `Validate` requires
`gatewayNamespace` for each `HTTPRoute` binding.

agentgateway already sends the `Gateway` namespace of each request. The
generated `AgentgatewayPolicy` objects do not change.

### The wiring

`candidatePolicies` in `internal/controller/processorconfig/attachment.go`
finds the policies that can apply to a route. The controller uses this set for
two decisions: if it generates an `AgentgatewayPolicy` for the route, and
which body phases agentgateway sends.

Today the function stops at a route policy and does not add the Gateway
policies. With the rule, this is wrong. In case 5, the set has only the `Off`
policy of the shop team. agentgateway then sends no request body, and the
`Blocking` policy of the platform team cannot inspect one.

The function must work for each `parentRef` that names a `Gateway`. For the
namespace of this `Gateway`, it does these steps:

1. It adds each rule policy of the route in this namespace.
2. If each rule of the route has such a policy, it stops for this `parentRef`.
3. If a route policy in this namespace exists, it adds this policy and stops
   for this `parentRef`.
4. If no route policy exists, it adds the listener policies and the Gateway
   policy of this `parentRef`, as today.

### The status is not a source of trust

`processorconfig.Build` receives the policies that have `Accepted=True`. A user
with write access to `wafpolicies/status` can write this condition.

`Build` must apply the rule again, without the status:

- It publishes a `Gateway` binding only if the policy and the `Gateway` are in
  the same namespace
- It always writes the namespace of the policy in `gatewayNamespace`, never a
  value from the specification of the policy

As a result, a false `Accepted=True` gives a user no effect outside the
Gateways of the namespace of the policy.

### The API

The `WAFPolicy` schema does not change. `targetRef.namespace` stays required.
Its comment in `api/v1alpha1/common_types.go` changes, because it describes
one platform namespace for all the policies.

`api/v1alpha1/common_types.go` gets the new constant
`ConditionReasonNotAllowed`.

### Summary of the code changes

| File                                                | Change                                                           |
| --------------------------------------------------- | ---------------------------------------------------------------- |
| `internal/controller/wafpolicy_target.go`           | The acceptance part of the rule                                  |
| `internal/controller/wafpolicy_conflicts.go`        | The namespace of the policy in the conflict key                  |
| `internal/processor/config/types.go`                | `gatewayNamespace` in `Binding` and `AttachmentPoint`, version 3 |
| `internal/processor/config/identity.go`             | The `Gateway` namespace of the request in levels 1 and 2         |
| `internal/processor/config/validate.go`             | `Validate` requires `gatewayNamespace` for an `HTTPRoute` binding |
| `internal/controller/processorconfig/attachment.go` | The policy index and `candidatePolicies` for each `parentRef`    |
| `internal/controller/processorconfig/build.go`      | The rule without the status                                      |
| `api/v1alpha1/common_types.go`                      | The reason `NotAllowed` and the field comment                    |

## Upgrade

This change is not compatible with the layout that the project documents
today. All the examples keep the policies in `gateway-protector-system` and
target a `Gateway` or an `HTTPRoute` in another namespace. After the upgrade,
these policies get `Accepted=False`, and the WAF stops for their traffic.

An administrator moves the policies before the upgrade:

1. List the policies and their targets:

   ```shell
   kubectl get wafpolicies -A -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,KIND:.spec.targetRef.kind,TARGET_NS:.spec.targetRef.namespace,TARGET:.spec.targetRef.name'
   ```

2. For each `Gateway` policy, compare `NAMESPACE` with `TARGET_NS`.
3. For each `HTTPRoute` policy, compare `NAMESPACE` with the namespaces in the
   `parentRefs` of the route.
4. If the namespaces are different, create a copy of the policy in the
   namespace of the `Gateway`.
5. If the policy has `customRulesRefs`, copy the `WAFRuleSet` objects to the
   same namespace.
6. Upgrade gateway-protector.
7. Make sure that each copy has `Accepted=True` and `Programmed=True`.
8. Delete the old policies.

Before the upgrade, each copy has the status `Conflicted`, because the old
controller sees two policies with the same target. After the upgrade, the copy
has no conflict, and the old policy gets `NotAllowed`.

## Acceptance criteria

The work is complete when an e2e test with agentgateway gives these results
for an XSS attack in the query string:

1. Case 1: the controller accepts the policy, and the WAF blocks the attack.
2. Case 2: the policy gets `NotAllowed`, and the policy of the platform team
   blocks the attack.
3. Case 3: the result is the same as in case 2.
4. Case 4: the controller accepts the policy, and the policy has no effect on
   the shop route.
5. Case 5: the WAF blocks the attack through `infra/shared-gw` and does not
   inspect it through `team-shop/local-gw`.
6. A policy in `team-evil` that targets `infra/shared-gw` gets `NotAllowed`.
7. A policy in `team-evil` that is older than the policy of the platform team
   does not make the policy of the platform team `Conflicted`.
8. A policy in `team-evil` with a false `Accepted=True` has no effect on the
   traffic of `infra/shared-gw`.

## Documentation changes

This RFC adds one page and changes these documents:

- A new threat model page, which states who can change the protection and
  which RBAC rules give this right
- RFC 0001, section Ownership, and its examples with the namespace
  `gateway-protector-system`
- `ARCHITECTURE.md`, section "Who owns what"
- `docs/wafpolicy-lifecycle.md` and `docs/policy-attachment.md`
- `docs/processor.md`, for the new field of the binding
- The manifests in `examples/`
- The known limitations page of the documentation website

# Drawbacks

[drawbacks]: #drawbacks

<!---
Why should we **not** do this?

  * obscure corner cases
  * will it impact performance?
  * what other parts of the product will be affected?
  * will the solution be hard to maintain in the future?
--->

- The upgrade is not compatible. A cluster that does not move its policies
  loses the WAF for their traffic. RFC 0001 has the goal that protection does
  not stop silently, and this upgrade can break it.
- The platform team cannot keep all its policies in one namespace if its
  `Gateway` objects are in more than one namespace.
- A namespace with a `Gateway` is a trust unit. If a `Gateway` and application
  workloads share a namespace, each user with write access to the policy kinds
  there controls the WAF of this `Gateway`.
- A route policy gets a new meaning. Today it applies to the route. With the
  rule, it applies to the route through the Gateways of one namespace.
- The format of the processor configuration changes again. Version 2 arrived
  with the fix of the policy selection.
- The rule does not replace RBAC. Write access to the policy kinds in the
  namespace of a platform `Gateway` is still a platform privilege, and the
  documentation must say so.

# Alternatives

[alternatives]: #alternatives

<!---
- What other designs/options have been considered?
- What is the impact of not doing this?
--->

## Documentation only

A threat model page states the real rule: no user outside the platform team
gets write access to the policy kinds in any namespace. No code changes.

This alternative is the smallest one, and it agrees with the model of RFC
0001. It depends on each administrator who gives a role in one namespace. A
wrong grant still has an effect on the full cluster, and the API still does
not follow GEP-713.

If the project rejects this RFC, this page is the minimum. The current pages
state the wrong rule.

## A list of trusted namespaces

A flag of the controller gives the namespaces that policies can come from. The
default is the namespace of the controller. The controller ignores the
policies of all other namespaces.

This alternative is a small change, and it keeps one central namespace for the
policies. It needs configuration. A team with its own `Gateway` cannot use it
safely, because a policy in a trusted namespace can target every route of the
cluster.

## Targets in the same namespace only

The API removes `targetRef.namespace`. A policy targets only objects of its
own namespace.

The platform team then writes each route policy in the namespace of the
application team. An application team with write access to the policy kinds in
its namespace can turn the WAF of its routes off. This breaks the goal of RFC
0001.

## A `ReferenceGrant` in the namespace of the target

GEP-713 names this handshake. The owner of the target creates a
`ReferenceGrant` that permits policies from one namespace.

For a route target, the application team gives the grant, and it can remove
the grant. The protection then depends on the consent of the team that must
not be able to remove it.

## Cluster-scoped kinds

`WAFPolicy` and `WAFRuleSet` become cluster-scoped, as `ClusterAdmissionPolicy`
in Kubewarden. A namespaced `Role` can then never grant them.

This alternative makes the API agree with the model of RFC 0001. It is a
larger API change, and it gives a team with its own `Gateway` no way to manage
its WAF.

## An admission rule

The chart installs a `ValidatingAdmissionPolicy` that rejects a policy outside
a list of namespaces. A `ValidatingAdmissionPolicy` is a Kubernetes object
that rejects API requests with an expression.

A user gets an error at the time of the request. A user with the right access
can delete the admission rule, and it does not examine the policies that
already exist. It can be an addition to another alternative, not a
replacement.

# Unresolved questions

[unresolved]: #unresolved-questions

<!---
- What are the unknowns?
- What can happen if Murphy's law holds true?
--->

## `ListenerSet` parents

A `ListenerSet` is a Gateway API object that adds listeners to a `Gateway`
from another object. A route can name a `ListenerSet` in `parentRefs`.

`isGatewayParentRef` ignores this kind today, so such a route gets no wiring
and no Gateway policy. With the rule, the controller also does not accept a
route policy for such a route. The controller must find the parent `Gateway`
of a `ListenerSet`.

This problem exists without this RFC. It needs a test that reproduces it
first.

## Other questions

- Does the project need a transition period? A flag can accept the old layout
  for one release. The flag then also turns the scope part of the rule off for
  the old policies.
- Are the upgrade steps correct? No test covers them. They follow from the
  conflict key of the two versions. A short time without protection can occur
  between the reconcile of the old policy and the reconcile of the copy.
- Does a route policy need a limit to one `Gateway` by name? This RFC limits
  it to the Gateways of one namespace.
- Can `targetRef.namespace` become optional for a `Gateway` target? With the
  rule, its value always equals the namespace of the policy.
- Is `NotAllowed` the right name for the reason? It is not one of the policy
  reasons of the Gateway API. The Gateway API uses this name for a
  `ListenerSet` that its `Gateway` does not permit.
- What can an application team do with write access to `AgentgatewayPolicy` in
  the namespace of its route? The controller creates the wiring object there.
  This RFC does not examine this access.
- Does agentgateway behave as the code expects? The description of the current
  selection comes from the code and from the unit tests. No test with
  agentgateway covers a route policy on a route with two Gateways.
