# API Reference

## Packages
- [gateway-protector.kubewarden.io/v1alpha1](#gateway-protectorkubewardeniov1alpha1)


## gateway-protector.kubewarden.io/v1alpha1

Package v1alpha1 contains API Schema definitions for the gateway-protector.kubewarden.io v1alpha1 API group.

### Resource Types
- [WAFPolicy](#wafpolicy)
- [WAFPolicyList](#wafpolicylist)
- [WAFRuleSet](#wafruleset)
- [WAFRuleSetList](#wafrulesetlist)



#### LocalRuleSetReference



LocalRuleSetReference references a WAFRuleSet living in the same namespace
as the WAFPolicy that references it (see WAFPolicySpec.CustomRulesRefs).



_Appears in:_
- [WAFPolicySpec](#wafpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | name is the name of the referenced WAFRuleSet, in the same namespace<br />as the WAFPolicy referencing it. |  | MaxLength: 253 <br />MinLength: 1 <br />Required: \{\} <br /> |


#### PolicyTargetReference



PolicyTargetReference identifies the Gateway API object (Gateway or
HTTPRoute) that a WAFPolicy/DLPPolicy attaches to.

It mirrors the upstream Gateway API policy-attachment reference form (see
sigs.k8s.io/gateway-api/apis/v1.NamespacedPolicyTargetReference), extended
with an optional SectionName so a policy can target a single listener
(when Kind is Gateway) or a single route rule (when Kind is HTTPRoute).
Upstream does not currently ship a combined Namespace+SectionName
reference type, so this struct is hand-written rather than reused
directly.



_Appears in:_
- [WAFPolicySpec](#wafpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `group` _[Group](https://gateway-api.sigs.k8s.io/reference/api-spec/main/spec/#group)_ | group is the group of the target resource. |  | Required: \{\} <br /> |
| `kind` _[Kind](https://gateway-api.sigs.k8s.io/reference/api-spec/main/spec/#kind)_ | kind is the kind of the target resource. Only "Gateway" and "HTTPRoute"<br />(group gateway.networking.k8s.io) are supported. |  | Enum: [Gateway HTTPRoute] <br />Required: \{\} <br /> |
| `name` _[ObjectName](https://gateway-api.sigs.k8s.io/reference/api-spec/main/spec/#objectname)_ | name is the name of the target resource. |  | Required: \{\} <br /> |
| `namespace` _[Namespace](https://gateway-api.sigs.k8s.io/reference/api-spec/main/spec/#namespace)_ | namespace is the namespace of the target resource. WAFPolicy/DLPPolicy<br />objects live in the platform-owned namespace (e.g.<br />gateway-protector-system) while the targeted Gateway/HTTPRoute usually<br />lives elsewhere, so this field is required to let the controller<br />resolve cross-namespace targets unambiguously. |  | Required: \{\} <br /> |
| `sectionName` _[SectionName](https://gateway-api.sigs.k8s.io/reference/api-spec/main/spec/#sectionname)_ | sectionName targets a specific listener (when kind is Gateway) or a<br />specific route rule (when kind is HTTPRoute). When unset, the policy<br />applies to the whole Gateway/HTTPRoute. |  | Optional: \{\} <br /> |


#### WAFAnomalyThreshold



WAFAnomalyThreshold sets the CRS anomaly-scoring thresholds above which a
request (or response) is considered an attack.



_Appears in:_
- [WAFPolicySpec](#wafpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `inbound` _integer_ | inbound is the anomaly score threshold applied to the request phase. |  | Optional: \{\} <br /> |
| `outbound` _integer_ | outbound is the anomaly score threshold applied to the response phase. |  | Optional: \{\} <br /> |


#### WAFBodyInspectionSpec



WAFBodyInspectionSpec toggles and bounds request/response body inspection.



_Appears in:_
- [WAFPolicySpec](#wafpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `enabled` _boolean_ | enabled toggles body inspection for this phase. |  | Required: \{\} <br /> |
| `maxSize` _[Quantity](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#quantity-resource-api)_ | maxSize caps the number of bytes buffered for inspection (e.g. "1Mi").<br />Bodies larger than this are handled per the engine's configured<br />behavior for oversized bodies. Only meaningful when enabled is true. |  | Optional: \{\} <br /> |


#### WAFCustomRule



WAFCustomRule is a single raw Coraza/ModSecurity SecRule directive block,
identified by its numeric rule id.



_Appears in:_
- [WAFRuleSetSpec](#wafrulesetspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `id` _integer_ | id is the numeric SecRule id. It must be in the site-local range<br />1-99999, which is the SecLang convention reserved for a site's own<br />custom rules (as opposed to 100000-899999, historically assigned to<br />various commercial/community rule vendors; 900000-999999, the OWASP<br />Core Rule Set itself; 9500000-9599999, registered CRS plugins; and<br />10000000-10000099, reserved by gateway-protector for its own<br />generated directives). It is<br />the author's responsibility to keep ids unique within a WAFRuleSet<br />and across every other WAFRuleSet referenced by the same WAFPolicy.<br />This validates the declared id field only, not any id that might<br />also appear inside the raw directive text below - a mismatch between<br />the two is still only caught at dry-compile time. |  | Required: \{\} <br /> |
| `directive` _string_ | directive is one or more raw SecRule lines composing this rule. |  | MinLength: 1 <br />Required: \{\} <br /> |


#### WAFEngineMode

_Underlying type:_ _string_

WAFEngineMode controls whether the WAF engine blocks matching requests,
only logs them, or is disabled entirely.

_Validation:_
- Enum: [Blocking Detection Off]

_Appears in:_
- [WAFEngineSpec](#wafenginespec)

| Field | Description |
| --- | --- |
| `Blocking` | WAFEngineModeBlocking rejects requests that match a rule.<br /> |
| `Detection` | WAFEngineModeDetection evaluates rules and reports matches but never<br />blocks traffic.<br /> |
| `Off` | WAFEngineModeOff disables the WAF engine for the attachment point,<br />e.g. to let a route opt out of a Gateway-level default.<br /> |


#### WAFEngineSpec



WAFEngineSpec configures the WAF engine's operating mode.

There is deliberately no failure-posture (fail-open/fail-closed) knob
here: the data plane this project integrates with (agentgateway's
ext_proc wiring) hardcodes fail-closed when the processor is
unreachable and exposes no way to configure it, so this API doesn't
promise a behavior it cannot deliver. If upstream ever exposes it, a
failureMode field can be reintroduced.



_Appears in:_
- [WAFPolicySpec](#wafpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `mode` _[WAFEngineMode](#wafenginemode)_ | mode selects whether the engine blocks, only logs, or is disabled. |  | Enum: [Blocking Detection Off] <br />Required: \{\} <br /> |


#### WAFExclusion



WAFExclusion excludes specific CRS rules (by numeric id) or rule tags from
evaluation, e.g. to silence a known false positive.



_Appears in:_
- [WAFPolicySpec](#wafpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `byId` _integer array_ | byId excludes specific CRS rule ids. |  | Optional: \{\} <br /> |
| `byTag` _string array_ | byTag excludes every CRS rule carrying one of the given tags (e.g.<br />"attack-sqli"). |  | Optional: \{\} <br /> |


#### WAFPolicy



WAFPolicy is the Schema for the wafpolicies API. It attaches a Coraza +
OWASP Core Rule Set WAF engine to a Gateway (as the default for all its
routes) or to a single HTTPRoute (as an override of the Gateway default).



_Appears in:_
- [WAFPolicyList](#wafpolicylist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `gateway-protector.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `WAFPolicy` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  | Optional: \{\} <br /> |
| `spec` _[WAFPolicySpec](#wafpolicyspec)_ | spec defines the desired state of WAFPolicy |  | Required: \{\} <br /> |
| `status` _[WAFPolicyStatus](#wafpolicystatus)_ | status defines the observed state of WAFPolicy |  | Optional: \{\} <br /> |


#### WAFPolicyList



WAFPolicyList contains a list of WAFPolicy





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `gateway-protector.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `WAFPolicyList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[WAFPolicy](#wafpolicy) array_ |  |  |  |


#### WAFPolicySpec



WAFPolicySpec defines the desired state of WAFPolicy.

A WAFPolicy attaches a Coraza + OWASP Core Rule Set WAF engine to a
Gateway (as the default for all its routes) or to a single HTTPRoute (as
an override of the Gateway default for that route only) - resolved
"most-specific-wins" between exactly those two attachment levels, with no
merging: a Route-level WAFPolicy fully replaces the Gateway-level one for
that route, it doesn't add to it. See the field docs below for the
per-field reference, docs/wafpolicy-lifecycle.md for the validation and
conflict-resolution rules, and docs/processor.md for how the compiled
result is ultimately consumed by the data plane.



_Appears in:_
- [WAFPolicy](#wafpolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `targetRef` _[PolicyTargetReference](#policytargetreference)_ | targetRef identifies exactly one Gateway (applies to all its routes,<br />the common default case) or one HTTPRoute (overrides the Gateway<br />default for that route only). |  | Required: \{\} <br /> |
| `engine` _[WAFEngineSpec](#wafenginespec)_ | engine configures the WAF engine's mode and failure posture. |  | Required: \{\} <br /> |
| `paranoiaLevel` _integer_ | paranoiaLevel selects the CRS paranoia level (1-4); higher levels<br />enable more (and more false-positive-prone) rules. Absent means the<br />Core Rule Set's own default (paranoia level 1). |  | Maximum: 4 <br />Minimum: 1 <br />Optional: \{\} <br /> |
| `anomalyThreshold` _[WAFAnomalyThreshold](#wafanomalythreshold)_ | anomalyThreshold sets the inbound/outbound anomaly score thresholds.<br />Absent means the Core Rule Set's own defaults. |  | Optional: \{\} <br /> |
| `requestBody` _[WAFBodyInspectionSpec](#wafbodyinspectionspec)_ | requestBody configures request body inspection. |  | Optional: \{\} <br /> |
| `responseBody` _[WAFBodyInspectionSpec](#wafbodyinspectionspec)_ | responseBody configures response body inspection. |  | Optional: \{\} <br /> |
| `exclusions` _[WAFExclusion](#wafexclusion) array_ | exclusions silence specific CRS rules (by id or tag), e.g. to resolve a<br />known false positive without lowering the paranoia level. |  | Optional: \{\} <br /> |
| `customRulesRefs` _[LocalRuleSetReference](#localrulesetreference) array_ | customRulesRefs references WAFRuleSet objects, in the same namespace as<br />this WAFPolicy, whose custom SecRule directives are compiled into the<br />engine alongside the Core Rule Set. Referenced WAFRuleSets are<br />rendered in namespace/name order, not the order listed here (this is<br />a listType=map, so list order isn't meaningful and isn't preserved<br />across a server-side-apply merge); SecLang rules that depend on a<br />specific relative order must be placed together within a single<br />WAFRuleSet, whose own spec.rules order is preserved. |  | Optional: \{\} <br /> |


#### WAFPolicyStatus



WAFPolicyStatus defines the observed state of WAFPolicy.



_Appears in:_
- [WAFPolicy](#wafpolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#condition-v1-meta) array_ | conditions represent the current state of the WAFPolicy resource, using<br />the Gateway API status-conditions convention: Accepted (valid, target<br />resolves, not conflicted - see ConditionReasonConflicted) and<br />Programmed (gateway wired, engine live in the data plane). |  | Optional: \{\} <br /> |


#### WAFRuleSet



WAFRuleSet is the Schema for the wafrulesets API. It is a reusable bundle
of custom SecRule directives referenced from one or more WAFPolicy objects
in the same namespace via customRulesRefs.



_Appears in:_
- [WAFRuleSetList](#wafrulesetlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `gateway-protector.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `WAFRuleSet` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  | Optional: \{\} <br /> |
| `spec` _[WAFRuleSetSpec](#wafrulesetspec)_ | spec defines the desired state of WAFRuleSet |  | Required: \{\} <br /> |
| `status` _[WAFRuleSetStatus](#wafrulesetstatus)_ | status defines the observed state of WAFRuleSet |  | Optional: \{\} <br /> |


#### WAFRuleSetList



WAFRuleSetList contains a list of WAFRuleSet





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `gateway-protector.kubewarden.io/v1alpha1` | | |
| `kind` _string_ | `WAFRuleSetList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[WAFRuleSet](#wafruleset) array_ |  |  |  |


#### WAFRuleSetSpec



WAFRuleSetSpec defines the desired state of WAFRuleSet.



_Appears in:_
- [WAFRuleSet](#wafruleset)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `rules` _[WAFCustomRule](#wafcustomrule) array_ | rules are raw Coraza/ModSecurity SecRule directive blocks, referenced<br />from WAFPolicy.customRulesRefs to avoid pasting raw directives inline<br />in every WAFPolicy. |  | MinItems: 1 <br />Required: \{\} <br /> |


#### WAFRuleSetStatus



WAFRuleSetStatus defines the observed state of WAFRuleSet.



_Appears in:_
- [WAFRuleSet](#wafruleset)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#condition-v1-meta) array_ | conditions represent the current state of the WAFRuleSet resource. |  | Optional: \{\} <br /> |


