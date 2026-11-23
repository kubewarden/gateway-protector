# Gateway Protector — Processor

The processor is the Envoy `ext_proc` gRPC service that runs the WAF engine (and, in the
future, DLP) for Gateway Protector. agentgateway calls it once per HTTP request/response over a
single bidirectional gRPC stream that spans all four processing phases (request headers, request
body, response headers, response body), so a single process can run WAF (request-phase allow/block)
and, eventually, DLP (response-phase redact/mask/block) with one network hop instead of two.

The processor has no Kubernetes API dependency: it is configured entirely over the config stream
(see [Config stream](#config-stream) below) and knows nothing about `WAFPolicy`/`WAFRuleSet`
objects. The controller renders that config from those objects and pushes it to every processor
replica over a gRPC stream it serves (see `internal/controller/processorconfig` and
`internal/controller/processor_config_reconciler.go`).

## Command-line flags

| Flag                        | Default | Description                                                                                             |
| ---------------------------- | --------- | ----------------------------------------------------------------------------------------------------------- |
| `--grpc-bind-address`       | `:9000` | Address the ext_proc gRPC service binds to.                                                             |
| `--health-bind-address`     | `:9001` | Address the plaintext gRPC health service binds to - see below.                                         |
| `--config-server-address`   | (none, required) | The controller's config stream gRPC address (host:port) - see [Config stream](#config-stream). |
| `--subscriber-id`           | the hostname | Identifies this replica to the controller's config stream logs/metrics (e.g. this pod's name).     |
| `--log-level`               | `info`  | One of `debug`, `info`, `warn`, `error`.                                                                 |
| `--grpc-reflection`         | `false` | Enable gRPC server reflection (local debugging only).                                                   |
| `--config-stream-cert-dir`  | (none)  | Directory with this replica's client certificate/key and the CA bundle for mTLS on the config stream - see [Config stream](#config-stream). Unset dials in plaintext. |
| `--ext-proc-cert-dir`       | (none)  | Directory with this replica's ext_proc server certificate/key and the CA bundle for mTLS with agentgateway - see [ext_proc mTLS](#ext_proc-mtls). Unset serves in plaintext. |
| `--waf-matched-rules-log`   | (none)  | Path to additionally append every matched WAF rule to, one per line, in ModSecurity's own log format (`MatchedRule.ErrorLog()`) rather than this processor's structured log - see [Matched-rule logging](#matched-rule-logging). Unset writes no such file; matched rules are still logged in the structured log either way. |

A gRPC health service (`grpc.health.v1.Health`) is always registered on its own plaintext listener
(`--health-bind-address`), separate from the ext_proc service itself: Kubernetes' native gRPC probes
can't present a client certificate, so they can't reach a health service registered on the ext_proc
listener once `--ext-proc-cert-dir` requires one there - see
[Config stream](#config-stream) for how readiness is tied to having received a first config.

## Configuration

The config (see `internal/processor/config/types.go` for the authoritative Go types, and
[Config stream](#config-stream) for how it's delivered) is canonical JSON with three top-level keys.
The example below uses YAML purely for readability in this document; the wire format is JSON, not
YAML:

```yaml
# schemaVersion is the version of this format. The processor rejects a config of any other
# version (see "Config stream" below for the version handshake). Version 1, which had no
# schemaVersion key, selected engines with a table of hosts and path prefixes.
schemaVersion: 2

# directives maps an opaque "engine key" to a block of raw Coraza/SecLang directives. Each entry is
# compiled into its own coraza.WAF engine, keyed by that string. Identical rendered directive blocks
# are expected to share the same engine key (e.g. a hash of the rendered directives) so that engines
# get deduplicated in memory instead of compiling one per policy that happens to use the exact
# same rules.
directives:
  <engineKey>: <secLangDirectives>

# bindings attaches engines to Gateway API attachment points - one per Accepted WAFPolicy, at the
# object (and optional section) its spec.targetRef names. At most one binding per attachment point.
bindings:
  - kind: <Gateway|HTTPRoute>
    namespace: <namespace>
    name: <name>
    sectionName: <listener or rule name> # optional; omitted means the whole Gateway/HTTPRoute
    waf:
      engineKey: <engineKey> # must exist in `directives`; `waf` is omitted for a policy whose
                             # directives failed to compile - see "Engine selection" below
```

The config has no hosts or paths. agentgateway selects the route of each request with the full
Gateway API matching rules (hostnames, path matches on segment boundaries, header, query parameter,
and method matches, the Gateway and the listener), and reports the result to the processor. The
processor only maps that result to an engine.

### Request identity

Every `AgentgatewayPolicy` the controller generates sets `traffic.extProc.metadataContext` (see
`wiringMetadataContext` in `internal/controller/processor_config_wiring.go`). agentgateway evaluates
these CEL expressions for each request, after it has selected the listener and the route, and sends
the results in `ProcessingRequest.metadata_context.filter_metadata`, under the namespace
`gateway-protector.kubewarden.io`:

| Key | CEL expression | Value |
| --- | --- | --- |
| `gatewayNamespace` | `proxy.gateway.namespace` | Namespace of the Gateway that accepted the request |
| `gatewayName` | `proxy.gateway.name` | Name of that Gateway |
| `listenerName` | `proxy.listener.name` | Name of the listener that accepted the request |
| `routeKind` | `default(proxy.route.kind, "")` | Kind of the selected route, e.g. `HTTPRoute` |
| `routeNamespace` | `proxy.route.namespace` | Namespace of the selected route |
| `routeName` | `proxy.route.name` | Name of the selected route |
| `routeRule` | `default(proxy.route.rule, "")` | Name of the selected rule, or `""` for a rule without a name |

The expressions read only `proxy.*` variables, which agentgateway fills from its own routing
decision - a client cannot set them with a header. The processor reads them in the request headers
phase (`identityFromMetadata` in `internal/processor/identity.go`).

### Engine selection

For each request, the processor resolves the WAF engine from that identity as follows (see
`Snapshot.Resolve` in `internal/processor/config/snapshot.go`). This is the *request-time* half of
policy attachment; see `docs/policy-attachment.md` for the user-facing rules. It tries these
attachment points, most specific first, and stops at the first one that has a binding:

1. the `HTTPRoute` rule (`kind: HTTPRoute`, `sectionName: <routeRule>`) - only when the rule has a
   name;
2. the whole `HTTPRoute` (`kind: HTTPRoute`, no `sectionName`);
3. the Gateway listener (`kind: Gateway`, `sectionName: <listenerName>`);
4. the whole Gateway (`kind: Gateway`, no `sectionName`).

Levels 1 and 2 apply only when `routeKind` is `HTTPRoute`.

- **A binding with an engine** — the processor inspects the request with that engine.
- **A binding without `waf`** — the policy at that attachment point failed to compile
  (`Programmed=False`, reason `CompileFailed`). No engine runs and the request continues
  uninspected. The processor does **not** fall back to a less specific binding: a broken policy
  never silently hands its traffic to another policy.
- **No binding at all** — no `WAFPolicy` covers the request, and it continues uninspected. This
  happens, for example, for a rule without a policy on a route where only other rules have one:
  the generated wiring targets the whole route.

### Requests without an identity fail closed

A request whose metadata lacks the `gateway-protector.kubewarden.io` namespace, or one of its seven
keys, or holds a key that is not a string, or has an empty Gateway or route namespace or name, is
answered with a plain `500` `ImmediateResponse`. The processor cannot tell which policy applies to
such a request, so it refuses it instead of letting it through uninspected. This happens when a
user-written `AgentgatewayPolicy` sends traffic to the processor without the metadata, or when
agentgateway fails to evaluate one of the expressions.

### Body inspection

Whether an engine buffers and inspects request/response bodies at all - and the size limits for
doing so - is controlled entirely by that engine's own SecLang directives
(`SecRequestBodyAccess`/`SecResponseBodyAccess` and their `*Limit`/`*InMemoryLimit` counterparts),
**not** by any processor-wide flag. This matches Coraza/ModSecurity's own default: body access is
off unless a directive turns it on. `@coraza.conf-recommended` (included by any CRS-based engine)
already sets sane defaults for both.

This is deliberate, not an oversight: Coraza applies SecLang directives *before* any programmatic
`WAFConfig` settings, so if the processor forced `WithRequestBodyAccess()` on for every engine, it
would silently override an engine that explicitly opts out (`SecRequestBodyAccess Off`), and would
waste memory buffering bodies for engines that never asked for it (e.g. the chart's default inert
`SecRuleEngine Off` engine). It is also where `WAFPolicy.spec.requestBody`/`spec.responseBody` (see
`api/v1alpha1.WAFBodyInspectionSpec`) land once rendered as directives:
`enabled`/`maxSize` become `SecRequestBodyAccess`/`SecRequestBodyLimit` (etc.) in the
rendered engine (see `internal/controller/processorconfig.RenderDirectives`), rather than being
threaded through as separate processor-level settings.

### Example

Again shown as YAML for readability (comments); the actual wire format is JSON (see
[Config stream](#config-stream)):

```yaml
schemaVersion: 2

directives:
  shop-strict: |
    Include @coraza.conf-recommended
    Include @crs-setup.conf.example
    Include @owasp_crs/*.conf
  off: |
    SecRuleEngine Off

bindings:
  # The default for every request that the shared-gw Gateway accepts.
  - kind: Gateway
    namespace: infra
    name: shared-gw
    waf:
      engineKey: shop-strict
  # The "health" rule of the shop HTTPRoute is exempted from the WAF. Requests that agentgateway
  # sends to the other rules of the route still resolve to the Gateway binding above.
  - kind: HTTPRoute
    namespace: team-shop
    name: shop
    sectionName: health
    waf:
      engineKey: off
  # The policy of the blog HTTPRoute failed to compile: its requests continue uninspected, and do
  # not fall back to the Gateway binding.
  - kind: HTTPRoute
    namespace: team-blog
    name: blog
```

The Core Rule Set shown above (`@coraza.conf-recommended`, `@crs-setup.conf.example`,
`@owasp_crs/*.conf`) comes from the embedded `github.com/corazawaf/coraza-coreruleset` module (see
`internal/processor/config/compile.go`); no vendored rule files ship in this repository. Exactly one
CRS version is baked into a given processor binary; its version is logged at startup (`crs-version`
attribute on the "Processor ready" log line).

## Request-time flow

1. **Request headers phase** — the processor extracts `:authority`, `:method`, `:path` (and, for
   logging, `:scheme`), reads the [request identity](#request-identity) from the ext_proc metadata,
   resolves the WAF engine from it (see [Engine selection](#engine-selection)), and if one is
   attached, starts a Coraza transaction (`ProcessURI` + per-header `AddRequestHeader` +
   `ProcessRequestHeaders`). An interruption here blocks immediately.
2. **Request body phase** — body chunks are fed into the transaction (`WriteRequestBody`) and, when
   Coraza is going to inspect the body (`SecRequestBodyAccess On`), **withheld from the upstream**
   until the phase-2 verdict (`ProcessRequestBody` at end-of-stream): a blocked request's body never
   reaches the upstream at all, so the upstream can't act on the attack (e.g. execute the SQLi) even
   though the client would have been answered 403 anyway. Clean bodies are then released in one go.
   Memory for the withheld chunks is bounded by Coraza's own `SecRequestBodyLimit`: with
   `ProcessPartial`, Coraza runs the phase-2 verdict on the partial body as soon as the limit is
   reached, after which everything is released and the remainder streams through unbuffered; with
   `Reject`, hitting the limit blocks outright.
3. **Response headers phase** — feeds every response header into the transaction (RESPONSE_HEADERS
   rules, e.g. CRS 95x leakage rules, need the values; the response body phase needs the
   `Content-Type` to open Coraza's `SecResponseBodyMimeType` gate) and runs `ProcessResponseHeaders`.
   When the response body *will* be inspected (`SecResponseBodyAccess On` and an allowlisted
   Content-Type), the CONTINUE answer for this phase is **withheld** until the phase-4 verdict:
   agentgateway commits the response head downstream the moment this answer is sent, after which a
   block can no longer change the status. Responses Coraza won't inspect (e.g. `text/event-stream`,
   images) are answered immediately and stream through unbuffered. **DLP response
   inspection/redaction is not implemented**: WAF is a request-phase concern (allow/block); DLP is
   meant to be a response-phase concern (redact/mask/block sensitive data such as PII/PAN/secrets
   before it leaves the cluster), and that engine doesn't exist yet.
4. **Response body phase** — same idea as request body, but response-phase rules
   (`ProcessResponseBody`), with the same withhold-until-verdict/`ProcessPartial` semantics as
   phase 2. Also **not** a DLP mutation point yet: this phase can currently only block, it never
   redacts or otherwise mutates the response body.

Two agentgateway-specific protocol details shape the implementation (both were caught by Coraza's
own connector e2e suite, `test/coraza-e2e`, run via `make test-coraza-e2e`):

- In `FULL_DUPLEX_STREAMED` mode (what the controller wires whenever body inspection is needed),
  agentgateway rebuilds the proxied body **exclusively from the chunks the processor echoes back**
  in `BodyMutation.streamed_response` — a plain CONTINUE with no body mutation silently *truncates*
  the body. Every body chunk (including on streams with no WAF engine attached) is therefore echoed
  back explicitly.
- agentgateway force-enables trailer delivery in full-duplex mode and signals end-of-body in one of
  three ways: a data chunk with `end_of_stream`, an empty body message with `end_of_stream`, or an
  `HttpTrailers` message. All three run the pending body phase; trailers are acknowledged with a
  matching `TrailersResponse` (a mismatched message type would be silently ignored by agentgateway).

### Blocking

When a rule interrupts the transaction — at any of the four phases — the processor answers
agentgateway with an ext_proc `ImmediateResponse` message (the message type comes from Envoy's
ext_proc protocol definitions, which agentgateway implements). agentgateway then stops proxying
the exchange: a request-phase block never reaches the upstream, and a response-phase block
discards the upstream's response instead of forwarding it. What the client receives is built
from the interruption:

- **Status code** — the rule's `deny,status:NNN` value, or `403` when the rule doesn't specify
  one.
- **An empty body** — the matched rule ID/action is logged server-side (the "WAF blocked
  traffic" log line) but deliberately never disclosed to the client, since that would help an
  attacker probe which rules fired.
- **An `x-waf-violation: 1` header** — lets operators distinguish a WAF block from an
  upstream-originated error with the same status code.

Response-phase blocking is only possible because of the withholding described above: once the
response-headers answer has been sent, agentgateway has already committed the response head to
the client, and an `ImmediateResponse` arriving later can no longer replace the status.

### Engine errors fail closed

The calls above can also fail outright (an `error` return, distinct from an interruption) - for
example, Coraza can no longer buffer body bytes because its storage is exhausted. This is not a
rule verdict, but the processor treats it the same way as a block: it logs the error, closes the
transaction, and answers with a plain `500` `ImmediateResponse` (empty body, no `x-waf-violation`
header - that marker means a rule matched, and none did here).

We fail closed here on purpose: letting the request/response through uninspected when the engine
itself is malfunctioning would hand an attacker able to trigger that failure a free pass around
the WAF. Refusing the traffic instead keeps that guarantee intact at the cost of availability for
the affected request.

## Matched-rule logging

Every matched rule is always logged in the processor's normal structured log (the `WAF rule
triggered` line, tagged with `engine_key`/`rule_id`/`severity`/etc. - see `newErrorCallback` in
`internal/processor/config/compile.go`).

`--waf-matched-rules-log=<path>` additionally appends the same match, one per line, in
ModSecurity's own log format instead (Coraza's `MatchedRule.ErrorLog()`, e.g. `[client "10.0.0.1"]
... [id "941100"] ...`). This is a second, differently-shaped sink alongside the structured log,
not a replacement for it - the flag is opt-in and off by default. It exists for tooling that
expects that specific format rather than structured JSON/text:

- **go-ftw**, the CRS regression test runner (see [Testing against the CRS regression
  suite](#testing-against-the-crs-regression-suite) below): it correlates each test's request with
  the rule IDs this file records to verify the exact rule fired, not just that *some* rule blocked
  the request.
- Existing ModSecurity-log-aware operational tooling (fail2ban-style blockers, SIEM parsers) that
  already knows how to parse this format.

The file is created if missing and appended to if it already exists; a single processor instance's
engines (and their concurrent transactions) all share it safely.

## Testing against the CRS regression suite

`make test-ftw` runs the OWASP Core Rule Set's own regression suite - [go-ftw](https://github.com/coreruleset/go-ftw),
the CRS project's official test runner - against this processor, fronted by a real agentgateway
instance (see `test/ftw`). This is the same suite every other CRS connector (Envoy, nginx, Apache
modules, etc.) uses to substantiate a "CRS compliant" claim, run here through the actual stack this
project ships rather than directly against Coraza.

- **Topology**: go-ftw (a CLI, run on the host) sends each test's request to a real agentgateway
  container, which calls this processor over ext_proc exactly as in production, fronting a
  purpose-built test backend ([albedo](https://github.com/coreruleset/albedo)).
- **Corpus version pinning**: the test corpus (the actual attack/benign request definitions) is
  downloaded from the CRS project's GitHub releases at the exact version this module's
  `github.com/corazawaf/coraza-coreruleset` dependency vendors (see `go.mod`) - the rules under
  test and the tests themselves can never silently drift apart.
- **Detection-only, log-correlated**: the directive block compiled for this suite forces
  `SecRuleEngine DetectionOnly` (see `test/ftw/testdata/crs-ftw-setup.conf`), so go-ftw verifies
  *which* rule fired by correlating a per-request marker header against the
  `--waf-matched-rules-log` file (see [Matched-rule logging](#matched-rule-logging) above) rather
  than asserting on the HTTP response for most tests.
- **Platform overrides**: `test/ftw/testdata/overrides.yml` lists the corpus tests that can't pass
  unmodified here, each with its reason and the evidence behind it - typically agentgateway
  rejecting or normalizing a request before ext_proc runs, or Coraza behavior that holds whichever
  proxy fronts it.

### Known limitation: agentgateway can drop or corrupt Cookie header values

agentgateway re-parses and re-serializes every request's `Cookie` header to strip its own OIDC
session cookies (any name prefixed `agw_oidc_`) - regardless of whether OIDC is configured anywhere
in the deployment (`crates/agentgateway/src/proxy/httpproxy.rs:150`, inside
`apply_request_policies`). Malformed values don't survive that round-trip: a literal `;` inside a
value truncates it (misread as a cookie-pair separator), and a value with no `=` or containing any
non-ASCII byte drops the whole header entirely - all three shapes are invalid per RFC 6265
§4.2.1's `cookie-pair`/`cookie-octet` grammar regardless.

This is not a WAF blind spot with the attack still reaching the application: the same `Request`
object `apply_request_policies` mutates is what's later forwarded to the backend, so the
application receives byte-identical values to what the WAF inspected (confirmed against a real
backend). The CRS regression tests this affects are asserting on payload bytes that no longer
exist anywhere in the request by the time it's processed - see
`test/ftw/testdata/overrides.yml`'s cookie-related overrides for the affected rules/tests and the
file:line evidence.

## Config stream

The processor receives its data-plane config (engines + bindings) from the controller over a
long-lived gRPC stream (`proto/configstream/v1/config_stream.proto`,
`internal/processor/config.Subscriber`), not from a file: the processor dials the controller's
`ConfigServer` (`internal/controller.ConfigServer`) once at startup and keeps that single stream open
for its whole lifetime, reconnecting with backoff on any error.

- The controller pushes the current config immediately on subscribe, and again every time
  `WAFPolicy`/`WAFRuleSet` changes cause `ProcessorConfigReconciler` to publish a new one (see
  `internal/controller.GRPCPublisher`). The push payload (`ConfigSnapshot.config_json`) is the
  canonical JSON encoding of `internal/processor/config.Config` - not proto messages, since both
  sides already share the same Go schema and parse/validate/compile pipeline; encoding it as opaque
  bytes avoids a redundant proto-message duplicate of that schema. Each push also carries a sha256
  hex digest of those bytes as its `version`, letting both sides skip no-op pushes/reloads - stable
  across reconciles because `processorconfig.Build` documents its `Bindings` ordering as canonical
  (sorted, not the cache's arbitrary iteration order) and `encoding/json.Marshal` is itself
  deterministic (sorted map keys, declaration-order struct fields). The config depends only on
  `WAFPolicy` and `WAFRuleSet` objects: an `HTTPRoute` change never changes it.
- **Schema version handshake**: the processor announces the config schema version it accepts
  (`Subscribe.schema_version`, `internal/processor/config.SchemaVersion`). The controller ends the
  stream of a processor with another version with `FAILED_PRECONDITION` and sends it no config.
  During a rolling upgrade, a processor of the previous version therefore keeps serving the config
  it already has, instead of reading the new format as an empty table and letting every request
  through; a processor of the new version rejects the config of a previous controller (it has no
  `schemaVersion`) and stays not ready until a new controller serves it.
- After receiving a config, the processor parses, validates, and compiles it, then sends a
  `ConfigAck` back reporting whether it applied successfully - the controller knows whether a given
  replica is actually running the config it was sent (see `ConfigServer`'s ack logging).
- **Fail-safe by default**: if a pushed config fails to parse, fails semantic validation, or fails to
  compile into Coraza engines, the processor logs the error, reports it back in a rejected
  `ConfigAck`, and keeps serving whatever `Snapshot` it had before (or none, if this was its first
  config). A bad push can never silently disable protection or crash the data plane.
- **Readiness**: the processor's gRPC health service reports `NOT_SERVING` until it has applied its
  first config, so Kubernetes doesn't route traffic to a pod with nothing loaded yet; it flips to
  `SERVING` on the first successful `ConfigAck` and never flips back for later config errors (those
  keep serving the last-known-good config instead, per the fail-safe behavior above).
- **Reload cleanup**: `Server.SetSnapshot` atomically swaps in the new `Snapshot` and closes the one
  it replaced (`config.Snapshot.Close`, via `coraza/v3`'s `experimental.WAFCloser`), releasing the
  entries the old `coraza.WAF` engines own in Coraza's process-wide memoize cache for compiled
  regex/aho-corasick patterns. This is safe even while requests are still in flight against the old
  `Snapshot`: closing a `coraza.WAF` only evicts shared cache entries, never anything an already-
  created transaction holds a direct reference to.
- With leader election (the chart's default), only the active controller replica's `ConfigServer`
  ever has a config to push - see `internal/controller.ConfigStreamRunnable`. A processor connected
  to a standby replica simply finds the config stream unavailable and reconnects with backoff until
  a leader is serving again; multi-replica controller HA beyond this hasn't been exercised.
- **mTLS, no cert-manager dependency**: the chart's default install secures the config stream with
  mutual TLS. A self-signed CA and two leaf certificates (controller server, processor client) are
  bootstrapped by the chart at install/upgrade time (`charts/gateway-protector/templates/certs.yaml`,
  Sprig `genCAWithKey`/`genSignedCertWithKey`, reusing existing Secrets via `lookup` across
  upgrades) and rotated afterwards by `internal/controller.CertReconciler`, a `manager.Runnable`
  that runs on the leader every 12h and regenerates whatever is within 60 days of expiring - the
  same no-cert-manager approach kubewarden's admission controller uses. See
  `internal/certs` for the certificate generation/verification code and
  `internal/certs.ReloadingClientCredentials` / `internal/certs.ServerTLSConfig` for how each side
  reloads its certificate/CA bundle from its mounted Secret on every connection, so a rotation takes
  effect without restarting either process. Passing `--config-stream-cert-dir` to the processor (and
  the equivalent flag to the controller) is what turns this on; leaving it unset dials/serves in
  plaintext, e.g. for local dev.

## ext_proc mTLS

agentgateway's connection to the processor's ext_proc service is secured with mutual TLS the same
way, and by the same `CertReconciler`: two more leaf certificates - a processor ext_proc server
cert and an agentgateway client cert - signed by the same CA as the config-stream certificates
above, bootstrapped and rotated identically.

- Passing `--ext-proc-cert-dir` to the processor requires and verifies agentgateway's client
  certificate on `--grpc-bind-address` (`certs.ServerTLSConfig`, `tls.RequireAndVerifyClientCert`);
  leaving it unset serves ext_proc in plaintext.
- agentgateway itself has no flag for this: TLS on a backend connection (including the ext_proc
  dial) is attached via an `AgentgatewayPolicy`'s `backend.tls`, targeting the processor's `Service`
  by name - see `charts/gateway-protector/templates/processor/backend-tls-policy.yaml`. Unlike the
  `AgentgatewayPolicy` objects the controller generates to wire WAF-protected routes to the
  processor (see `docs/wafpolicy-lifecycle.md`'s "Gateway wiring"), this one is static and
  chart-owned: it doesn't depend on any `WAFPolicy`/`HTTPRoute`/`Gateway` state, so there's nothing
  to reconcile. It deliberately omits the `gateway-protector.kubewarden.io/managed=true` label the
  controller's own generated policies carry, so the controller's cache/watch and wiring garbage
  collection (see `internal/controller/processor_config_wiring.go`) never see it.
- agentgateway reads its client certificate from a `kubernetes.io/tls` Secret
  (`mtlsCertificateRef`) but its CA bundle from a **ConfigMap** (`caCertificateRefs`) - it has no
  Secret-based CA bundle option. `CertReconciler` therefore also maintains a
  `gateway-protector-ca-bundle` ConfigMap alongside every leaf Secret's own `ca.crt` key.
- This composes with the controller's own generated `traffic.extProc.backendRef` policies:
  agentgateway resolves backend TLS by the ext_proc `backendRef`'s target Service, independent of
  which Gateway/HTTPRoute policy carries that `backendRef`.

## Deployment

`charts/gateway-protector/templates/processor/`:

- `deployment.yaml` — passes `--config-server-address` pointing at the controller's config stream
  Service (see below); liveness/readiness use Kubernetes' native gRPC probe support against the
  health service on `--health-bind-address`. Mounts the `gateway-protector-processor-client-cert`
  Secret at `/config-stream-certs` (`--config-stream-cert-dir=/config-stream-certs`) and the
  `gateway-protector-processor-server-cert` Secret at `/ext-proc-certs`
  (`--ext-proc-cert-dir=/ext-proc-certs`) - see [Config stream](#config-stream) and
  [ext_proc mTLS](#ext_proc-mtls).
- `service.yaml` — a `ClusterIP` Service on port `9000`. This is the `backendRef` every generated
  `AgentgatewayPolicy` points `ext_proc` traffic at (see `internal/controller/processor_config_wiring.go`).

The controller's config stream is served from its own `ConfigStreamRunnable`
(`internal/controller/configstream_runnable.go`), exposed by `charts/gateway-protector/templates/controller/service.yaml`
as the fixed-name `gateway-protector-controller-config-stream` Service on port `9002` - fixed for the
same reason as the processor's own Service name: the processor Deployment's `--config-server-address`
needs a name to dial that doesn't depend on the Helm release name.

## Current limitations / roadmap

- **No DLP** - response-phase inspection is Coraza-only (CRS phase 3/4 blocking); there is no data
  redaction, masking, or response-body mutation yet.
- **No WebSocket-specific handling** - a long-lived upgraded connection is just a single ext_proc
  stream/Coraza transaction like any other request; there's no dedicated state machine for it.
- **Config stream acks aren't surfaced to `WAFPolicy` status** - `ConfigServer` logs every
  `ConfigAck` (and a future metric), but a replica repeatedly rejecting a config isn't yet reflected
  back onto the `WAFPolicy` objects that contributed to it.
