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
| `--config-server-address`   | (none, required) | The controller's config stream gRPC address (host:port) - see [Config stream](#config-stream). |
| `--subscriber-id`           | the hostname | Identifies this replica to the controller's config stream logs/metrics (e.g. this pod's name).     |
| `--log-level`               | `info`  | One of `debug`, `info`, `warn`, `error`.                                                                 |
| `--grpc-reflection`         | `false` | Enable gRPC server reflection (local debugging only).                                                   |

A gRPC health service (`grpc.health.v1.Health`) is always registered, so `kubectl` and Kubernetes'
native gRPC probes can check readiness/liveness on the same port without a separate HTTP port - see
[Config stream](#config-stream) for how readiness is tied to having received a first config.

## Configuration

The config (see `internal/processor/config/types.go` for the authoritative Go types, and
[Config stream](#config-stream) for how it's delivered) is canonical JSON with two top-level keys.
The example below uses YAML purely for readability in this document; the wire format is JSON, not
YAML:

```yaml
# directives maps an opaque "engine key" to a block of raw Coraza/SecLang directives. Each entry is
# compiled into its own coraza.WAF engine, keyed by that string. Identical rendered directive blocks
# are expected to share the same engine key (e.g. a hash of the rendered directives) so that engines
# get deduplicated in memory instead of compiling one per policy/route that happens to use the exact
# same rules.
directives:
  <engineKey>: <secLangDirectives>

# routes maps host+pathPrefix pairs to the engine that protects them.
routes:
  - host: <host>            # matched against :authority/Host - an exact hostname, "*.<suffix>"
                             # (any strict subdomain of suffix), or "*" (any host) - see "Matching
                             # semantics" below
    pathPrefix: <pathPrefix> # matched against :path
    waf:
      engineKey: <engineKey> # must exist in `directives`; omit `waf` entirely for a route with no engine attached
```

### Matching semantics

For each request, the processor resolves the WAF engine as follows (see
`internal/processor/config/snapshot.go`). This is the *request-time* half of
matching; see `docs/policy-attachment.md` for how the controller decides
which `WAFPolicy` governs a route in the first place, and how that becomes
the `host`/`pathPrefix` entries matched below:

1. **Host** — tried in this order, each fully exhausted before falling through to the next:
   1. an exact match against `:authority`/`Host`;
   2. the same host with any `:port` suffix stripped, still matched exactly (an IPv6 literal like
      `[::1]:8443` is handled correctly: only the port after the closing `]` is stripped);
   3. a wildcard route (`host: "*.example.com"`), matched against the host and then the
      port-stripped host - it matches any strict subdomain of the suffix (`shop.example.com`) but
      **not** the bare suffix itself (`example.com`); when more than one wildcard route matches,
      the most specific (longest) suffix wins (`*.internal.example.com` over `*.example.com`);
   4. a catch-all route (`host: "*"`), matching any host at all.
2. **Path** — among the routes for the matched host (whichever step above matched), the **longest
   matching `pathPrefix`** wins, so a more specific route (e.g. `/health`) can override a broader
   one (e.g. `/`) for the same host.
3. **No match at all** — the request is **not blocked**; it continues unprotected. This is
   intentional: classification (which requests get inspected) is meant to live in the gateway's
   native route table (via policy attachment), not be re-derived here from an ever-growing host
   inventory. The processor's routing table exists purely to pick *which* engine applies once the
   gateway has already decided a request should be sent through `ext_proc` at all. A route with no
   matching host at all (not even a catch-all) is how the controller expresses that: it simply
   doesn't emit an entry.
4. **Route matches but has no `waf` key** — distinct from "no route matched": the route is
   recognized, but no engine runs. This is reserved for a future DLP-only route (once DLP exists as
   its own response-phase engine, independent of the WAF request-phase engine).

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
directives:
  shop-strict: |
    Include @coraza.conf-recommended
    Include @crs-setup.conf.example
    Include @owasp_crs/*.conf
  off: |
    SecRuleEngine Off

routes:
  # /health on shop.example.com is explicitly exempted from the WAF (longest-prefix wins over the
  # broader "/" route below).
  - host: shop.example.com
    pathPrefix: /health
    waf:
      engineKey: off
  - host: shop.example.com
    pathPrefix: /
    waf:
      engineKey: shop-strict
  # blog.example.com is recognized (so a future DLP-only config could attach to it) but currently
  # has no WAF engine at all - equivalent to unprotected, but explicit about it.
  - host: blog.example.com
    pathPrefix: /
```

The Core Rule Set shown above (`@coraza.conf-recommended`, `@crs-setup.conf.example`,
`@owasp_crs/*.conf`) comes from the embedded `github.com/corazawaf/coraza-coreruleset` module (see
`internal/processor/config/compile.go`); no vendored rule files ship in this repository. Exactly one
CRS version is baked into a given processor binary; its version is logged at startup (`crs-version`
attribute on the "Processor ready" log line).

## Request-time flow

1. **Request headers phase** — the processor extracts `:authority`, `:method`, `:path` (and, for
   logging, `:scheme`), resolves the WAF engine via the routing table above, and if one is attached,
   starts a Coraza transaction (`ProcessURI` + per-header `AddRequestHeader` + `ProcessRequestHeaders`).
   An interruption here blocks immediately.
2. **Request body phase** — body chunks are streamed into the transaction (`WriteRequestBody`); on
   `EndOfStream`, `ProcessRequestBody` runs the request-body-phase rules.
3. **Response headers phase** — currently only re-runs Coraza's own response-header rules
   (`ProcessResponseHeaders`). **DLP response inspection/redaction is not implemented**: WAF is a
   request-phase concern (allow/block); DLP is meant to be a response-phase concern (redact/mask/
   block sensitive data such as PII/PAN/secrets before it leaves the cluster), and that engine
   doesn't exist yet.
4. **Response body phase** — same idea as request body, but response-phase rules
   (`ProcessResponseBody`). Also **not** a DLP mutation point yet: this phase can currently only
   block, it never redacts or otherwise mutates the response body.

Any interruption at any phase produces an Envoy `ImmediateResponse`: this short-circuits the
request/response entirely (the client gets this response directly, nothing is forwarded to/from the
upstream), with the interruption's status code (or 403 if unset), a `content-type: text/plain` body
describing the matched rule ID/action, and an `x-waf-violation: 1` header.

## Config stream

The processor receives its data-plane config (engines + routing table) from the controller over a
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
  across reconciles because `processorconfig.Build` documents its `Routes` ordering as canonical
  (sorted, not the cache's arbitrary iteration order) and `encoding/json.Marshal` is itself
  deterministic (sorted map keys, declaration-order struct fields).
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

## Deployment

`charts/gateway-protector/templates/processor/`:

- `deployment.yaml` — passes `--config-server-address` pointing at the controller's config stream
  Service (see below); liveness/readiness use Kubernetes' native gRPC probe support against the
  health service above.
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
- **No mTLS** between agentgateway and the processor, or between the processor and the controller's
  config stream, yet.
- **Config stream acks aren't surfaced to `WAFPolicy` status** - `ConfigServer` logs every
  `ConfigAck` (and a future metric), but a replica repeatedly rejecting a config isn't yet reflected
  back onto the `WAFPolicy` objects that contributed to it.
