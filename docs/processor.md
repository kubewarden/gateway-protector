# Gateway Protector — Processor

The processor is the Envoy `ext_proc` gRPC service that runs the WAF engine (and, in the
future, DLP) for Gateway Protector. agentgateway calls it once per HTTP request/response over a
single bidirectional gRPC stream that spans all four processing phases (request headers, request
body, response headers, response body), so a single process can run WAF (request-phase allow/block)
and, eventually, DLP (response-phase redact/mask/block) with one network hop instead of two.

The processor has no Kubernetes API dependency: it is configured entirely by a local YAML file (see
[Configuration](#configuration) below) and knows nothing about `WAFPolicy`/`WAFCoreRuleSet`/
`WAFRuleSet` objects. A future controller will render that config file automatically from those CRDs;
today it is hand-authored (see `charts/gateway-protector/values.yaml`'s `processor.config` for the
chart-installed default).

## Command-line flags

| Flag                    | Default                                             | Description                                                              |
| ------------------------ | ---------------------------------------------------- | ------------------------------------------------------------------------- |
| `--grpc-bind-address`   | `:9000`                                             | Address the ext_proc gRPC service binds to.                              |
| `--config`              | `/etc/gateway-protector/processor/config.yaml`      | Path to the data-plane config file described below.                     |
| `--log-level`           | `info`                                              | One of `debug`, `info`, `warn`, `error`.                                 |
| `--grpc-reflection`     | `false`                                             | Enable gRPC server reflection (local debugging only).                   |

A gRPC health service (`grpc.health.v1.Health`) is always registered, so `kubectl` and Kubernetes'
native gRPC probes can check readiness/liveness on the same port without a separate HTTP port.

## Configuration

The config file (see `internal/processor/config/types.go` for the authoritative Go types) has two
top-level keys:

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
  - host: <host>            # matched against :authority/Host
    pathPrefix: <pathPrefix> # matched against :path
    waf:
      engineKey: <engineKey> # must exist in `directives`; omit `waf` entirely for a route with no engine attached
```

### Matching semantics

For each request, the processor resolves the WAF engine as follows (see
`internal/processor/config/snapshot.go`):

1. **Host** — an exact match against `:authority`/`Host` is tried first. If none matches and the
   host has a `:port` suffix, the port is stripped and the lookup is retried once more (an IPv6
   literal like `[::1]:8443` is handled correctly: only the port after the closing `]` is stripped).
2. **Path** — among the routes for the matched host, the **longest matching `pathPrefix`** wins,
   so a more specific route (e.g. `/health`) can override a broader one (e.g. `/`) for the same host.
3. **No match at all** — the request is **not blocked**; it continues unprotected. This is
   intentional: classification (which requests get inspected) is meant to live in the gateway's
   native route table (via policy attachment), not be re-derived here from an ever-growing host
   inventory. The processor's routing table exists purely to pick *which* engine applies once the
   gateway has already decided a request should be sent through `ext_proc` at all.
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
`api/v1alpha1.WAFBodyInspectionSpec`) are expected to land once the controller renders this config
as directives: `enabled`/`maxSize` become `SecRequestBodyAccess`/`SecRequestBodyLimit` (etc.) in the
rendered engine, rather than being threaded through as separate processor-level settings.

### Example

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
`internal/processor/config/compile.go`); no vendored rule files ship in this repository.

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

## Hot reload

The processor watches its config file for changes using inotify (`github.com/fsnotify/fsnotify`), and
recompiles + swaps in a new in-memory `Snapshot` (engines + routing table) whenever the content
actually changes (see `internal/processor/config/loader.go`).

- It watches the file's **parent directory**, not the file itself. This is required for Kubernetes
  ConfigMap volume mounts: kubelet updates a mounted ConfigMap by writing the new content under a
  new `..data_<timestamp>` directory and atomically repointing the `..data` symlink (and the
  mounted file itself) at it. A watch on the original file's inode would never observe that swap; a
  watch on the directory does.
- A sha256 content hash gates every reload, so the inevitable duplicate/spurious inotify events
  (writes, chmods, the ConfigMap symlink dance) never trigger a wasted recompile.
- **Fail-safe by default**: if the file becomes unreadable, fails to parse, fails semantic
  validation, or fails to compile into Coraza engines, the error is logged and the *previous*
  compiled `Snapshot` keeps serving traffic untouched. A bad reload can never silently disable
  protection or crash the data plane.

**Known limitation:** Coraza memoizes compiled regex/aho-corasick patterns in a process-wide cache by
default. When a `Snapshot` is superseded, its old `coraza.WAF` engines are simply dropped/garbage
collected today; that cache is not explicitly released (`coraza/v3`'s `experimental.WAFCloser` isn't
wired up yet). On a processor that reloads configuration very frequently this is a slow memory leak,
not a correctness bug - worth revisiting before recommending frequent reloads in production.

## Deployment

`charts/gateway-protector/templates/processor/`:

- `deployment.yaml` — mounts the config as a ConfigMap volume at
  `/etc/gateway-protector/processor/`; liveness/readiness use Kubernetes' native gRPC probe support
  against the health service above.
- `service.yaml` — a `ClusterIP` Service on port `9000`. This is the `backendRef` a future
  `AgentgatewayPolicy` (generated by the controller) will point `ext_proc` traffic at.
- `configmap.yaml` — renders `values.yaml`'s `processor.config`. The chart default is intentionally
  inert (a single `SecRuleEngine Off` engine, zero routes), so a default `helm install` starts
  cleanly without protecting anything until an operator supplies a real configuration.

## Current limitations / roadmap

- **No DLP** - response-phase inspection is Coraza-only (CRS phase 3/4 blocking); there is no data
  redaction, masking, or response-body mutation yet.
- **No WebSocket-specific handling** - a long-lived upgraded connection is just a single ext_proc
  stream/Coraza transaction like any other request; there's no dedicated state machine for it.
- **Config is hand-authored** - the controller does not yet render this file from
  `WAFPolicy`/`WAFCoreRuleSet`/`WAFRuleSet` objects.
- **No mTLS** between agentgateway and the processor yet.
- **No `WAFCloser` cleanup on reload** (see "Hot reload" above).
