# Contributing

## Run tests

```shell
make test
```

This runs `go vet` plus the full Go test suite (unit tests and the envtest-based controller
suite) with `-race`. `setup-envtest` downloads the required `KUBEBUILDER_ASSETS` automatically -
no manual setup needed.

Helm chart unit tests (via the [`helm unittest`](https://github.com/helm-unittest/helm-unittest)
plugin) are run separately:

```shell
make helm-unittest
```

End-to-end tests (`make test-e2e`) are planned but not implemented yet - `test/e2e` doesn't exist
in the repo yet. `test/manifests/httpbin.yaml` (see below) is meant to be the shared fixture
between the Tilt dev environment and that future suite.

## Lint code

```shell
make lint
```

## Run the development environment with Tilt

We use [Tilt](https://tilt.dev/) to run a local development environment. Copy
[`tilt-settings.yaml.example`](tilt-settings.yaml.example) to `tilt-settings.yaml` and customize
it to your needs (at minimum, set your own image repositories).

Run tilt:

```shell
tilt up
```

Run tilt with unified logs:

```shell
tilt up --stream
```

Follow controller logs:

```shell
tilt logs -f gateway-protector-controller
```

Follow processor logs:

```shell
tilt logs -f gateway-protector-processor
```

Teardown the environment:

```shell
tilt down
```

### What Tilt sets up

The `Tiltfile` installs everything gateway-protector needs to run end to end in a local
cluster, in dependency order:

- The [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) CRDs, pinned to the version this
  repo's `go.mod` depends on.
- [agentgateway](https://agentgateway.dev/) (CRDs + control plane), installed via Helm from
  agentgateway's own OCI registry - the data plane this controller generates
  `AgentgatewayPolicy` objects for.
- The `gateway-protector` chart itself (controller + processor), with hot reloading: editing Go
  source under `internal/controller`, `internal/agentgatewayapi`, or `internal/processor`
  rebuilds and restarts the corresponding container in place.
- A demo setup to exercise the whole loop immediately: the
  [httpbin](https://github.com/mccutchen/go-httpbin) sample app with a `Gateway`/`HTTPRoute`
  (`test/manifests/httpbin.yaml`), a demo `WAFPolicy` protecting it
  (`examples/wafpolicy-demo.yaml`), and a port-forward to the agentgateway proxy Deployment that
  `Gateway` creates - see [Verifying the environment](#verifying-the-environment) below.

### Verifying the environment

All traffic goes through the `httpbin-gateway-port-forward` Tilt resource, which forwards
`localhost:8080` to the agentgateway proxy created for the demo `Gateway`.

Clean requests pass through to httpbin:

```shell
curl -i localhost:8080/get                  # 200
curl -i localhost:8080/post -d "q=hello"    # 200, body inspected and passed
```

Requests matching OWASP Core Rule Set signatures are blocked by the demo `WAFPolicy`
(`examples/wafpolicy-demo.yaml`, `mode: Blocking`, `paranoiaLevel: 1`):

```shell
# XSS in a query parameter (URL-encoded: an unencoded "<script>" is rejected
# by the HTTP parser with a 400 before the request ever reaches the WAF)
curl -i "localhost:8080/get?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"  # 403

# SQL injection in a query parameter
curl -i "localhost:8080/get?id=1'%20OR%20'1'='1"                   # 403

# XSS in a POST body (request body inspection)
curl -i localhost:8080/post -d "q=<script>alert(1)</script>"       # 403
```

The same requests can be sent from inside the cluster (no port-forward needed) via the curl
sidecar shipped with the httpbin Deployment:

```shell
kubectl exec -n httpbin deploy/httpbin -c curl -- curl -si http://httpbin-gateway/get
```

To check the control-plane side:

```shell
# Accepted/Programmed should both be True
kubectl get wafpolicy -n gateway-protector-system

# The generated ext_proc wiring for the httpbin route
kubectl get agentgatewaypolicies -n httpbin

# The published processor config (engines + routing table)
kubectl get configmap gateway-protector-processor-config -n gateway-protector-system -o yaml
```

## Generate code

When you make changes to the CRDs in `/api` or rbac rules annotations, you need to regenerate the code.

```shell
make generate
```

This will automatically update the API reference documentation in [`docs/crds`](docs/crds/README.md).

## Writing Tests

**Controller Tests**
Controller tests live in `internal/controller` and use [envtest](https://book.kubebuilder.io/reference/envtest.html)
to run against a real API server and etcd instance.
We use [Ginkgo](https://onsi.github.io/ginkgo/) and [Gomega](https://onsi.github.io/gomega/) for BDD-style testing.

**Unit Tests**
Unit tests for other packages (e.g. `internal/controller/processorconfig`, `internal/processor`)
are plain Go tests, using [testify](https://github.com/stretchr/testify)'s `assert`/`require`,
in their respective directories.

**E2E Tests**
Planned, not implemented yet - see "Run tests" above.
