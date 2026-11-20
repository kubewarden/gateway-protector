# Kubewarden Gateway Protector

> [!WARNING]
> This project is experimental and under active development. It is not ready
> for production. It has no release yet.

Kubewarden Gateway Protector is a Kubernetes security tool. It protects the
HTTP traffic that a gateway exposes from a cluster. The gateway is a proxy
that implements the
[Kubernetes Gateway API](https://gateway-api.sigs.k8s.io).

The first protection is a web application firewall (WAF). A WAF inspects HTTP
requests and responses and blocks attacks such as SQL injection. The WAF uses
[Coraza](https://coraza.io) and the
[OWASP Core Rule Set](https://coreruleset.org), a set of ready-to-use rules
that find generic attacks.

A platform team attaches a `WAFPolicy` to a `Gateway` or to an `HTTPRoute`:

```yaml
apiVersion: gateway-protector.kubewarden.io/v1alpha1
kind: WAFPolicy
metadata:
  name: shared-gw-default
  namespace: gateway-protector-system
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: shared-gw
    namespace: infra
  engine:
    mode: Detection
```

A policy has one of three modes:

- `Detection`: the WAF logs each rule that matches and blocks nothing.
- `Blocking`: the WAF rejects the traffic that a rule matches.
- `Off`: the WAF is off for the target of the policy.

Gateway Protector works with one gateway,
[agentgateway](https://agentgateway.dev). A second protection, data loss
prevention (DLP), is planned.

## Documentation

The project has no documentation website and no installation instructions
yet. These documents describe the design and the code:

- [RFC 0001](docs/rfc/0001-project-purpose.md) describes the purpose of the
  project, the design, and the alternatives.
- [Architecture](docs/architecture.md) is a map of the code.
- [CRD reference](docs/crds/) describes each field of the API.

## Development

[CONTRIBUTING.md](CONTRIBUTING.md) describes how to run the tests, the linter,
and the development environment.

## Security disclosure

See the
[Kubewarden security policy](https://github.com/kubewarden/community/security/policy).

## Build with the community

Gateway Protector is part of [Kubewarden](https://www.kubewarden.io/), a CNCF
Sandbox project.

- [Join us on Slack](https://kubernetes.slack.com/?redir=%2Fmessages%2Fkubewarden)
- [Community meetings](https://www.kubewarden.io/#get-in-touch)
