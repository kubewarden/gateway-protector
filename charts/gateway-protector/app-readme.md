# Kubewarden Gateway Protector

Kubewarden Gateway Protector protects the HTTP traffic that a gateway exposes
from a Kubernetes cluster. It works with [agentgateway](https://agentgateway.dev),
an implementation of the Kubernetes Gateway API.

The first protection is a web application firewall (WAF), based on
[Coraza](https://coraza.io) and the
[OWASP Core Rule Set](https://coreruleset.org). A platform team attaches a
`WAFPolicy` to a `Gateway` or to an `HTTPRoute`. The policy runs in one of
three modes:

- **Detection**: log each rule that matches, and block nothing.
- **Blocking**: reject the traffic that a rule matches.
- **Off**: turn the WAF off for the target of the policy.

For more information refer to the
[project repository](https://github.com/kubewarden/gateway-protector).
