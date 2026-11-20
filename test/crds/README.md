# Test-only CRD fixtures

`agentgateway.dev_agentgatewaypolicies.yaml` is a verbatim copy of the
`AgentgatewayPolicy` CRD from
`github.com/agentgateway/agentgateway`
(`controller/install/helm/agentgateway-crds/templates/agentgateway.dev_agentgatewaypolicies.yaml`)
at commit `8729cd04a85bd374701d00a7f2140e6408df7b1a` (v1.3.1-45-g8729cd04).
The "Update agentgateway" workflow replaces it with the CRD of each new
agentgateway release, together with the agentgateway version that the e2e
suites and the Tiltfile use. It is installed
by the envtest suite (see `internal/controller/suite_test.go`) so the
Gateway-wiring specs can create/list generated `AgentgatewayPolicy` objects
against the real schema. It is **not** shipped by this project's Helm chart:
installing the agentgateway CRDs in a real cluster is agentgateway's job
(see the prerequisites in README.md).
