tilt_settings_file = "./tilt-settings.yaml"
settings = read_yaml(tilt_settings_file)

update_settings(k8s_upsert_timeout_secs=300)

# Install the Kubernetes Gateway API CRDs (Gateway, HTTPRoute, ...) that
# both agentgateway and this project's WAFPolicy/WAFRuleSet CRDs build on.
# Use the version of sigs.k8s.io/gateway-api in go.mod, so the installed
# CRDs match the Go types compiled into the controller.
gateway_api_version = str(
    local("go list -m -f '{{.Version}}' sigs.k8s.io/gateway-api", quiet=True)
).strip()
local_resource(
    "gateway-api-crds",
    cmd="kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/{}/standard-install.yaml".format(
        gateway_api_version
    ),
    labels=["core"],
)

# Install agentgateway: the data plane this controller generates
# AgentgatewayPolicy objects for (see
# internal/controller/processor_config_wiring.go). Pinned to the release
# that the vendored internal/agentgatewayapi types match. The "Update
# agentgateway" workflow updates it.
#
# Installed via Helm from agentgateway's own OCI registry, following
# https://agentgateway.dev/docs/kubernetes/latest/install/helm/ - first the
# CRDs (AgentgatewayPolicy, AgentgatewayBackend, AgentgatewayParameters),
# then the control plane itself.
agentgateway_version = "v1.7.0"

load("ext://helm_resource", "helm_resource")
helm_resource(
    "agentgateway-crds",
    "oci://cr.agentgateway.dev/charts/agentgateway-crds",
    namespace="agentgateway-system",
    flags=[
        "--create-namespace",
        "--version",
        agentgateway_version,
    ],
    resource_deps=[
        "gateway-api-crds",
    ],
    labels=["core"],
    # This chart only installs CRDs - no Deployment/Pod. Tilt's default
    # pod-readiness heuristic ("wait for pods to be ready if it thinks a
    # resource has pods") doesn't resolve to "no pods, therefore
    # immediately healthy" here, so this resource's health status (as
    # opposed to its build/apply status, which does succeed) never
    # settles - which is what left `agentgateway`'s resource_deps on this
    # resource stuck on "waiting on resource:agentgateway-crds" even
    # though this resource showed green. Explicitly ignoring pod
    # readiness makes health track the apply command's exit status
    # instead, which is the only thing that makes sense for a CRD-only
    # chart.
    pod_readiness="ignore",
)
helm_resource(
    "agentgateway",
    "oci://cr.agentgateway.dev/charts/agentgateway",
    namespace="agentgateway-system",
    flags=[
        "--version",
        agentgateway_version,
    ],
    resource_deps=[
        "agentgateway-crds",
    ],
    labels=["core"],
)

# Create the gateway-protector namespace.
# This is required since the helm() function doesn't support the
# create_namespace flag.
load("ext://namespace", "namespace_create")
namespace_create("gateway-protector-system")

registry = settings.get("registry")
controller_image = settings.get("controller").get("image")
processor_image = settings.get("processor").get("image")

yaml = helm(
    "./charts/gateway-protector",
    name="gateway-protector",
    namespace="gateway-protector-system",
    set=[
        "controller.image.repository=" + registry + "/" + controller_image,
        "processor.image.repository=" + registry + "/" + processor_image,
        "controller.replicas=1",
        "processor.replicas=1",
        "processor.logLevel=debug",
    ],
)

objects = decode_yaml_stream(yaml)
for o in objects:
    if o.get('kind') == 'Deployment':
        containers = o['spec']['template']['spec']['containers']
        # Remove securityContext to allow hot reloading
        for container in containers:
            if 'securityContext' in container:
                container['securityContext'] = {}
updated_yaml = encode_yaml_stream(objects)
k8s_yaml(
    updated_yaml,
)

k8s_resource(
    "gateway-protector-controller",
    resource_deps=["gateway-api-crds", "agentgateway-crds"],
    labels=["core"],
)
k8s_resource(
    "gateway-protector-processor",
    port_forwards="9000:9000",
    labels=["core"],
)

# Hot reloading containers

local_resource(
    "controller_tilt",
    "make controller",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/controller",
        "api",
        "internal/controller",
        "internal/agentgatewayapi",
    ],
    labels=["core"],
)

entrypoint = ["/controller"]
dockerfile = "./hack/Dockerfile.controller.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build_with_restart(
    registry + "/" + controller_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/controller",
    ],
    live_update=[
        sync("./bin/controller", "/controller"),
    ],
)

local_resource(
    "processor_tilt",
    "make processor",
    deps=[
        "go.mod",
        "go.sum",
        "cmd/processor",
        "internal/processor",
    ],
    labels=["core"],
)

entrypoint = ["/processor"]
dockerfile = "./hack/Dockerfile.processor.tilt"

docker_build_with_restart(
    registry + "/" + processor_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./bin/processor",
    ],
    live_update=[
        sync("./bin/processor", "/processor"),
    ],
    # The processor Deployment mounts an emptyDir at /tmp (see
    # charts/gateway-protector/templates/processor/deployment.yaml), which
    # shadows the /tmp/.restart-proc file the restart_process extension
    # bakes into the image - entr then crash-loops with "unable to stat
    # '/tmp/.restart-proc'". Move the restart file out of /tmp.
    restart_file="/.restart-proc",
)

# httpbin sample app + Gateway/HTTPRoute wiring it through agentgateway
# (see test/manifests/httpbin.yaml - shared with test/e2e), plus a demo
# WAFPolicy protecting it, so the whole loop is exercisable right after
# `tilt up`:
#
#   curl -s localhost:8080/get                                       # 200
#   curl -s "localhost:8080/get?q=%3Cscript%3Ealert(1)%3C/script%3E"  # 403
#
# The XSS payload must be percent-encoded: agentgateway's HTTP/1.1 front
# end rejects a raw, unescaped "<"/">" in the request target with its own
# 400 before the request ever reaches the processor, independently of any
# WAFPolicy. Coraza/CRS decode percent-encoding before pattern matching,
# so the encoded form still triggers the same rule.
k8s_yaml("test/manifests/httpbin.yaml")
k8s_resource(
    "httpbin",
    objects=[
        "httpbin:namespace",
        "httpbin:serviceaccount",
        "httpbin-gateway:gateway",
        "httpbin:httproute",
    ],
    resource_deps=["agentgateway"],
    labels=["demo"],
)

k8s_yaml("examples/wafpolicy-demo.yaml")
k8s_resource(
    new_name="httpbin-demo-policy",
    objects=["httpbin-demo:wafpolicy"],
    resource_deps=["gateway-protector-controller", "httpbin"],
    labels=["demo"],
)

# agentgateway creates a proxy Deployment/Service named after the Gateway
# object, in the Gateway's own namespace (here: deployment/httpbin-gateway
# in the httpbin namespace) - Tilt has no k8s_resource for it to attach a
# port_forwards to, since it isn't part of any k8s_yaml this Tiltfile
# applies. serve_cmd keeps a long-running port-forward process instead,
# restarting it if the proxy isn't up yet.
local_resource(
    "httpbin-gateway-port-forward",
    serve_cmd="kubectl port-forward -n httpbin deployment/httpbin-gateway 8080:80",
    resource_deps=["httpbin"],
    labels=["demo"],
)
