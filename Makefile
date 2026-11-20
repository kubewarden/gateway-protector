CONTROLLER_TOOLS_VERSION := v0.21.0
ENVTEST_VERSION := release-0.24
ENVTEST_K8S_VERSION := 1.33.0
HELM_VALUES_SCHEMA_JSON_VERSION := v2.3.1
GOLANGCI_LINT_VERSION ?= v2.12.1
BUF_VERSION ?= v1.72.0

CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)
ENVTEST ?= go run sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION)
HELM_SCHEMA ?= go run github.com/losisin/helm-values-schema-json/v2@$(HELM_VALUES_SCHEMA_JSON_VERSION)

## Location to install dependencies to. Declared this early (rather than in
## the "##@ Dependencies" section below, where the rest of the tooling setup
## lives) because GOLANGCI_LINT/BUF are used as prerequisites - not just
## inside recipes - further down: unlike recipes, which Make expands lazily
## at execution time, a rule's prerequisite list is expanded immediately as
## the Makefile is read, so these variables must already be defined by the
## time any earlier rule's prerequisite list references them, or that
## reference silently expands to nothing.
LOCALBIN ?= $(shell pwd)/bin
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint-$(GOLANGCI_LINT_VERSION)
BUF = $(LOCALBIN)/buf-$(BUF_VERSION)

GO_MOD_SRCS := go.mod go.sum
GO_BUILD_ENV := CGO_ENABLED=0 GOOS=linux GOARCH=amd64

ENVTEST_DIR ?= $(shell pwd)/.envtest

REGISTRY ?= ghcr.io
REPO ?= kubewarden/gateway-protector
TAG ?= latest

.PHONY: all
all: controller processor

.PHONY: test
test: vet ## Run tests.
	# TODO: decrease timeout once we move to self-hosted runners
	$(GO_BUILD_ENV) CGO_ENABLED=1 KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_DIR) -p path)" go test $$(go list ./... | grep -v /test/) -race -test.v -timeout 30m -coverprofile coverage/cover.out -covermode=atomic

.PHONY: helm-unittest
helm-unittest:
	helm unittest charts/gateway-protector --file "tests/**/*_test.yaml"

.PHONY: test-e2e
test-e2e: controller-image processor-image
	# TODO: decrease timeout once we move to self-hosted runners
	$(GO_BUILD_ENV) go test ./test/e2e/ -v -timeout 30m

.PHONY: test-coraza-e2e
test-coraza-e2e: ## Run Coraza's connector e2e suite through agentgateway + the ext_proc processor
	go test ./test/coraza-e2e/ -v -timeout 15m

.PHONY: test-ftw
test-ftw: ## Run the OWASP CRS regression suite (go-ftw) through agentgateway + the ext_proc processor.
	go test ./test/ftw/ -v -timeout 30m

.PHONY: fmt
fmt: buf
	$(GO_BUILD_ENV) go fmt ./...
	$(BUF) format -w proto

.PHONY: proto-lint
proto-lint: buf ## Lint and check formatting of the config stream's proto definitions.
	$(BUF) lint proto
	$(BUF) format --exit-code -d proto

.PHONY: lint
lint: golangci-lint proto-lint
	$(GO_BUILD_ENV) $(GOLANGCI_LINT) run --verbose

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GO_BUILD_ENV) $(GOLANGCI_LINT) run --fix

.PHONY: vet
vet:
	$(GO_BUILD_ENV) go vet ./...

CONTROLLER_SRC_DIRS := cmd/controller api internal/controller
CONTROLLER_GO_SRCS := $(shell find $(CONTROLLER_SRC_DIRS) -type f -name '*.go' 2>/dev/null)
CONTROLLER_SRCS := $(GO_MOD_SRCS) $(CONTROLLER_GO_SRCS)
.PHONY: controller
controller: $(CONTROLLER_SRCS) vet
	$(GO_BUILD_ENV) go build -o ./bin/controller ./cmd/controller

.PHONY: controller-image
controller-image:
	docker build -f ./Dockerfile.controller \
		-t "$(REGISTRY)/$(REPO)/controller:$(TAG)" .
	@echo "Built $(REGISTRY)/$(REPO)/controller:$(TAG)"

PROCESSOR_SRC_DIRS := cmd/processor internal/processor
PROCESSOR_GO_SRCS := $(shell find $(PROCESSOR_SRC_DIRS) -type f -name '*.go' 2>/dev/null)
PROCESSOR_SRCS := $(GO_MOD_SRCS) $(PROCESSOR_GO_SRCS)
.PHONY: processor
processor: $(PROCESSOR_SRCS) vet
	$(GO_BUILD_ENV) go build -o ./bin/processor ./cmd/processor

.PHONY: processor-image
processor-image:
	docker build -f ./Dockerfile.processor \
		-t "$(REGISTRY)/$(REPO)/processor:$(TAG)" .
	@echo "Built $(REGISTRY)/$(REPO)/processor:$(TAG)"

.PHONY: generate
generate: generate-controller generate-chart generate-docs generate-proto

.PHONY: check-generate
check-generate: generate ## Regenerate all files and fail if that changes the working tree.
	@./hack/check-for-auto-generated-changes.sh

.PHONY: generate-controller
generate-controller: manifests  ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(GO_BUILD_ENV) $(CONTROLLER_GEN) object paths="./api/v1alpha1" paths="./internal/agentgatewayapi"

.PHONY: manifests
manifests: ## Generate ClusterRole and CustomResourceDefinition objects. We use sed to inject labels that controller-gen markers can't express (see role.yaml); everything else (names) comes from the roleName= marker in the Go source.
	$(GO_BUILD_ENV) $(CONTROLLER_GEN) rbac:roleName=unused crd paths="./api/v1alpha1" paths="./internal/controller" output:crd:artifacts:config=charts/gateway-protector/templates/crd output:rbac:artifacts:config=charts/gateway-protector/templates/controller
	sed -i '/metadata:/a\  labels:\n    {{ include "gateway-protector.labels" . | nindent 4 }}\n    app.kubernetes.io/component: controller' charts/gateway-protector/templates/controller/role.yaml

.PHONY: generate-chart
generate-chart: ## Generate Helm chart values schema.
	$(HELM_SCHEMA) --values charts/gateway-protector/values.yaml --output charts/gateway-protector/values.schema.json

.PHONY: generate-docs
generate-docs: ## Generate API documentation for CRDs.
	$(MAKE) -C docs/crds

.PHONY: generate-fixtures
generate-fixtures: ## Generate test fixtures.
	$(GO_BUILD_ENV) go run ./hack/generate_fixtures.go ./test/fixtures

PROTO_SRCS := proto/configstream/v1/config_stream.proto

# PROTO_GEN_MAIN is the only one of buf generate's two output files
# (config_stream_grpc.pb.go is the other) declared as this rule's target.
# A real multi-output rule (GNU Make 4.3's "&:" grouped targets) would be
# more precise, but 4.3 postdates several still-common Make versions
# (macOS ships 3.81; Ubuntu 20.04/RHEL 8 ship 4.2.1) and degrades silently
# on older ones: "&:" parses there as an ordinary rule with a stray literal
# "&" target, so the recipe can run twice (once per stale target) or, under
# `make -j`, twice concurrently - two buf processes racing to write the same
# files, with no error at all. Tracking one representative output instead
# works on any Make: both files are only ever written together by the same
# invocation, so the one blind spot (deleting only the non-tracked file by
# hand) is both unlikely and already caught by CI's generate-proto drift
# check.
PROTO_GEN_MAIN := internal/configstream/v1/config_stream.pb.go

.PHONY: generate-proto
generate-proto: $(PROTO_GEN_MAIN) ## Generate Go code from the config stream's proto definitions.

$(PROTO_GEN_MAIN): $(PROTO_SRCS) buf.gen.yaml proto/buf.yaml $(BUF)
	$(GO_BUILD_ENV) $(BUF) generate proto

.PHONY: proto-breaking
proto-breaking: buf ## Check the config stream's proto definitions for breaking changes against main. Run this locally before changing proto/configstream/v1/config_stream.proto; not run in CI (needs full git history).
	$(BUF) breaking proto --against '.git#branch=main,subdir=proto'

##@ Dependencies

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,${GOLANGCI_LINT_VERSION})

.PHONY: buf
buf: $(BUF) ## Download buf locally if necessary.
$(BUF): $(LOCALBIN)
	$(call go-install-tool,$(BUF),github.com/bufbuild/buf/cmd/buf,${BUF_VERSION})

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary (ideally with version)
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f $(1) ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv "$$(echo "$(1)" | sed "s/-$(3)$$//")" $(1) ;\
}
endef
