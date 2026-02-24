# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

# Required environemnt variables for the project
ENV_VARS := AZURE_TENANT_ID AZURE_CLIENT_SECRET AZURE_CLIENT_ID AZURE_APP_GATEWAY_RESOURCE_ID

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: reset
reset: ## Reset the environment
	@echo "Resetting..."
	@rm -rf test.env
	@rm -rf .env

.PHONY: setup
setup: ## Setup the environment for development
	@if [ ! -f .test.env ]; then \
		echo "Creating .test.env file..."; \
		> .env; \
		for var in $(ENV_VARS); do \
			echo -n "Enter value for $$var: "; \
			read value; \
			echo "export $$var=$$value" >> .test.env; \
		done; \
		echo ".test.env file created with input values."; \
	fi
	@if [ ! -f .env ]; then \
		echo "PROJECT_ROOT=$$(pwd)" >> .env; \
		echo "Select a project to target:"; \
		PS3="Enter your choice: "; \
		select opt in $$(ls */*.csproj); do \
			if [ -n "$$opt" ]; then \
				echo "You have selected $$opt"; \
				echo "PROJECT_FILE=$$opt" >> .env; \
				break; \
			else \
				echo "Invalid selection. Please try again."; \
			fi; \
		done; \
		echo "PROJECT_NAME=$$(basename $$(dirname $$(grep PROJECT_FILE .env | cut -d '=' -f 2)))" >> .env; \
	fi

.PHONY: newtest
newtest: setup ## Create a new test project
	@source .env; \
	testProjectName="$$PROJECT_NAME".Tests; \
	echo "Creating new xUnit project called $$testProjectName"; \
	dotnet new xunit -o $$testProjectName; \
	dotnet sln add $$testProjectName/$$testProjectName.csproj; \
	dotnet add $$testProjectName reference $$PROJECT_FILE;

.PHONY: installpackage
installpackage: ## Install a package to the project
	@source .env; \
	echo "Select a project to install the package into"; \
	PS3="Selection: "; \
	select opt in $$(ls */*.csproj); do \
		if [ -n "$$opt" ]; then \
			echo "You have selected $$opt"; \
			break; \
		else \
			echo "Invalid selection. Please try again."; \
		fi; \
	done; \
	echo "Enter the package name to install: "; \
	read packageName; \
	echo "Installing $$packageName to $$opt"; \
	dotnet add $$opt package $$packageName;

##@ Testing

.PHONY: testall
testall: ## Run all tests (unit + integration if RUN_INTEGRATION_TESTS=true)
	@source .env; \
	source .test.env; \
	dotnet test

.PHONY: test
test: ## Run a single test (interactive selection with fzf)
	@source .env; \
	source .test.env; \
	dotnet test --no-restore --list-tests | \
	grep -A 1000 "The following Tests are available:" | \
	awk 'NR>1' | \
	cut -d ' ' -f 5- | \
	sed 's/(.*//i' | \
	sort | uniq | \
	fzf | \
	xargs -I {} dotnet test --filter {} --logger "console;verbosity=detailed"

.PHONY: test-unit
test-unit: ## Run unit tests only (excludes integration tests)
	@source .env; \
	source .test.env; \
	dotnet test --filter "FullyQualifiedName!~Integration"

.PHONY: test-integration
test-integration: ## Run integration tests only (requires RUN_INTEGRATION_TESTS=true)
	@source .env; \
	source .test.env; \
	export RUN_INTEGRATION_TESTS=true; \
	if [ -n "$$INTEGRATION_TEST_KUBECONFIG" ]; then \
		export INTEGRATION_TEST_KUBECONFIG; \
	fi; \
	dotnet test --filter "FullyQualifiedName~Integration"

.PHONY: test-integration-fast
test-integration-fast: ## Run integration tests on single framework (net8.0 only, ~50% faster)
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	if [ -n "$$INTEGRATION_TEST_KUBECONFIG" ]; then \
		export INTEGRATION_TEST_KUBECONFIG; \
	fi; \
	dotnet test -f net8.0 --filter "FullyQualifiedName~Integration"

.PHONY: test-integration-full
test-integration-full: ## Run integration tests on all frameworks (net8.0 + net10.0)
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	if [ -n "$$INTEGRATION_TEST_KUBECONFIG" ]; then \
		export INTEGRATION_TEST_KUBECONFIG; \
	fi; \
	dotnet test --filter "FullyQualifiedName~Integration"

.PHONY: test-integration-smoke-net10
test-integration-smoke-net10: ## Run smoke tests on net10.0 only (Inventory tests)
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	if [ -n "$$INTEGRATION_TEST_KUBECONFIG" ]; then \
		export INTEGRATION_TEST_KUBECONFIG; \
	fi; \
	dotnet test -f net10.0 --filter "FullyQualifiedName~Integration&FullyQualifiedName~Inventory_"

.PHONY: test-ci
test-ci: ## Run CI-optimized tests (fast on PRs, full on main branch)
	@if [ "$$CI_BRANCH" = "main" ] || [ "$$GITHUB_REF" = "refs/heads/main" ]; then \
		echo "Running full test suite (main branch)..."; \
		$(MAKE) test-integration-full; \
	else \
		echo "Running fast test suite (PR branch)..."; \
		$(MAKE) test-integration-fast; \
		$(MAKE) test-integration-smoke-net10; \
	fi

.PHONY: test-coverage
test-coverage: ## Run tests with code coverage and generate HTML report
	@source .env; \
	source .test.env; \
	dotnet test --collect:"XPlat Code Coverage" --results-directory ./coverage; \
	reportgenerator \
		-reports:./coverage/**/coverage.cobertura.xml \
		-targetdir:./coverage/html \
		-reporttypes:Html; \
	echo "Coverage report generated at ./coverage/html/index.html"

.PHONY: test-watch
test-watch: ## Run tests in watch mode (auto-rerun on file changes)
	@source .env; \
	source .test.env; \
	dotnet watch test

.PHONY: test-store-jks
test-store-jks: ## Run K8SJKS store type integration tests
	@source .env; \
	source .test.env; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8SJKSStoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-store-pkcs12
test-store-pkcs12: ## Run K8SPKCS12 store type integration tests
	@source .env; \
	source .test.env; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8SPKCS12StoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-store-secret
test-store-secret: ## Run K8SSecret store type integration tests
	@source .env; \
	source .test.env; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8SSecretStoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-store-tls
test-store-tls: ## Run K8STLSSecr store type integration tests
	@source .env; \
	source .test.env; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8STLSSecrStoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-store-cluster
test-store-cluster: ## Run K8SCluster store type integration tests
	@source .env; \
	source .test.env; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8SClusterStoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-store-ns
test-store-ns: ## Run K8SNS store type integration tests
	@source .env; \
	source .test.env; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8SNSStoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-store-cert
test-store-cert: ## Run K8SCert store type integration tests
	@source .env; \
	source .test.env; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8SCertStoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-cluster-setup
test-cluster-setup: ## Display instructions for setting up test cluster
	@echo "=== Kubernetes Test Cluster Setup ==="
	@echo ""
	@echo "For integration tests, ensure your kubeconfig has a context named 'kf-integrations'."
	@echo ""
	@echo "Current kubectl context:"
	@kubectl config current-context 2>/dev/null || echo "  kubectl not configured"
	@echo ""
	@echo "Available contexts:"
	@kubectl config get-contexts 2>/dev/null || echo "  kubectl not configured"
	@echo ""
	@echo "To switch to kf-integrations:"
	@echo "  kubectl config use-context kf-integrations"
	@echo ""
	@echo "To verify cluster connectivity:"
	@echo "  kubectl cluster-info"
	@echo ""
	@echo "Integration tests will create/cleanup these namespaces:"
	@echo "  - keyfactor-test-k8sjks"
	@echo "  - keyfactor-test-k8spkcs12"
	@echo "  - keyfactor-test-k8ssecret"
	@echo "  - keyfactor-test-k8stlssecr"
	@echo "  - keyfactor-test-k8scluster"
	@echo "  - keyfactor-test-k8sns"
	@echo "  - keyfactor-test-k8scert"

.PHONY: test-cluster-cleanup
test-cluster-cleanup: ## Clean up test namespaces and CSRs from cluster
	@echo "=== Cleaning up test namespaces ==="
	@for ns in keyfactor-k8sjks-integration-tests keyfactor-k8spkcs12-integration-tests \
		keyfactor-k8ssecret-integration-tests keyfactor-k8stlssecr-integration-tests \
		keyfactor-k8scluster-test-ns1 keyfactor-k8scluster-test-ns2 \
		keyfactor-k8sns-integration-tests keyfactor-k8scert-integration-tests \
		keyfactor-manual-test; do \
		if kubectl get namespace $$ns 2>/dev/null; then \
			echo "Deleting namespace $$ns..."; \
			kubectl delete namespace $$ns; \
		else \
			echo "Namespace $$ns does not exist, skipping"; \
		fi; \
	done
	@echo "=== Cleaning up test CSRs ==="
	@kubectl get csr --no-headers 2>/dev/null | grep "test-" | awk '{print $$1}' | \
		while read csr; do \
			echo "Deleting CSR $$csr..."; \
			kubectl delete csr $$csr 2>/dev/null || true; \
		done || echo "No test CSRs found"
	@echo "Cleanup complete"

.PHONY: test-store-type
test-store-type: ## Run integration tests for a single store type with cleanup (usage: make test-store-type STORE=K8SSecret)
	@if [ -z "$(STORE)" ]; then \
		echo "ERROR: STORE parameter required"; \
		echo "Usage: make test-store-type STORE=<store-type>"; \
		echo ""; \
		echo "Available store types:"; \
		echo "  K8SSecret      - Opaque secrets"; \
		echo "  K8STLSSecr     - TLS secrets"; \
		echo "  K8SJKS         - Java Keystores"; \
		echo "  K8SPKCS12      - PKCS12/PFX files"; \
		echo "  K8SCluster     - Cluster-wide management"; \
		echo "  K8SNS          - Namespace-level management"; \
		echo "  K8SCert        - Certificate Signing Requests"; \
		exit 1; \
	fi
	@echo "=== Running tests for $(STORE) store type ==="
	@$(MAKE) test-cluster-cleanup
	@source .env; \
	source .test.env; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test \
		--filter "FullyQualifiedName~$(STORE)StoreIntegrationTests" \
		--logger "console;verbosity=normal"

.PHONY: test-integration-no-cleanup
test-integration-no-cleanup: ## Run integration tests without cleanup (leaves secrets for manual inspection)
	@source .env; \
	source .test.env; \
	export RUN_INTEGRATION_TESTS=true; \
	export SKIP_INTEGRATION_TEST_CLEANUP=true; \
	if [ -n "$$INTEGRATION_TEST_KUBECONFIG" ]; then \
		export INTEGRATION_TEST_KUBECONFIG; \
	fi; \
	dotnet test --filter "FullyQualifiedName~Integration"

.PHONY: test-all-with-cleanup
test-all-with-cleanup: ## Run all tests (unit + integration) with cleanup before and after
	@echo "=== Pre-test cleanup ==="
	@$(MAKE) test-cluster-cleanup
	@echo ""
	@echo "=== Running unit tests ==="
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	dotnet test --filter "FullyQualifiedName!~Integration" --logger "console;verbosity=minimal"
	@echo ""
	@echo "=== Running integration tests ==="
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	if [ -n "$$INTEGRATION_TEST_KUBECONFIG" ]; then \
		export INTEGRATION_TEST_KUBECONFIG; \
	fi; \
	dotnet test --filter "FullyQualifiedName~Integration" --logger "console;verbosity=minimal"
	@echo ""
	@echo "=== Post-test cleanup ==="
	@$(MAKE) test-cluster-cleanup
	@echo ""
	@echo "=== All tests complete ==="

##@ Build

.PHONY: build
build: ## Build the test project
	dotnet build 
