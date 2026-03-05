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
test-integration: test-cluster-cleanup ## Run integration tests only (requires RUN_INTEGRATION_TESTS=true)
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	if [ -n "$$INTEGRATION_TEST_KUBECONFIG" ]; then \
		export INTEGRATION_TEST_KUBECONFIG; \
	fi; \
	dotnet test --filter "FullyQualifiedName~Integration"

.PHONY: test-integration-fast
test-integration-fast: test-cluster-cleanup ## Run integration tests on single framework (net8.0 only, ~50% faster)
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	if [ -n "$$INTEGRATION_TEST_KUBECONFIG" ]; then \
		export INTEGRATION_TEST_KUBECONFIG; \
	fi; \
	dotnet test -f net8.0 --filter "FullyQualifiedName~Integration"

.PHONY: test-integration-full
test-integration-full: test-cluster-cleanup ## Run integration tests on all frameworks (net8.0 + net10.0)
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

.PHONY: test-setup
test-setup: test-cluster-cleanup ## Set up test environment (clean + create CSRs for K8SCert tests)
	@echo "=== Setting up test environment ==="
	@echo "Creating CSRs with certificates for K8SCert tests..."
	@$(MAKE) csr-create-batch-with-chain COUNT=3
	@echo "Test environment ready"

.PHONY: test-coverage
test-coverage: test-setup ## Run all tests with code coverage and generate HTML report
	@echo "Running all tests with coverage..."; \
	source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	rm -rf ./coverage; \
	dotnet test \
		--framework net8.0 \
		--collect:"XPlat Code Coverage" \
		--results-directory ./coverage \
		-- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=cobertura; \
	echo "Generating HTML coverage report..."; \
	~/.dotnet/tools/reportgenerator \
		"-reports:./coverage/*/coverage.cobertura.xml" \
		"-targetdir:./coverage/html" \
		"-reporttypes:Html;MarkdownSummary" 2>/dev/null || \
	reportgenerator \
		"-reports:./coverage/*/coverage.cobertura.xml" \
		"-targetdir:./coverage/html" \
		"-reporttypes:Html;MarkdownSummary"; \
	echo "Coverage report generated at ./coverage/html/index.html"

.PHONY: test-coverage-install
test-coverage-install: ## Install reportgenerator tool for coverage reports
	@dotnet tool install --global dotnet-reportgenerator-globaltool 2>/dev/null || \
		dotnet tool update --global dotnet-reportgenerator-globaltool 2>/dev/null || \
		echo "reportgenerator already installed"

.PHONY: test-coverage-unit
test-coverage-unit: ## Run unit tests only with code coverage
	@echo "Running unit tests with coverage..."; \
	rm -rf ./coverage/unit; \
	dotnet test \
		--framework net8.0 \
		--filter "Category!=Integration" \
		--collect:"XPlat Code Coverage" \
		--results-directory ./coverage/unit \
		-- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=cobertura; \
	echo "Generating HTML coverage report..."; \
	~/.dotnet/tools/reportgenerator \
		"-reports:./coverage/unit/*/coverage.cobertura.xml" \
		"-targetdir:./coverage/unit/html" \
		"-reporttypes:Html;MarkdownSummary" 2>/dev/null || \
	reportgenerator \
		"-reports:./coverage/unit/*/coverage.cobertura.xml" \
		"-targetdir:./coverage/unit/html" \
		"-reporttypes:Html;MarkdownSummary"; \
	echo "Unit test coverage report generated at ./coverage/unit/html/index.html"

.PHONY: test-coverage-summary
test-coverage-summary: ## Show coverage summary in terminal (requires test-coverage-unit first)
	@if [ -f ./coverage/unit/html/Summary.md ]; then \
		cat ./coverage/unit/html/Summary.md; \
	else \
		echo "No coverage summary found. Run 'make test-coverage-unit' first."; \
	fi

.PHONY: test-coverage-open
test-coverage-open: ## Open coverage HTML report in browser (macOS)
	@if [ -f ./coverage/html/index.html ]; then \
		open ./coverage/html/index.html; \
	elif [ -f ./coverage/unit/html/index.html ]; then \
		open ./coverage/unit/html/index.html; \
	else \
		echo "No coverage report found. Run 'make test-coverage' or 'make test-coverage-unit' first."; \
	fi

.PHONY: test-coverage-clean
test-coverage-clean: ## Remove coverage reports
	@rm -rf ./coverage
	@echo "Coverage reports removed."

.PHONY: coverage-summary
coverage-summary: ## Show coverage summary sorted by uncovered lines (unit coverage)
	@python3 scripts/analyze-coverage.py --summary

.PHONY: coverage-summary-all
coverage-summary-all: ## Show combined (unit+integration) coverage summary sorted by uncovered lines
	@python3 scripts/analyze-coverage.py --summary --dir ./coverage

.PHONY: coverage-uncovered
coverage-uncovered: ## Show uncovered lines for a class (usage: make coverage-uncovered CLASS=CertificateUtilities)
	@python3 scripts/analyze-coverage.py --uncovered $(CLASS)

.PHONY: coverage-uncovered-all
coverage-uncovered-all: ## Show uncovered lines from combined coverage (usage: make coverage-uncovered-all CLASS=JobBase)
	@python3 scripts/analyze-coverage.py --uncovered $(CLASS) --dir ./coverage

.PHONY: test-watch
test-watch: ## Run tests in watch mode (auto-rerun on file changes)
	@source .env; \
	source .test.env; \
	dotnet watch test

.PHONY: test-single
test-single: ## Run a single integration test by filter (usage: make test-single FILTER=Inventory_OpaqueSecretWithCertificate)
	@if [ -z "$(FILTER)" ]; then \
		echo "ERROR: FILTER parameter required"; \
		echo "Usage: make test-single FILTER=<test-name-pattern>"; \
		echo "Example: make test-single FILTER=Inventory_OpaqueSecretWithCertificate"; \
		exit 1; \
	fi
	@echo "=== Cleaning build artifacts ==="
	@rm -rf */bin */obj
	@echo "=== Running test matching '$(FILTER)' ==="
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~$(FILTER)" --verbosity normal 2>&1 | tail -60

.PHONY: test-store-jks
test-store-jks: test-cluster-cleanup ## Run K8SJKS store type integration tests
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8SJKSStoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-store-pkcs12
test-store-pkcs12: test-cluster-cleanup ## Run K8SPKCS12 store type integration tests
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8SPKCS12StoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-store-secret
test-store-secret: test-cluster-cleanup ## Run K8SSecret store type integration tests
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8SSecretStoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-store-tls
test-store-tls: test-cluster-cleanup ## Run K8STLSSecr store type integration tests
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8STLSSecrStoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-store-cluster
test-store-cluster: test-cluster-cleanup ## Run K8SCluster store type integration tests
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8SClusterStoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-store-ns
test-store-ns: test-cluster-cleanup ## Run K8SNS store type integration tests
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8SNSStoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-store-cert
test-store-cert: test-cluster-cleanup ## Run K8SCert store type integration tests
	@source .env 2>/dev/null || true; \
	source .test.env 2>/dev/null || true; \
	export RUN_INTEGRATION_TESTS=true; \
	dotnet test --filter "FullyQualifiedName~K8SCertStoreIntegrationTests" --logger "console;verbosity=minimal"

.PHONY: test-handlers
test-handlers: ## Run handler unit tests
	@dotnet test --filter "FullyQualifiedName~Handler" --logger "console;verbosity=minimal"

.PHONY: test-base-jobs
test-base-jobs: ## Run base job class unit tests
	@dotnet test --filter "FullyQualifiedName~Jobs.Base" --logger "console;verbosity=minimal"

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
	@# Clean up framework-specific namespaces (net8, net10) and legacy namespaces
	@for ns in keyfactor-k8sjks-integration-tests keyfactor-k8sjks-integration-tests-net8 keyfactor-k8sjks-integration-tests-net10 \
		keyfactor-k8spkcs12-integration-tests keyfactor-k8spkcs12-integration-tests-net8 keyfactor-k8spkcs12-integration-tests-net10 \
		keyfactor-k8ssecret-integration-tests keyfactor-k8ssecret-integration-tests-net8 keyfactor-k8ssecret-integration-tests-net10 \
		keyfactor-k8stlssecr-integration-tests keyfactor-k8stlssecr-integration-tests-net8 keyfactor-k8stlssecr-integration-tests-net10 \
		keyfactor-k8scluster-test-ns1 keyfactor-k8scluster-test-ns1-net8 keyfactor-k8scluster-test-ns1-net10 \
		keyfactor-k8scluster-test-ns2 keyfactor-k8scluster-test-ns2-net8 keyfactor-k8scluster-test-ns2-net10 \
		keyfactor-k8sns-integration-tests keyfactor-k8sns-integration-tests-net8 keyfactor-k8sns-integration-tests-net10 \
		keyfactor-k8scert-integration-tests keyfactor-k8scert-integration-tests-net8 keyfactor-k8scert-integration-tests-net10 \
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

##@ Debugging (Container-based testing with Keyfactor Command)

# Configuration - override with environment variables or command line
DEBUG_ENV_FILE ?= ~/.env_ses2541
DEBUG_CONTAINER_DIR ?= ~/Desktop/Container
DEBUG_COMPOSE_FILE ?= docker-compose-ses.yml
DEBUG_SERVICE_NAME ?= ses_2541_uo_25_4_oauth
DEBUG_TLS_STORE_ID ?= e523b800-fe18-4e68-b7be-8f2034ffdc16
DEBUG_OPAQUE_STORE_ID ?= 27b16153-742c-4b4c-9b2d-02ec9cc90fa5
# PfxPassword must be 12+ alphanumeric characters per Command policy
DEBUG_PFX_PASSWORD ?= 3ceZRxdQffny
DEBUG_CERT_ID ?= 44
DEBUG_CERT_THUMBPRINT ?= FA3BFCD6966AC297B1A3AA9FA43EB1C55EE1048B

# Test certificates
# Cert 43: Has private key + chain (meow, issued by Sub-CA)
DEBUG_CERT_43_ID := 43
DEBUG_CERT_43_THUMBPRINT := F3127840482241A1251498545A598C6D765BA03E
# Cert 44: No private key, DER format (ec-csr, issued by Sub-CA)
DEBUG_CERT_44_ID := 44
DEBUG_CERT_44_THUMBPRINT := FA3BFCD6966AC297B1A3AA9FA43EB1C55EE1048B

.PHONY: debug-build
debug-build: ## Build extension and verify DLL is in container folder
	@echo "=== Building extension ==="
	@dotnet build kubernetes-orchestrator-extension/Keyfactor.Orchestrators.K8S.csproj
	@echo ""
	@echo "=== Verifying DLL in container folder ==="
	@ls -la $(DEBUG_CONTAINER_DIR)/extensions/K8S/Local/net10.0/Keyfactor.Orchestrators.K8S.dll 2>/dev/null || \
		echo "WARNING: DLL not found in container folder. You may need to set up a symlink."

.PHONY: debug-container-id
debug-container-id: ## Get the current container ID
	@docker ps --filter "name=ses" --format "{{.ID}}" | head -1

.PHONY: debug-restart
debug-restart: ## Restart the orchestrator container
	@echo "=== Restarting container ==="
	@source $(DEBUG_ENV_FILE) && cd $(DEBUG_CONTAINER_DIR) && docker compose -f $(DEBUG_COMPOSE_FILE) down $(DEBUG_SERVICE_NAME) 2>/dev/null || true
	@source $(DEBUG_ENV_FILE) && cd $(DEBUG_CONTAINER_DIR) && docker compose -f $(DEBUG_COMPOSE_FILE) up -d $(DEBUG_SERVICE_NAME)
	@echo "Waiting for container to start..."
	@sleep 5
	@echo "Container ID: $$(docker ps --filter "name=ses" --format "{{.ID}}" | head -1)"

.PHONY: debug-logs
debug-logs: ## Show recent container logs (last 100 lines)
	@CONTAINER_ID=$$(docker ps --filter "name=ses" --format "{{.ID}}" | head -1); \
	if [ -z "$$CONTAINER_ID" ]; then \
		echo "ERROR: No running container found"; \
		exit 1; \
	fi; \
	docker logs --tail 100 $$CONTAINER_ID

.PHONY: debug-logs-follow
debug-logs-follow: ## Follow container logs in real-time
	@CONTAINER_ID=$$(docker ps --filter "name=ses" --format "{{.ID}}" | head -1); \
	if [ -z "$$CONTAINER_ID" ]; then \
		echo "ERROR: No running container found"; \
		exit 1; \
	fi; \
	docker logs -f $$CONTAINER_ID

.PHONY: debug-get-token
debug-get-token: ## Get OAuth token from Keyfactor (uses cache, outputs token to stdout)
	@$(MAKE) -s token-get

.PHONY: debug-schedule-tls
debug-schedule-tls: ## Schedule a management job for TLS secret store
	@echo "=== Scheduling TLS secret management job ==="
	@TOKEN=$$($(MAKE) -s token-get); \
	if [ "$$TOKEN" = "null" ] || [ -z "$$TOKEN" ]; then \
		echo "ERROR: Failed to get token" >&2; \
		exit 1; \
	fi; \
	source $(DEBUG_ENV_FILE); \
	RESULT=$$(curl -s --insecure -X POST "https://$$KEYFACTOR_HOSTNAME/$$KEYFACTOR_API_PATH/CertificateStores/Certificates/Add" \
		-H "Authorization: Bearer $$TOKEN" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "Content-Type: application/json" \
		-d '{"CertificateId": $(DEBUG_CERT_ID), "CertificateStores": [{"CertificateStoreId": "$(DEBUG_TLS_STORE_ID)", "Alias": "$(DEBUG_CERT_THUMBPRINT)", "Overwrite": true, "JobFields": {}}], "Schedule": {"Immediate": true}}'); \
	echo "$$RESULT" | jq -r 'if type == "array" then "Job scheduled: " + .[0] else "Error: " + .Message end'

.PHONY: debug-schedule-opaque
debug-schedule-opaque: ## Schedule a management job for Opaque secret store
	@echo "=== Scheduling Opaque secret management job ==="
	@TOKEN=$$($(MAKE) -s token-get); \
	if [ "$$TOKEN" = "null" ] || [ -z "$$TOKEN" ]; then \
		echo "ERROR: Failed to get token" >&2; \
		exit 1; \
	fi; \
	source $(DEBUG_ENV_FILE); \
	RESULT=$$(curl -s --insecure -X POST "https://$$KEYFACTOR_HOSTNAME/$$KEYFACTOR_API_PATH/CertificateStores/Certificates/Add" \
		-H "Authorization: Bearer $$TOKEN" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "Content-Type: application/json" \
		-d '{"CertificateId": $(DEBUG_CERT_ID), "CertificateStores": [{"CertificateStoreId": "$(DEBUG_OPAQUE_STORE_ID)", "Alias": "$(DEBUG_CERT_THUMBPRINT)", "Overwrite": true, "JobFields": {}}], "Schedule": {"Immediate": true}}'); \
	echo "$$RESULT" | jq -r 'if type == "array" then "Job scheduled: " + .[0] else "Error: " + .Message end'

.PHONY: debug-schedule-both
debug-schedule-both: ## Schedule management jobs for both TLS and Opaque stores
	@$(MAKE) debug-schedule-tls
	@$(MAKE) debug-schedule-opaque

.PHONY: debug-check-tls-secret
debug-check-tls-secret: ## Check the TLS secret in Kubernetes
	@echo "=== TLS Secret (manual-tlssecr) ==="
	@kubectl get secret manual-tlssecr -n default -o yaml | grep -E "^  (tls\.|ca\.)" | while read line; do \
		key=$$(echo "$$line" | cut -d: -f1 | tr -d ' '); \
		value=$$(echo "$$line" | cut -d: -f2- | tr -d ' '); \
		if [ -z "$$value" ] || [ "$$value" = '""' ]; then \
			echo "$$key: (empty)"; \
		else \
			decoded=$$(echo "$$value" | base64 -d 2>/dev/null | head -1); \
			echo "$$key: $$decoded..."; \
		fi; \
	done

.PHONY: debug-check-opaque-secret
debug-check-opaque-secret: ## Check the Opaque secret in Kubernetes
	@echo "=== Opaque Secret (manual-opaque) ==="
	@kubectl get secret manual-opaque -n default -o yaml | grep -E "^  [a-zA-Z]" | head -10

.PHONY: debug-check-secrets
debug-check-secrets: ## Check both TLS and Opaque secrets
	@$(MAKE) debug-check-tls-secret
	@echo ""
	@$(MAKE) debug-check-opaque-secret

.PHONY: debug-wait-job
debug-wait-job: ## Wait for jobs to complete (polls logs for completion message)
	@echo "=== Waiting for job completion ==="
	@CONTAINER_ID=$$(docker ps --filter "name=ses" --format "{{.ID}}" | head -1); \
	for i in 1 2 3 4 5 6 7 8 9 10; do \
		if docker logs --tail 20 $$CONTAINER_ID 2>&1 | grep -q "End MANAGEMENT job.*Success"; then \
			echo "Job completed successfully!"; \
			exit 0; \
		fi; \
		echo "Waiting... ($$i/10)"; \
		sleep 2; \
	done; \
	echo "Timeout waiting for job completion"

.PHONY: debug-loop
debug-loop: ## Full debug loop: build, restart, schedule TLS job, wait, check logs and secret
	@echo "=========================================="
	@echo "=== Starting Debug Loop ==="
	@echo "=========================================="
	@$(MAKE) debug-build
	@echo ""
	@$(MAKE) debug-restart
	@echo ""
	@echo "=== Scheduling job ==="
	@$(MAKE) debug-schedule-tls
	@echo ""
	@$(MAKE) debug-wait-job
	@echo ""
	@echo "=== Container Logs (last 50 lines) ==="
	@CONTAINER_ID=$$(docker ps --filter "name=ses" --format "{{.ID}}" | head -1); \
	docker logs --tail 50 $$CONTAINER_ID 2>&1 | grep -E "(InitJobCertificate|DER|PEM|Certificate data|NO PASSWORD|JobCertificate|MANAGEMENT)"
	@echo ""
	@$(MAKE) debug-check-tls-secret
	@echo ""
	@echo "=========================================="
	@echo "=== Debug Loop Complete ==="
	@echo "=========================================="

.PHONY: debug-loop-both
debug-loop-both: ## Full debug loop for both TLS and Opaque stores
	@echo "=========================================="
	@echo "=== Starting Debug Loop (Both Stores) ==="
	@echo "=========================================="
	@$(MAKE) debug-build
	@echo ""
	@$(MAKE) debug-restart
	@echo ""
	@echo "=== Scheduling jobs ==="
	@$(MAKE) debug-schedule-both
	@echo ""
	@$(MAKE) debug-wait-job
	@sleep 2
	@echo ""
	@echo "=== Container Logs (filtered) ==="
	@CONTAINER_ID=$$(docker ps --filter "name=ses" --format "{{.ID}}" | head -1); \
	docker logs --tail 80 $$CONTAINER_ID 2>&1 | grep -E "(InitJobCertificate|DER|PEM|Certificate data|NO PASSWORD|JobCertificate|MANAGEMENT|properties)"
	@echo ""
	@$(MAKE) debug-check-secrets
	@echo ""
	@echo "=========================================="
	@echo "=== Debug Loop Complete ==="
	@echo "=========================================="

.PHONY: debug-schedule-tls-cert
debug-schedule-tls-cert: ## Schedule TLS job with specific cert (usage: make debug-schedule-tls-cert CERT_ID=43 [PFX_PASSWORD=xxx])
	@if [ -z "$(CERT_ID)" ]; then \
		echo "ERROR: CERT_ID required"; \
		echo "Usage: make debug-schedule-tls-cert CERT_ID=43"; \
		echo "       make debug-schedule-tls-cert CERT_ID=43 PFX_PASSWORD=mypassword"; \
		exit 1; \
	fi
	@echo "=== Scheduling TLS job for cert $(CERT_ID) (IncludePrivateKey=true) ==="
	@TOKEN=$$($(MAKE) -s token-get); \
	if [ "$$TOKEN" = "null" ] || [ -z "$$TOKEN" ]; then \
		echo "ERROR: Failed to get token" >&2; \
		exit 1; \
	fi; \
	source $(DEBUG_ENV_FILE); \
	PFX_PASS="$(if $(PFX_PASSWORD),$(PFX_PASSWORD),$(DEBUG_PFX_PASSWORD))"; \
	BODY='{"CertificateId": $(CERT_ID), "CertificateStores": [{"CertificateStoreId": "$(DEBUG_TLS_STORE_ID)", "IncludePrivateKey": true, "PfxPassword": "'$$PFX_PASS'", "JobFields": {}}], "Schedule": {"Immediate": true}}'; \
	RESULT=$$(curl -s --insecure -X POST "https://$$KEYFACTOR_HOSTNAME/$$KEYFACTOR_API_PATH/CertificateStores/Certificates/Add" \
		-H "Authorization: Bearer $$TOKEN" \
		-H "x-keyfactor-requested-with: APIClient" \
		-H "Content-Type: application/json" \
		-d "$$BODY"); \
	echo "$$RESULT" | jq -r 'if type == "array" then "Job scheduled: " + .[0] else "Error: " + .Message end'

.PHONY: debug-loop-cert43
debug-loop-cert43: ## Full debug loop with cert 43 (has private key + chain in Command)
	@echo "=========================================="
	@echo "=== Debug Loop - Cert 43 (with key+chain) ==="
	@echo "=========================================="
	@$(MAKE) debug-build
	@echo ""
	@$(MAKE) debug-restart
	@echo ""
	@echo "=== Scheduling job for cert 43 ==="
	@$(MAKE) debug-schedule-tls-cert CERT_ID=$(DEBUG_CERT_43_ID)
	@echo ""
	@$(MAKE) debug-wait-job
	@sleep 3
	@echo ""
	@echo "=== Container Logs (filtered) ==="
	@CONTAINER_ID=$$(docker ps --filter "name=ses" --format "{{.ID}}" | head -1); \
	docker logs --tail 80 $$CONTAINER_ID 2>&1 | grep -E "(InitJobCertificate|DER|PEM|Certificate|NO PASSWORD|JobCertificate|MANAGEMENT|properties|ContentsFormat|chain|bytes)"
	@echo ""
	@$(MAKE) debug-check-tls-secret
	@echo ""
	@echo "=========================================="
	@echo "=== Debug Loop Complete ==="
	@echo "=========================================="

.PHONY: debug-loop-cert44
debug-loop-cert44: ## Full debug loop with cert 44 (no private key, DER format)
	@echo "=========================================="
	@echo "=== Debug Loop - Cert 44 (no key, DER) ==="
	@echo "=========================================="
	@$(MAKE) debug-build
	@echo ""
	@$(MAKE) debug-restart
	@echo ""
	@echo "=== Scheduling job for cert 44 ==="
	@$(MAKE) debug-schedule-tls-cert CERT_ID=$(DEBUG_CERT_44_ID)
	@echo ""
	@$(MAKE) debug-wait-job
	@sleep 3
	@echo ""
	@echo "=== Container Logs (filtered) ==="
	@CONTAINER_ID=$$(docker ps --filter "name=ses" --format "{{.ID}}" | head -1); \
	docker logs --tail 80 $$CONTAINER_ID 2>&1 | grep -E "(InitJobCertificate|DER|PEM|Certificate|NO PASSWORD|JobCertificate|MANAGEMENT|properties|ContentsFormat|chain|bytes)"
	@echo ""
	@$(MAKE) debug-check-tls-secret
	@echo ""
	@echo "=========================================="
	@echo "=== Debug Loop Complete ==="
	@echo "=========================================="

.PHONY: debug-get-cert-info
debug-get-cert-info: ## Get certificate info from Command (usage: make debug-get-cert-info CERT_ID=43)
	@if [ -z "$(CERT_ID)" ]; then \
		echo "ERROR: CERT_ID required"; \
		echo "Usage: make debug-get-cert-info CERT_ID=43"; \
		exit 1; \
	fi
	@TOKEN=$$($(MAKE) -s token-get); \
	if [ "$$TOKEN" = "null" ] || [ -z "$$TOKEN" ]; then \
		echo "ERROR: Failed to get token" >&2; \
		exit 1; \
	fi; \
	source $(DEBUG_ENV_FILE); \
	curl -s --insecure "https://$$KEYFACTOR_HOSTNAME/$$KEYFACTOR_API_PATH/Certificates/$(CERT_ID)" \
		-H "Authorization: Bearer $$TOKEN" \
		-H "x-keyfactor-requested-with: APIClient" | \
		jq '{Id, Thumbprint, IssuedCN, HasPrivateKey, IssuerDN, KeyType: .KeyTypeString}'

##@ OAuth Token Management

# Token cache file and expiry (tokens valid for 55 minutes, refresh at 50 min)
TOKEN_FILE := .oauth_token
TOKEN_EXPIRY_FILE := .oauth_token_expiry
TOKEN_VALIDITY_SECONDS := 3000

.PHONY: token
token: ## Get OAuth token (uses cache if valid, otherwise fetches new)
	@if [ -f "$(TOKEN_FILE)" ] && [ -f "$(TOKEN_EXPIRY_FILE)" ]; then \
		EXPIRY=$$(cat $(TOKEN_EXPIRY_FILE)); \
		NOW=$$(date +%s); \
		if [ "$$NOW" -lt "$$EXPIRY" ]; then \
			echo "Using cached token (expires in $$(( ($$EXPIRY - $$NOW) / 60 )) minutes)"; \
			cat $(TOKEN_FILE); \
			exit 0; \
		fi; \
	fi; \
	$(MAKE) token-refresh

.PHONY: token-refresh
token-refresh: ## Force refresh OAuth token and cache to disk
	@echo "Fetching new OAuth token..."
	@source $(DEBUG_ENV_FILE); \
	TOKEN=$$(curl -s --insecure -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET&scope=openid" | \
		jq -r '.access_token'); \
	if [ "$$TOKEN" = "null" ] || [ -z "$$TOKEN" ]; then \
		echo "ERROR: Failed to get OAuth token" >&2; \
		exit 1; \
	fi; \
	echo "$$TOKEN" > $(TOKEN_FILE); \
	echo $$(( $$(date +%s) + $(TOKEN_VALIDITY_SECONDS) )) > $(TOKEN_EXPIRY_FILE); \
	echo "Token cached to $(TOKEN_FILE) (valid for $(TOKEN_VALIDITY_SECONDS) seconds)"; \
	echo "$$TOKEN"

.PHONY: token-show
token-show: ## Show cached token info (without exposing full token)
	@if [ -f "$(TOKEN_FILE)" ] && [ -f "$(TOKEN_EXPIRY_FILE)" ]; then \
		TOKEN=$$(cat $(TOKEN_FILE)); \
		EXPIRY=$$(cat $(TOKEN_EXPIRY_FILE)); \
		NOW=$$(date +%s); \
		if [ "$$NOW" -lt "$$EXPIRY" ]; then \
			echo "Token status: VALID"; \
			echo "Expires in: $$(( ($$EXPIRY - $$NOW) / 60 )) minutes"; \
			echo "Token preview: $${TOKEN:0:20}..."; \
		else \
			echo "Token status: EXPIRED"; \
			echo "Expired: $$(( ($$NOW - $$EXPIRY) / 60 )) minutes ago"; \
		fi; \
	else \
		echo "Token status: NOT CACHED"; \
		echo "Run 'make token' to fetch a new token"; \
	fi

.PHONY: token-clear
token-clear: ## Clear cached OAuth token
	@rm -f $(TOKEN_FILE) $(TOKEN_EXPIRY_FILE)
	@echo "Token cache cleared"

# Helper function to get token (for use in other targets)
# Usage: TOKEN=$$($(MAKE) -s token-get)
.PHONY: token-get
token-get: ## Get token silently (for use in scripts)
	@if [ -f "$(TOKEN_FILE)" ] && [ -f "$(TOKEN_EXPIRY_FILE)" ]; then \
		EXPIRY=$$(cat $(TOKEN_EXPIRY_FILE)); \
		NOW=$$(date +%s); \
		if [ "$$NOW" -lt "$$EXPIRY" ]; then \
			cat $(TOKEN_FILE); \
			exit 0; \
		fi; \
	fi; \
	source $(DEBUG_ENV_FILE); \
	TOKEN=$$(curl -s --insecure -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET&scope=openid" | \
		jq -r '.access_token'); \
	if [ "$$TOKEN" != "null" ] && [ -n "$$TOKEN" ]; then \
		echo "$$TOKEN" > $(TOKEN_FILE); \
		echo $$(( $$(date +%s) + $(TOKEN_VALIDITY_SECONDS) )) > $(TOKEN_EXPIRY_FILE); \
	fi; \
	echo "$$TOKEN"

##@ Keyfactor Command API

.PHONY: api-list-stores
api-list-stores: ## List certificate stores from Command
	@TOKEN=$$($(MAKE) -s token-get); \
	if [ "$$TOKEN" = "null" ] || [ -z "$$TOKEN" ]; then \
		echo "ERROR: Failed to get token" >&2; \
		exit 1; \
	fi; \
	source $(DEBUG_ENV_FILE); \
	curl -s --insecure "https://$$KEYFACTOR_HOSTNAME/$$KEYFACTOR_API_PATH/CertificateStores" \
		-H "Authorization: Bearer $$TOKEN" \
		-H "x-keyfactor-requested-with: APIClient" | \
		jq -r '.[] | "\(.Id) | \(.ClientMachine) | \(.StorePath)"'

.PHONY: api-list-certs
api-list-certs: ## List certificates from Command (first 20)
	@TOKEN=$$($(MAKE) -s token-get); \
	if [ "$$TOKEN" = "null" ] || [ -z "$$TOKEN" ]; then \
		echo "ERROR: Failed to get token" >&2; \
		exit 1; \
	fi; \
	source $(DEBUG_ENV_FILE); \
	curl -s --insecure "https://$$KEYFACTOR_HOSTNAME/$$KEYFACTOR_API_PATH/Certificates?pq.pageReturned=1&pq.returnLimit=20" \
		-H "Authorization: Bearer $$TOKEN" \
		-H "x-keyfactor-requested-with: APIClient" | \
		jq -r '.[] | "\(.Id) | \(.IssuedCN) | \(.Thumbprint) | HasKey=\(.HasPrivateKey)"'

.PHONY: api-get-cert
api-get-cert: ## Get certificate details (usage: make api-get-cert CERT_ID=43)
	@if [ -z "$(CERT_ID)" ]; then \
		echo "ERROR: CERT_ID required"; \
		echo "Usage: make api-get-cert CERT_ID=43"; \
		exit 1; \
	fi; \
	TOKEN=$$($(MAKE) -s token-get); \
	if [ "$$TOKEN" = "null" ] || [ -z "$$TOKEN" ]; then \
		echo "ERROR: Failed to get token" >&2; \
		exit 1; \
	fi; \
	source $(DEBUG_ENV_FILE); \
	curl -s --insecure "https://$$KEYFACTOR_HOSTNAME/$$KEYFACTOR_API_PATH/Certificates/$(CERT_ID)" \
		-H "Authorization: Bearer $$TOKEN" \
		-H "x-keyfactor-requested-with: APIClient" | \
		jq '{Id, Thumbprint, IssuedCN, HasPrivateKey, IssuerDN, KeyType: .KeyTypeString, NotBefore, NotAfter}'

.PHONY: api-get-jobs
api-get-jobs: ## Get recent orchestrator jobs (last 10)
	@TOKEN=$$($(MAKE) -s token-get); \
	if [ "$$TOKEN" = "null" ] || [ -z "$$TOKEN" ]; then \
		echo "ERROR: Failed to get token" >&2; \
		exit 1; \
	fi; \
	source $(DEBUG_ENV_FILE); \
	curl -s --insecure "https://$$KEYFACTOR_HOSTNAME/$$KEYFACTOR_API_PATH/OrchestratorJobs/ScheduledJobs?pq.pageReturned=1&pq.returnLimit=10&pq.sortAscending=0" \
		-H "Authorization: Bearer $$TOKEN" \
		-H "x-keyfactor-requested-with: APIClient" | \
		jq -r '.[] | "\(.JobId) | \(.JobTypeName) | \(.Status) | \(.Requested)"'

##@ Kubernetes CSR Management (for K8SCert testing)

.PHONY: csr-create
csr-create: ## Create a test CSR (usage: make csr-create [NAME=my-csr] [CN=test-cert])
	@NAME=$${NAME:-test-csr-$$(date +%s)}; \
	CN=$${CN:-test-certificate}; \
	TMPDIR=$$(mktemp -d); \
	echo "=== Creating CSR: $$NAME (CN=$$CN) ==="; \
	openssl genrsa -out $$TMPDIR/key.pem 2048 2>/dev/null; \
	openssl req -new -key $$TMPDIR/key.pem -out $$TMPDIR/csr.pem -subj "/CN=$$CN" 2>/dev/null; \
	CSR_BASE64=$$(cat $$TMPDIR/csr.pem | base64 | tr -d '\n'); \
	printf 'apiVersion: certificates.k8s.io/v1\nkind: CertificateSigningRequest\nmetadata:\n  name: %s\nspec:\n  request: %s\n  signerName: kubernetes.io/kube-apiserver-client\n  usages:\n  - client auth\n' "$$NAME" "$$CSR_BASE64" | kubectl apply -f -; \
	rm -rf $$TMPDIR; \
	echo "CSR created: $$NAME"; \
	echo "To approve: make csr-approve NAME=$$NAME"; \
	echo "To view:    kubectl get csr $$NAME"

.PHONY: csr-create-approved
csr-create-approved: ## Create and approve a test CSR (usage: make csr-create-approved [NAME=my-csr])
	@NAME=$${NAME:-test-csr-$$(date +%s)}; \
	$(MAKE) csr-create NAME=$$NAME; \
	sleep 1; \
	$(MAKE) csr-approve NAME=$$NAME

.PHONY: csr-approve
csr-approve: ## Approve a CSR (usage: make csr-approve NAME=my-csr)
	@if [ -z "$(NAME)" ]; then \
		echo "ERROR: NAME required"; \
		echo "Usage: make csr-approve NAME=my-csr"; \
		exit 1; \
	fi
	@echo "=== Approving CSR: $(NAME) ==="
	@kubectl certificate approve $(NAME)
	@echo "CSR approved"

.PHONY: csr-deny
csr-deny: ## Deny a CSR (usage: make csr-deny NAME=my-csr)
	@if [ -z "$(NAME)" ]; then \
		echo "ERROR: NAME required"; \
		echo "Usage: make csr-deny NAME=my-csr"; \
		exit 1; \
	fi
	@echo "=== Denying CSR: $(NAME) ==="
	@kubectl certificate deny $(NAME)
	@echo "CSR denied"

.PHONY: csr-list
csr-list: ## List all CSRs in the cluster
	@echo "=== Certificate Signing Requests ==="
	@kubectl get csr -o wide

.PHONY: csr-list-test
csr-list-test: ## List only test CSRs (prefixed with test-)
	@echo "=== Test CSRs ==="
	@kubectl get csr -o wide | grep -E "^NAME|^test-" || echo "No test CSRs found"

.PHONY: csr-describe
csr-describe: ## Describe a CSR (usage: make csr-describe NAME=my-csr)
	@if [ -z "$(NAME)" ]; then \
		echo "ERROR: NAME required"; \
		echo "Usage: make csr-describe NAME=my-csr"; \
		exit 1; \
	fi
	@kubectl describe csr $(NAME)

.PHONY: csr-delete
csr-delete: ## Delete a CSR (usage: make csr-delete NAME=my-csr)
	@if [ -z "$(NAME)" ]; then \
		echo "ERROR: NAME required"; \
		echo "Usage: make csr-delete NAME=my-csr"; \
		exit 1; \
	fi
	@echo "=== Deleting CSR: $(NAME) ==="
	@kubectl delete csr $(NAME)
	@echo "CSR deleted"

.PHONY: csr-cleanup
csr-cleanup: ## Delete all test CSRs (prefixed with test-)
	@echo "=== Cleaning up test CSRs ==="
	@kubectl get csr --no-headers 2>/dev/null | grep "^test-" | awk '{print $$1}' | \
		while read csr; do \
			echo "Deleting CSR $$csr..."; \
			kubectl delete csr $$csr 2>/dev/null || true; \
		done || echo "No test CSRs found"
	@echo "Cleanup complete"

.PHONY: csr-create-batch
csr-create-batch: ## Create multiple test CSRs (usage: make csr-create-batch [COUNT=10] [APPROVE=true])
	@COUNT=$${COUNT:-10}; \
	APPROVE=$${APPROVE:-false}; \
	echo "=== Creating $$COUNT test CSRs (approve=$$APPROVE) ==="; \
	for i in $$(seq 1 $$COUNT); do \
		NAME="test-batch-csr-$$i-$$(date +%s)"; \
		if [ "$$APPROVE" = "true" ]; then \
			$(MAKE) csr-create-approved NAME=$$NAME; \
		else \
			$(MAKE) csr-create NAME=$$NAME; \
		fi; \
		echo ""; \
	done; \
	echo "=== Created $$COUNT CSRs ==="

.PHONY: csr-create-with-chain
csr-create-with-chain: ## Create a CSR with a certificate chain (for testing chain handling)
	@NAME=$${NAME:-test-chain-csr-$$(date +%s)}; \
	TMPDIR=$$(mktemp -d); \
	echo "=== Creating CSR with certificate chain: $$NAME ==="; \
	echo "Generating test CA chain (root -> intermediate -> leaf)..."; \
	openssl genrsa -out $$TMPDIR/root-ca.key 2048 2>/dev/null; \
	openssl req -x509 -new -nodes -key $$TMPDIR/root-ca.key -sha256 -days 365 \
		-out $$TMPDIR/root-ca.pem -subj "/CN=Test Root CA" 2>/dev/null; \
	openssl genrsa -out $$TMPDIR/intermediate-ca.key 2048 2>/dev/null; \
	openssl req -new -key $$TMPDIR/intermediate-ca.key \
		-out $$TMPDIR/intermediate-ca.csr -subj "/CN=Test Intermediate CA" 2>/dev/null; \
	openssl x509 -req -in $$TMPDIR/intermediate-ca.csr -CA $$TMPDIR/root-ca.pem \
		-CAkey $$TMPDIR/root-ca.key -CAcreateserial -out $$TMPDIR/intermediate-ca.pem \
		-days 365 -sha256 2>/dev/null; \
	openssl genrsa -out $$TMPDIR/leaf.key 2048 2>/dev/null; \
	openssl req -new -key $$TMPDIR/leaf.key \
		-out $$TMPDIR/leaf.csr -subj "/CN=Test Leaf Certificate" 2>/dev/null; \
	openssl x509 -req -in $$TMPDIR/leaf.csr -CA $$TMPDIR/intermediate-ca.pem \
		-CAkey $$TMPDIR/intermediate-ca.key -CAcreateserial -out $$TMPDIR/leaf.pem \
		-days 365 -sha256 2>/dev/null; \
	cat $$TMPDIR/leaf.pem $$TMPDIR/intermediate-ca.pem $$TMPDIR/root-ca.pem > $$TMPDIR/chain.pem; \
	echo "Creating K8S CSR with custom signer (to allow manual certificate injection)..."; \
	CSR_BASE64=$$(cat $$TMPDIR/leaf.csr | base64 | tr -d '\n'); \
	printf 'apiVersion: certificates.k8s.io/v1\nkind: CertificateSigningRequest\nmetadata:\n  name: %s\nspec:\n  request: %s\n  signerName: keyfactor.com/test-signer\n  usages:\n  - client auth\n' "$$NAME" "$$CSR_BASE64" | kubectl apply -f -; \
	echo "Approving CSR..."; \
	kubectl certificate approve $$NAME; \
	sleep 1; \
	echo "Injecting certificate chain (3 certs: leaf + intermediate + root)..."; \
	CHAIN_BASE64=$$(cat $$TMPDIR/chain.pem | base64 | tr -d '\n'); \
	kubectl patch csr $$NAME --type=json --subresource=status \
		-p "[{\"op\": \"add\", \"path\": \"/status/certificate\", \"value\": \"$$CHAIN_BASE64\"}]"; \
	rm -rf $$TMPDIR; \
	echo ""; \
	echo "=== CSR created with 3-certificate chain: $$NAME ==="; \
	kubectl get csr $$NAME -o jsonpath='{.status.certificate}' | base64 -d | grep -c "BEGIN CERTIFICATE" | xargs -I{} echo "Certificate count: {}"; \
	echo "To view chain: kubectl get csr $$NAME -o jsonpath='{.status.certificate}' | base64 -d"

.PHONY: csr-create-batch-with-chain
csr-create-batch-with-chain: ## Create multiple CSRs with certificate chains (usage: make csr-create-batch-with-chain [COUNT=3])
	@COUNT=$${COUNT:-3}; \
	echo "=== Creating $$COUNT CSRs with certificate chains ==="; \
	for i in $$(seq 1 $$COUNT); do \
		NAME="test-chain-csr-$$i-$$(date +%s)"; \
		$(MAKE) csr-create-with-chain NAME=$$NAME; \
		echo ""; \
	done; \
	echo "=== Created $$COUNT CSRs with chains ==="

##@ Build

.PHONY: build
build: ## Build the test project
	dotnet build
