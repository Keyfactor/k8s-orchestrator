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

.PHONY: testall
testall: ## Run all tests.
	@source .env; \
	source .test.env; \
	dotnet test

.PHONY: test
test: ## Run a single test.
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

##@ Build

.PHONY: build
build: ## Build the test project
	dotnet build 
