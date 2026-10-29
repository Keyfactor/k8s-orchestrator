#!/usr/bin/env bash
# shellcheck shell=bash
#
# lab-env.sh - the ONLY place that knows about a specific lab.
#
# Everything environment-specific lives here and is read from environment
# variables: the Command URL, how a Command API token is obtained, which
# Universal Orchestrator (UO) runs the jobs, how the extension build is staged
# onto that UO (via the `kfclab` CLI), and which kube context the stores live
# in. To run the suite against a different lab, set the variables below (or
# replace the lab_* functions); nothing else in scripts/e2e is lab-specific.
#
# This file is sourced by lib.sh. Do not execute it. It never prints a secret
# and holds no secret defaults.
#
# Variables (see README.md for details and a worked example):
#
#   Always required (every phase that talks to the cluster)
#     E2E_KUBE_CONTEXT      kubectl context of the cluster where the stores live
#                           AND where the UO runs (the UO authenticates with its
#                           in-cluster identity, so they must be the same cluster)
#
#   Required by phases that talk to Command (discovery, inventory, management,
#   rbac, baseline, cleanup, stage-extension)
#     E2E_COMMAND_URL       Command API base URL, including the API path,
#                           e.g. https://command.example.com/KeyfactorAPI
#     E2E_TOKEN_CMD         a command line that prints a Command OAuth bearer
#                           token on stdout (run with `bash -c`), e.g.
#                           'kfclab token -f "$E2E_KFCLAB_SPEC"'
#     E2E_UO_NAME           the UO's name as known to kfclab (e.g. my-uo)
#
#   Required only to stage / restore the extension build on the UO
#     E2E_KFCLAB_SPEC       path to the kfclab lab spec. It is COPIED into the run's
#                           work dir (it can contain lab credentials); the original
#                           is never modified.
#     E2E_EXT_BUILD_PATH    local directory or .zip holding the extension build under
#                           test (e.g. the net10.0 Release output)
#
#   Optional
#     E2E_ENV_FILE          a shell file to source first (keep it out of git)
#     E2E_KUBECONFIG        kubeconfig file for kubectl (default: kubectl's default)
#     E2E_CA_CERT           PEM CA bundle that signs the Command endpoint
#     E2E_UO_AGENT          the UO's orchestrator name in Command (AgentResponse
#                           .ClientMachine). Default: kfclab-uo-<E2E_UO_NAME>
#     E2E_EXT_NAME          extension name in the kfclab spec (default k8s-orchestrator)
#     E2E_KFCLAB_BIN        kfclab executable (default kfclab)
#     E2E_UO_NAMESPACE      namespace of the UO pod (default keyfactor-lab, kfclab's default)
#     E2E_UO_SELECTOR       label selector of the UO pod (default
#                           app.kubernetes.io/instance=uo-<E2E_UO_NAME>, kfclab's naming)
#     E2E_UO_EXT_DIR        extensions directory inside the UO pod (default /app/extensions).
#                           Used to read back what the UO really has deployed (needs
#                           `kubectl exec` on the pod); without it the checks are skipped
#     E2E_UO_LOG_CMD        command that prints the UO log (enables case K108)
#     E2E_RBAC_API_SERVER   API server URL as seen from the UO pod, written into the
#                           scoped-service-account kubeconfig
#                           (default https://kubernetes.default.svc:443)
#     E2E_JOB_TIMEOUT       seconds to wait for each Command job (default 300)
#     E2E_JOB_POLL          seconds between job-history polls (default 5)
#     E2E_TOKEN_TTL         seconds a fetched token is reused (default 240)
#     E2E_MAX_REJECTS       abort a phase when Command rejects this many scheduling requests
#                           in a row (default 3); every rejected request is a FAIL at once
#     E2E_STRICT_XPASS      true: an unexpectedly passing known-issue case fails the run

if [ -n "${E2E_ENV_FILE:-}" ]; then
  if [ -r "$E2E_ENV_FILE" ]; then
    # shellcheck disable=SC1090
    . "$E2E_ENV_FILE"
  else
    echo "ERROR: E2E_ENV_FILE='$E2E_ENV_FILE' is not a readable file" >&2
    exit 2
  fi
fi

# ---- non-secret defaults -----------------------------------------------------
: "${E2E_EXT_NAME:=k8s-orchestrator}"
: "${E2E_KFCLAB_BIN:=kfclab}"
: "${E2E_RBAC_API_SERVER:=https://kubernetes.default.svc:443}"
: "${E2E_JOB_TIMEOUT:=300}"
: "${E2E_JOB_POLL:=5}"
: "${E2E_TOKEN_TTL:=240}"
: "${E2E_STRICT_XPASS:=false}"
: "${E2E_MAX_REJECTS:=3}"
# Where the UO pod and its extension directory live (kfclab conventions; override for another lab).
: "${E2E_UO_NAMESPACE:=keyfactor-lab}"
: "${E2E_UO_SELECTOR:=app.kubernetes.io/instance=uo-${E2E_UO_NAME:-unset}}"
: "${E2E_UO_EXT_DIR:=/app/extensions}"

# E2E_TOKEN_CMD and E2E_UO_LOG_CMD run under `bash -c`; let them refer to these.
export E2E_KFCLAB_SPEC E2E_KUBECONFIG E2E_KUBE_CONTEXT E2E_UO_NAME E2E_UO_NAMESPACE E2E_UO_SELECTOR E2E_COMMAND_URL

# lab_require VAR... : fail with a clear message naming every missing variable.
lab_require() {
  local v missing=""
  for v in "$@"; do
    if [ -z "${!v:-}" ]; then missing="$missing $v"; fi
  done
  if [ -n "$missing" ]; then
    echo "ERROR: required environment variable(s) not set:$missing" >&2
    echo "       Set them (or point E2E_ENV_FILE at a file that does). See scripts/e2e/README.md and scripts/e2e/lab-env.sh." >&2
    exit 2
  fi
}

# The suite creates and deletes namespaces and RBAC objects. The integration tests
# have their own cluster (context kf-integrations); never point the suite at it.
lab_require_kube() {
  lab_require E2E_KUBE_CONTEXT
  case $E2E_KUBE_CONTEXT in
    kf-integrations)
      echo "ERROR: E2E_KUBE_CONTEXT='$E2E_KUBE_CONTEXT' is the integration-test cluster; the e2e suite must run against the lab cluster the UO runs in" >&2
      exit 2
      ;;
  esac
}

lab_require_command() {
  lab_require_kube
  lab_require E2E_COMMAND_URL E2E_TOKEN_CMD E2E_UO_NAME
  : "${E2E_UO_AGENT:=kfclab-uo-${E2E_UO_NAME}}"
  E2E_COMMAND_URL=${E2E_COMMAND_URL%/}
}

# lab_require_stage [restore] : the build path is only needed to stage
lab_require_stage() {
  lab_require_command
  lab_require E2E_KFCLAB_SPEC
  [ "${1:-}" = restore ] || lab_require E2E_EXT_BUILD_PATH
  [ "${DRY_RUN:-0}" = 1 ] && return 0
  [ -r "$E2E_KFCLAB_SPEC" ] || { echo "ERROR: E2E_KFCLAB_SPEC is not a readable file" >&2; exit 2; }
  [ "${1:-}" = restore ] || [ -e "$E2E_EXT_BUILD_PATH" ] || { echo "ERROR: E2E_EXT_BUILD_PATH does not exist" >&2; exit 2; }
}

# ---- kubernetes --------------------------------------------------------------
# lab_kubectl ARGS... : kubectl pinned to the configured context.
lab_kubectl() {
  if [ -n "${E2E_KUBECONFIG:-}" ]; then
    kubectl --kubeconfig "$E2E_KUBECONFIG" --context "$E2E_KUBE_CONTEXT" "$@"
  else
    kubectl --context "$E2E_KUBE_CONTEXT" "$@"
  fi
}

# ---- command api -------------------------------------------------------------
# lab_token : print a bearer token on stdout. Never logs it. Fails (without
# echoing the command output) when the output does not look like a JWT, which
# catches e.g. a kfclab build that prints a curl hint instead of a token.
lab_token() {
  local t
  t=$(bash -c "$E2E_TOKEN_CMD" 2>/dev/null | tr -d '\r\n ') || true
  case $t in
    *.*.*) : ;;
    *)
      echo "ERROR: E2E_TOKEN_CMD did not print a bearer token (got ${#t} bytes that do not look like a JWT)" >&2
      return 1
      ;;
  esac
  printf '%s' "$t"
}

# ---- uo log (optional) -------------------------------------------------------
lab_uo_logs() {
  [ -n "${E2E_UO_LOG_CMD:-}" ] || return 1
  bash -c "$E2E_UO_LOG_CMD" 2>/dev/null
}

# ---- extension staging (kfclab) ----------------------------------------------
# The UO's extension is staged by editing the plugin entry of a PRIVATE COPY of
# the kfclab spec and running `kfclab extension update`, which re-stages the
# artifact into the UO's extension volume and restarts the UO pod. Restoring is
# the same operation with the recorded original entry written back. If your lab
# stages extensions differently, replace the lab_ext_* functions; stage-extension.sh
# only calls these.
#
# All lab_ext_* functions take the path of the spec copy as $1.

_lab_yq_sel='.orchestrators[] | select(.name == strenv(E2E_UO_NAME)) | .plugins[] | select(.name == strenv(E2E_EXT_NAME))'

# lab_ext_get_node SPEC : the plugin entry as compact JSON
lab_ext_get_node() {
  E2E_UO_NAME=$E2E_UO_NAME E2E_EXT_NAME=$E2E_EXT_NAME yq -o=json -I=0 "$_lab_yq_sel" "$1"
}

# lab_ext_set_node SPEC NODE_JSON : replace the plugin entry
lab_ext_set_node() {
  E2E_UO_NAME=$E2E_UO_NAME E2E_EXT_NAME=$E2E_EXT_NAME E2E_NODE=$2 \
    yq -i "($_lab_yq_sel) = (strenv(E2E_NODE) | from_json) | ($_lab_yq_sel | ..) style = \"\"" "$1"
}

# lab_ext_apply SPEC : re-stage the extension described by the spec and restart the UO
lab_ext_apply() {
  "$E2E_KFCLAB_BIN" extension update --uo "$E2E_UO_NAME" --extension "$E2E_EXT_NAME" -f "$1"
}

# Fingerprints. `kfclab extension list` is NOT usable for this: it lists kfclab's
# local plugin cache (one global list, not per UO), ignores --json, and its --uo
# filter never matches. Instead the extension directory the UO pod actually has is
# fingerprinted: one "<sha256> <file>" line per *.dll plus manifest.json, sorted.
# kfclab itself already verifies the primary DLL after every update; this covers
# the rest and lets the suite compare "before staging" with "after restore".

_lab_sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# lab_ext_dir_fp DIR : fingerprint of a local extension build directory
lab_ext_dir_fp() {
  ( cd "$1" 2>/dev/null && _lab_sha ./*.dll manifest.json ) | sed 's# \./# #; s#  *# #' | sort -k2
}

# lab_ext_deployed_fp : fingerprint of the extension directory inside the UO pod.
# Needs permission to `kubectl exec` into the pod; returns non-zero (and prints
# nothing) when it cannot be read.
lab_ext_deployed_fp() {
  local pod out
  pod=$(lab_kubectl -n "$E2E_UO_NAMESPACE" get pod -l "$E2E_UO_SELECTOR" -o name 2>/dev/null | head -1)
  [ -n "$pod" ] || return 1
  out=$(lab_kubectl -n "$E2E_UO_NAMESPACE" exec "$pod" -- sh -c \
    "cd '$E2E_UO_EXT_DIR/$E2E_EXT_NAME' && sha256sum *.dll manifest.json" 2>/dev/null) || return 1
  [ -n "$out" ] || return 1
  printf '%s\n' "$out" | sed 's#  *# #' | sort -k2
}
