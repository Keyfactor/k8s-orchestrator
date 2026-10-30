#!/usr/bin/env bash
# shellcheck shell=bash
#
# uo-log-loki.sh - print the Universal Orchestrator's log from Loki, oldest first, one log line
# per output line in the container's own layout (what `kubectl logs` prints). It is a drop-in
# E2E_UO_LOG_CMD for case K108 on a lab whose container logs are rotated but shipped to Loki:
#
#   export E2E_LOKI_SERVICE=<namespace>/<service>:<port>        # the Loki HTTP service in the cluster
#   export E2E_UO_LOG_CMD='"$E2E_DIR/uo-log-loki.sh"'
#
# Read-only. Loki is reached through the Kubernetes API server's service proxy
# (`kubectl get --raw /api/v1/namespaces/<ns>/services/<svc>:<port>/proxy/...`), so nothing
# needs an ingress, a port-forward or a hostname; the only requirement is `get` on services/proxy.
#
# Environment (the lab-env.sh variables are honoured as everywhere else)
#   E2E_LOKI_SERVICE   required: <namespace>/<service>:<port> of Loki
#   E2E_LOKI_QUERY     optional LogQL stream selector. Default: the UO pod found through
#                      E2E_UO_NAMESPACE + E2E_UO_SELECTOR, i.e. {namespace="..",pod=".."}
#   E2E_LOG_SINCE      optional start of the window, RFC 3339 UTC (management.sh sets it to the
#                      start of the phase). Default: 6 hours ago
#   E2E_LOG_UNTIL      optional end of the window (default: now)
#
# The output is paged (Loki returns at most 5000 entries per query). Exit status is non-zero,
# with nothing on stdout, when Loki cannot be queried.
set -u -o pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/e2e/lab-env.sh
. "$HERE/lab-env.sh"
lab_require E2E_KUBE_CONTEXT E2E_LOKI_SERVICE
command -v jq >/dev/null || { echo "ERROR: jq is required" >&2; exit 2; }

case $E2E_LOKI_SERVICE in
  */*:*) : ;;
  *) echo "ERROR: E2E_LOKI_SERVICE must look like <namespace>/<service>:<port>" >&2; exit 2 ;;
esac
svc_ns=${E2E_LOKI_SERVICE%%/*}
svc_rest=${E2E_LOKI_SERVICE#*/}
base="/api/v1/namespaces/$svc_ns/services/$svc_rest/proxy/loki/api/v1/query_range"

iso_ago() { # HOURS : RFC 3339 UTC, GNU or BSD date
  date -u -d "-$1 hours" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-"$1"H +%Y-%m-%dT%H:%M:%SZ
}
since=${E2E_LOG_SINCE:-$(iso_ago 6)}
until=${E2E_LOG_UNTIL:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
case $since$until in *[!0-9A-Za-z:.+-]*) echo "ERROR: E2E_LOG_SINCE / E2E_LOG_UNTIL must be RFC 3339 timestamps" >&2; exit 2 ;; esac

query=${E2E_LOKI_QUERY:-}
if [ -z "$query" ]; then
  pod=$(lab_kubectl -n "$E2E_UO_NAMESPACE" get pod -l "$E2E_UO_SELECTOR" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null) || pod=""
  [ -n "$pod" ] || { echo "ERROR: no UO pod matches selector '$E2E_UO_SELECTOR' in namespace '$E2E_UO_NAMESPACE' (set E2E_LOKI_QUERY)" >&2; exit 2; }
  query="{namespace=\"$E2E_UO_NAMESPACE\",pod=\"$pod\"}"
fi
enc=$(printf '%s' "$query" | jq -sRr @uri)

out=$(mktemp "${TMPDIR:-/tmp}/uo-log-loki.XXXXXX") || exit 2
page=$(mktemp "${TMPDIR:-/tmp}/uo-log-loki.XXXXXX") || exit 2
trap 'rm -f "$out" "$page"' EXIT

limit=5000
start=$since
last_ts=""     # nanosecond timestamp (string) of the last entry already emitted
skip=0         # how many entries carrying exactly last_ts were already emitted
pages=0
while :; do
  lab_kubectl get --raw "$base?query=$enc&start=$start&end=$until&limit=$limit&direction=forward" > "$page" 2>/dev/null \
    || { echo "ERROR: Loki query failed (E2E_LOKI_SERVICE=$E2E_LOKI_SERVICE)" >&2; exit 1; }
  jq -e '.status == "success"' "$page" >/dev/null 2>&1 || { echo "ERROR: Loki answered something unexpected" >&2; exit 1; }
  # all streams merged by timestamp (nanosecond strings of equal length sort lexically);
  # entries at last_ts that were already printed are dropped. Output: "<ts>\t<line>" with
  # the line's own newlines removed, so the count of lines equals the count of entries.
  jq -r --arg last "$last_ts" --argjson skip "$skip" '
      [.data.result[]?.values[]?] | sort_by(.[0])
      | (map(select(.[0] == $last)) | length) as $same
      | .[([$skip, $same] | min):]
      | .[] | "\(.[0])\t\(.[1] | gsub("\n"; " "))"' "$page" > "$page.rows" \
    || { echo "ERROR: could not parse Loki's answer" >&2; rm -f "$page.rows"; exit 1; }
  n=$(wc -l < "$page.rows" | tr -d ' ')
  total_in_page=$(jq '[.data.result[]?.values[]?] | length' "$page")
  if [ "$n" -eq 0 ] && [ "$total_in_page" -ge "$limit" ]; then
    echo "ERROR: a full page of Loki entries share one timestamp; cannot page past it" >&2; exit 1
  fi
  [ "$n" -gt 0 ] && cut -f2- "$page.rows" >> "$out"
  if [ "$n" -gt 0 ]; then
    new_last=$(tail -1 "$page.rows" | cut -f1)
    if [ "$new_last" = "$last_ts" ]; then skip=$((skip + n)); else last_ts=$new_last; skip=$(awk -F'\t' -v t="$new_last" '($1 "") == (t "") {c++} END {print c + 0}' "$page.rows"); fi   # string compare: 19-digit values exceed a double
    # the next window starts at the last timestamp (RFC 3339 has no ns precision; Loki takes epoch ns too)
    start=$last_ts
  fi
  rm -f "$page.rows"
  pages=$((pages + 1))
  [ "$total_in_page" -lt "$limit" ] && break
  [ "$pages" -ge 400 ] && { echo "ERROR: more than 400 pages of log; narrow E2E_LOG_SINCE" >&2; exit 1; }
done
cat "$out"
