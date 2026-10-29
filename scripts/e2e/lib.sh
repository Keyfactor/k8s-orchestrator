#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC2034  # variables set here are consumed by the phase scripts that source this file
#
# lib.sh - shared helpers for the e2e lab suite. Sourced by every phase script.
#
# Conventions
#   - bash 3.2 compatible (macOS /bin/bash): no associative arrays, no mapfile.
#   - `set -x` is never used. No function prints a token, password or key.
#   - Every call that leaves this machine (Command API, kubectl, kfclab) is
#     guarded by --dry-run and prints "[dry-run] would ..." instead.
#   - JSON is handled with jq only.

set -u -o pipefail

E2E_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export E2E_DIR
# shellcheck source=scripts/e2e/lab-env.sh
. "$E2E_DIR/lab-env.sh"

DRY_RUN=0
PREFIX=${E2E_PREFIX:-e2e-suite}
ONLY=""
WORK=""
WORK_ARG=${E2E_WORKDIR:-}
PHASE=${PHASE:-e2e}
E2E_REST=()
N_PASS=0 N_FAIL=0 N_XFAIL=0 N_XPASS=0 N_SKIP=0 N_REPRO=0 N_NOREPRO=0

# ---------------------------------------------------------------- output ----
say()  { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
dry()  { [ "$DRY_RUN" = 1 ]; }
dsay() { printf '[dry-run] %s\n' "$*"; }
csv()  { paste -sd, - ; }
upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }

# ------------------------------------------------------------------ init ----
e2e_usage() {
  cat <<EOF
Usage: ${0##*/} [--prefix NAME] [--dry-run] [--workdir DIR] [--only ID[,ID...]] ${E2E_USAGE_EXTRA:-}

  --prefix NAME   run prefix; every resource this suite creates carries it
                  (default: \$E2E_PREFIX or e2e-suite; must match ^e2e[a-z0-9-]{3,40}\$)
  --dry-run       print what would be done; touches no cluster, Command or UO
  --workdir DIR   scratch directory (default: \${TMPDIR:-/tmp}/e2e-lab-<prefix>)
  --only IDS      comma separated case IDs or globs (e.g. D1,D5,I*); some cases
                  depend on earlier ones, see README.md
  -h, --help      this help
EOF
}

e2e_init() {
  E2E_REST=()
  while [ $# -gt 0 ]; do
    case $1 in
      --prefix)    [ $# -ge 2 ] || die "--prefix needs a value"; PREFIX=$2; shift 2 ;;
      --prefix=*)  PREFIX=${1#*=}; shift ;;
      --dry-run)   DRY_RUN=1; shift ;;
      --workdir)   [ $# -ge 2 ] || die "--workdir needs a value"; WORK_ARG=$2; shift 2 ;;
      --workdir=*) WORK_ARG=${1#*=}; shift ;;
      --only)      [ $# -ge 2 ] || die "--only needs a value"; ONLY=$2; shift 2 ;;
      --only=*)    ONLY=${1#*=}; shift ;;
      -h|--help)   e2e_usage; exit 0 ;;
      *)           E2E_REST+=("$1"); shift ;;
    esac
  done
  # A prefix guards every delete this suite issues, so it must be specific.
  if ! printf '%s' "$PREFIX" | grep -Eq '^e2e[a-z0-9-]{3,40}$' || [ "${PREFIX%-}" != "$PREFIX" ]; then
    die "invalid --prefix '$PREFIX': must match ^e2e[a-z0-9-]{3,40}\$ and not end with '-' (it is used in namespace names and as the only delete scope)"
  fi
  NS_A=$PREFIX-a NS_B=$PREFIX-b NS_C=$PREFIX-c NS_IGN=$PREFIX-ign NS_EMPTY=$PREFIX-empty
  NS_M=$PREFIX-m NS_RBAC=$PREFIX-rbac NS_ALL=all
  FIXTURE_NS_RE="^(${PREFIX}-(a|b|c|ign|empty)|all)\$"
  LBL_KEY=e2e-suite LBL_VAL=$PREFIX
  CSR_NAME=$PREFIX-csr1
  if dry; then
    # Dry run: an ephemeral scratch dir, never the real work dir.
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/e2e-dry.XXXXXX")
    trap 'rm -rf "$WORK"' EXIT
  else
    WORK=${WORK_ARG:-${TMPDIR:-/tmp}/e2e-lab-$PREFIX}
    WORK=${WORK%/}
    case $WORK in ""|/|"$HOME") die "refusing to use '$WORK' as the work dir" ;; esac
    if [ -f "$WORK/.e2e-suite-workdir" ]; then
      [ "$(cat "$WORK/.e2e-suite-workdir")" = "$PREFIX" ] || die "work dir $WORK belongs to another prefix"
    elif [ -e "$WORK" ]; then
      # an existing directory is only adopted when it is empty; cleanup.sh deletes the work dir
      [ -d "$WORK" ] && [ -z "$(ls -A "$WORK" 2>/dev/null)" ] && [ "$(cd "$WORK" && pwd)" != "$(pwd)" ] \
        || die "work dir $WORK exists and was not created by this suite; choose another --workdir"
    fi
    trap 'rm -rf "$WORK/tmp"' EXIT
  fi
  ( umask 077; mkdir -p "$WORK/state" "$WORK/tmp" "$WORK/jobs" "$WORK/pki" )
  dry || printf '%s\n' "$PREFIX" > "$WORK/.e2e-suite-workdir"
  RESULTS=$WORK/results.tsv
  KSPW_FILE=$WORK/state/ks.pw
  case $PHASE in e2e) : ;; *) say "== phase: $PHASE  prefix: $PREFIX  dry-run: $DRY_RUN" ;; esac
}

e2e_no_extra() {
  if [ "${#E2E_REST[@]}" -gt 0 ]; then
    die "unknown argument(s): ${E2E_REST[*]} (try --help)"
  fi
}

# want ID : is this case selected by --only ?
want() {
  local id=$1 pat
  [ -z "$ONLY" ] && return 0
  local IFS=,
  for pat in $ONLY; do
    # a pattern selects the case itself and its lettered sub-cases (D11 -> D11a, D11b)
    # shellcheck disable=SC2053
    [[ $id == $pat || $id == ${pat}[a-z] ]] && return 0
  done
  return 1
}

# ----------------------------------------------------------------- state ----
state_set() { printf '%s' "$2" > "$WORK/state/$1"; chmod 600 "$WORK/state/$1" 2>/dev/null || true; }
state_get() { if [ -f "$WORK/state/$1" ]; then cat "$WORK/state/$1"; fi; }

# ------------------------------------------------------------- reporting ----
# verdict ID OK DESC EXPECTED ACTUAL [ISSUE]
#   OK=1 means the observed behaviour is the CORRECT behaviour.
#   without ISSUE: PASS / FAIL.  with ISSUE (known deviation): XFAIL / XPASS.
verdict() {
  local id=$1 ok=$2 desc=$3 exp=$4 act=$5 issue=${6:-} st
  want "$id" || return 0
  if dry; then dsay "assert $id: $desc | expected: $exp${issue:+ (known issue $issue: expected-fail until fixed)}"; return 0; fi
  if [ -n "$issue" ]; then
    if [ "$ok" = 1 ]; then st=XPASS; N_XPASS=$((N_XPASS + 1)); else st=XFAIL; N_XFAIL=$((N_XFAIL + 1)); fi
  else
    if [ "$ok" = 1 ]; then st=PASS; N_PASS=$((N_PASS + 1)); else st=FAIL; N_FAIL=$((N_FAIL + 1)); fi
  fi
  _emit "$st" "$id" "$desc" "$exp" "$act" "$issue"
}

skip() { # ID DESC REASON
  want "$1" || return 0
  if dry; then dsay "skip-capable case $1: $2 ($3)"; return 0; fi
  N_SKIP=$((N_SKIP + 1)); _emit SKIP "$1" "$2" "" "$3" ""
}

# repro ID REPRODUCED DESC EXPECTED_OLD_BEHAVIOUR ACTUAL   (baseline phase)
repro() {
  local id=$1 r=$2 desc=$3 exp=$4 act=$5 st
  want "$id" || return 0
  if dry; then dsay "baseline $id: $desc | old behaviour expected: $exp"; return 0; fi
  if [ "$r" = 1 ]; then st=REPRO; N_REPRO=$((N_REPRO + 1)); else st=NOREPRO; N_NOREPRO=$((N_NOREPRO + 1)); fi
  _emit "$st" "$id" "$desc" "$exp" "$act" ""
}

_emit() { # STATUS ID DESC EXP ACT ISSUE
  local st=$1 id=$2 desc=$3 exp=$4 act=$5 issue=$6 tag=""
  [ -n "$issue" ] && tag=" [known issue $issue]"
  exp=$(printf '%s' "$exp" | tr '\n' ' ' | cut -c1-400)
  act=$(printf '%s' "$act" | tr '\n' ' ' | cut -c1-400)
  printf '%-7s %-7s %s%s\n' "$st" "$id" "$desc" "$tag"
  case $st in
    PASS) : ;;
    *) printf '          expected: %s\n          actual:   %s\n' "$exp" "$act" ;;
  esac
  if [ "$st" = XPASS ]; then
    printf '  !!!!!!  XPASS %s: known issue %s now behaves correctly. Remove the known-issue tag for this case.\n' "$id" "$issue"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$PHASE" "$id" "$st" "$issue" "$desc" "$act" >> "$RESULTS"
}

# expect_eq ID DESC EXPECTED ACTUAL [ISSUE]
expect_eq() {
  local ok=0
  [ "$3" = "$4" ] && ok=1
  verdict "$1" "$ok" "$2" "$3" "$4" "${5:-}"
}

# set_eq ID DESC "expected lines" "actual lines" [ISSUE] : order-insensitive set compare
set_eq() {
  local id=$1 desc=$2 e a ok=0 miss unexp
  e=$(printf '%s\n' "$3" | sed '/^$/d' | sort -u)
  a=$(printf '%s\n' "$4" | sed '/^$/d' | sort -u)
  [ "$e" = "$a" ] && ok=1
  if [ "$ok" = 0 ]; then
    miss=$(comm -23 <(printf '%s\n' "$e") <(printf '%s\n' "$a") | csv)
    unexp=$(comm -13 <(printf '%s\n' "$e") <(printf '%s\n' "$a") | csv)
    verdict "$id" 0 "$desc" "$(printf '%s' "$e" | csv)" "missing=[$miss] unexpected=[$unexp]" "${5:-}"
  else
    verdict "$id" 1 "$desc" "$(printf '%s' "$e" | csv)" "$(printf '%s' "$a" | csv)" "${5:-}"
  fi
}

finish() {
  local rc=0
  if dry; then say "== dry-run complete for phase $PHASE: nothing was executed against any lab system"; exit 0; fi
  if [ $((N_PASS + N_FAIL + N_XFAIL + N_XPASS + N_SKIP + N_REPRO + N_NOREPRO)) -gt 0 ]; then
    say "== $PHASE summary: PASS=$N_PASS FAIL=$N_FAIL XFAIL=$N_XFAIL XPASS=$N_XPASS SKIP=$N_SKIP REPRO=$N_REPRO NOREPRO=$N_NOREPRO"
  fi
  [ "$N_FAIL" -gt 0 ] && rc=1
  if [ "$N_XPASS" -gt 0 ]; then
    say "== NOTE: $N_XPASS known-issue case(s) now PASS unexpectedly (XPASS); the underlying issue looks fixed"
    [ "$E2E_STRICT_XPASS" = true ] && rc=1
  fi
  exit "$rc"
}

# ------------------------------------------------------------------ kube ----
# kube ARGS... : mutating or generic kubectl call; dry-run prints and skips.
kube() {
  if dry; then dsay "kubectl --context <ctx> $*"; return 0; fi
  lab_kubectl "$@"
}
# kube_get ARGS... : read-only call; silent no-op in dry-run.
kube_get() {
  if dry; then return 0; fi
  lab_kubectl "$@"
}

labels_json() { # extra label json merge not needed; plain object
  jq -n --arg k "$LBL_KEY" --arg v "$LBL_VAL" '{($k):$v}'
}

# mk_namespace NAME : create (or adopt) a labelled namespace. Refuses to adopt
# a namespace that exists without OUR label.
mk_namespace() {
  local ns=$1 cur
  if dry; then dsay "create namespace $ns labelled $LBL_KEY=$LBL_VAL"; return 0; fi
  cur=$(lab_kubectl get ns "$ns" -o json 2>/dev/null || true)
  if [ -n "$cur" ]; then
    if [ "$(printf '%s' "$cur" | jq -r --arg k "$LBL_KEY" '.metadata.labels[$k] // ""')" != "$LBL_VAL" ]; then
      die "namespace '$ns' already exists and is not labelled $LBL_KEY=$LBL_VAL; refusing to touch an existing lab resource"
    fi
    return 0
  fi
  lab_kubectl create namespace "$ns" >/dev/null && lab_kubectl label namespace "$ns" "$LBL_KEY=$LBL_VAL" >/dev/null
}

# apply_labelled : stdin = a Secret manifest (json); adds our label and applies
apply_labelled() {
  if dry; then cat >/dev/null; dsay "apply labelled object"; return 0; fi
  jq --arg k "$LBL_KEY" --arg v "$LBL_VAL" '.metadata.labels = ((.metadata.labels // {}) + {($k):$v})' | lab_kubectl apply -f - >/dev/null
}

# ------------------------------------------------------------ command api ---
_tok_file() { printf '%s' "$WORK/tmp/.tok"; }

# api_token : cached bearer token on stdout
api_token() {
  local f; f=$(_tok_file)
  if [ ! -s "$f" ] || [ -n "$(find "$f" -mmin +"$(( (E2E_TOKEN_TTL + 59) / 60 ))" 2>/dev/null)" ]; then
    ( umask 077; lab_token > "$f.new" ) || { rm -f "$f.new"; die "could not obtain an API token (E2E_TOKEN_CMD)"; }
    mv "$f.new" "$f"; chmod 600 "$f"
  fi
  cat "$f"
}

# api METHOD PATH [BODYFILE] : prints the response body; returns 0 on 2xx.
# The HTTP status is left in $WORK/tmp/last_code (subshell safe).
api() {
  local m=$1 p=$2 b=${3:-} out code url
  if dry; then
    [ "$m" = GET ] || dsay "$m $p${b:+ (with request body)}"
    return 0
  fi
  url="$E2E_COMMAND_URL$p"
  out=$(mktemp "$WORK/tmp/resp.XXXXXX")
  local args=(-sS -o "$out" -w '%{http_code}' -K - -X "$m"
              -H 'Content-Type: application/json' -H 'x-keyfactor-requested-with: APIClient')
  [ -n "${E2E_CA_CERT:-}" ] && args+=(--cacert "$E2E_CA_CERT")
  [ -n "$b" ] && args+=(--data "@$b")
  # The token goes to curl through stdin (-K -), never through argv.
  code=$(printf 'header = "Authorization: Bearer %s"\n' "$(api_token)" | curl "${args[@]}" "$url") || code=000
  printf '%s' "$code" > "$WORK/tmp/last_code"
  case $code in
    2??) cat "$out"; rm -f "$out"; return 0 ;;
    *)   warn "API $m $p -> HTTP $code: $(head -c 300 "$out" | tr '\n' ' ')"; rm -f "$out"; return 1 ;;
  esac
}
api_code() { cat "$WORK/tmp/last_code" 2>/dev/null || printf '000'; }

# --------------------------------------------------------- lab discovery ----
# resolve_lab : agent id of the UO and store type ids / capabilities, cached in state
resolve_lab() {
  local t j aid
  if dry; then dsay "resolve UO agent '${E2E_UO_AGENT:-?}' and store type ids from Command (read-only GETs)"; return 0; fi
  api GET "/Agents?PageReturned=1&ReturnLimit=1" >/dev/null || die "Command API not reachable, or the token was rejected (check E2E_COMMAND_URL, E2E_TOKEN_CMD, E2E_CA_CERT)"
  aid=$(api GET "/Agents?PageReturned=1&ReturnLimit=500" | jq -r --arg n "$E2E_UO_AGENT" '[.[]? | select(.ClientMachine == $n) | .AgentId] | first // empty')
  [ -n "$aid" ] || die "no orchestrator named '$E2E_UO_AGENT' found in Command (set E2E_UO_AGENT to its name in Command)"
  state_set agent.id "$aid"
  for t in K8SCert K8SCluster K8SJKS K8SNS K8SPKCS12 K8SSecret K8STLSSecr; do
    j=$(api GET "/CertificateStoreTypes/Name/$t" | jq -c 'if type == "array" then .[0] else . end // empty')
    [ -n "$j" ] || die "store type '$t' is not defined in Command"
    state_set "st.$t" "$(printf '%s' "$j" | jq -r '.StoreType')"
    state_set "st.$t.discovery" "$(printf '%s' "$j" | jq -r '.SupportedOperations.Discovery // false')"
  done
}
st_id() { state_get "st.$1"; }

# ------------------------------------------------------------- job history --
# NB: the Keyfactor API's SortAscending is inverted: 0 = ascending, 1 = descending.
hist_recent() { api GET "/OrchestratorJobs/JobHistory?PageReturned=1&ReturnLimit=${E2E_HIST_LIMIT:-500}&SortField=OperationStart&SortAscending=1"; }
hist_max_id() { hist_recent | jq -r 'if type == "array" then (map(.JobHistoryId) | max // 0) else 0 end'; }

BATCH_BASE=0
batch_begin() {
  if dry; then BATCH_BASE=0; return 0; fi
  BATCH_BASE=$(hist_max_id)
  rm -f "$WORK/jobs/pending"
}

# job_register LABEL CM PATH_SUFFIX TYPE_REGEX [BASE] : remember a job to wait for
job_register() {
  local base=${5:-$BATCH_BASE}
  dry && return 0
  # '|' separated (a tab would collapse an empty path-suffix field when read back)
  printf '%s|%s|%s|%s|%s\n' "$1" "$base" "$2" "$3" "$4" >> "$WORK/jobs/pending"
  rm -f "$WORK/jobs/$1.json"
}

# Command re-queues a job whose result was a failure (status CompletedWillRetry) about every
# 5 minutes, and every retry is a NEW history entry with a higher JobHistoryId but the SAME
# JobId. Each job the suite has already waited for is therefore remembered by JobId, and its
# later retries are never taken for the result of a newer job on the same store.
_wait_one() { # BASE CM PSUF TRE OUT -> 0 found, 1 timeout
  local base=$1 cm=$2 psuf=$3 tre=$4 out=$5 deadline entry seen
  deadline=$(( $(date +%s) + E2E_JOB_TIMEOUT ))
  while :; do
    seen=$(cat "$WORK/state/jobids.seen" 2>/dev/null || true)
    entry=$(hist_recent | jq -c --argjson b "$base" --arg cm "$cm" --arg ps "$psuf" --arg tre "$tre" --arg seen "$seen" '
      ($seen | split("\n")) as $S
      | [ .[]? | select(.JobHistoryId > $b
                      and .ClientMachine == $cm
                      and (.JobType | test($tre))
                      and ($ps == "" or ((.StorePath // "") | endswith($ps)))
                      and ((.Status // "") | test("^Completed"))
                      and ((.JobId // "") as $j | $j == "" or ($S | index($j)) == null)) ]
      | sort_by(.JobHistoryId) | last // empty')
    if [ -n "$entry" ]; then
      printf '%s' "$entry" > "$out"
      printf '%s' "$entry" | jq -r '.JobId // empty' >> "$WORK/state/jobids.seen"
      return 0
    fi
    [ "$(date +%s)" -ge "$deadline" ] && return 1
    sleep "$E2E_JOB_POLL"
  done
}

# batch_wait : wait for every registered job; results in $WORK/jobs/LABEL.json
batch_wait() {
  local label base cm psuf tre
  dry && return 0
  [ -f "$WORK/jobs/pending" ] || return 0
  while IFS='|' read -r -u 3 label base cm psuf tre; do
    if ! _wait_one "$base" "$cm" "$psuf" "$tre" "$WORK/jobs/$label.json"; then
      jq -n --arg m "timed out after ${E2E_JOB_TIMEOUT}s waiting for the job in Command job history" '{Result:"Timeout",Status:"Timeout",Message:$m}' > "$WORK/jobs/$label.json"
    fi
  done 3< "$WORK/jobs/pending"
  rm -f "$WORK/jobs/pending"
}
job_result()  { jq -r '.Result // ""'  "$WORK/jobs/$1.json" 2>/dev/null; }
job_message() { jq -r '.Message // ""' "$WORK/jobs/$1.json" 2>/dev/null; }
job_status()  { jq -r '.Status // ""'  "$WORK/jobs/$1.json" 2>/dev/null; }
job_id()      { jq -r '.JobHistoryId // ""' "$WORK/jobs/$1.json" 2>/dev/null; }

# ---------------------------------------------------------------- stores ----
stores_all() { api GET "/CertificateStores?PageReturned=1&ReturnLimit=3000"; }

# store_find CM PATH : id of the store with exactly this client machine + path
store_find() {
  stores_all | jq -r --arg cm "$1" --arg p "$2" '[.[]? | select(.ClientMachine == $cm and .Storepath == $p) | .Id] | first // empty'
}
# store_find_suffix CM SUFFIX : id of the (discovered) store whose path ends with /SUFFIX or equals it
store_find_suffix() {
  stores_all | jq -r --arg cm "$1" --arg s "$2" '[.[]? | select(.ClientMachine == $cm and ((.Storepath == $s) or ((.Storepath // "") | endswith("/" + $s)))) | .Id] | first // empty'
}
store_field() { # ID FIELD
  api GET "/CertificateStores/$1" | jq -r --arg f "$2" '.[$f] // empty'
}
# own_store_ids : ids of every store this run owns (client machine = PREFIX or PREFIX-*)
own_store_ids() {
  stores_all | jq -r --arg p "$PREFIX" '.[]? | select(.ClientMachine == $p or (.ClientMachine | startswith($p + "-"))) | .Id'
}
# delete_stores IDS... : delete by id. Refuses ids that are not owned by this prefix.
delete_stores() {
  local own id body keep
  [ $# -gt 0 ] || return 0
  if dry; then dsay "DELETE /CertificateStores ($# store(s) owned by prefix $PREFIX)"; return 0; fi
  own=$(own_store_ids)
  keep=""
  for id in "$@"; do
    if printf '%s\n' "$own" | grep -qx "$id"; then keep="$keep $id"; else warn "refusing to delete store $id: not owned by prefix $PREFIX"; fi
  done
  [ -n "$keep" ] || return 0
  body=$(mktemp "$WORK/tmp/del.XXXXXX")
  # shellcheck disable=SC2086
  printf '%s\n' $keep | jq -R . | jq -s . > "$body"
  api DELETE /CertificateStores "$body" >/dev/null
  rm -f "$body"
}
# purge_cm CM : remove leftover stores of one of our client machines (idempotent reruns)
purge_cm() {
  local cm=$1 ids
  case $cm in "$PREFIX"|"$PREFIX"-*) : ;; *) die "purge_cm: '$cm' is outside prefix $PREFIX" ;; esac
  dry && { dsay "remove leftover Command stores for client machine $cm (if any)"; return 0; }
  ids=$(stores_all | jq -r --arg cm "$cm" '.[]? | select(.ClientMachine == $cm) | .Id')
  # shellcheck disable=SC2086
  [ -n "$ids" ] && delete_stores $ids
  return 0
}
# norm_path PATH : drop the leading cluster/host segment of a discovered path
norm_path() { sed 's#^[^/]*/##'; }

# discovered_paths CM : normalised paths of the stores discovery produced for CM
discovered_paths() {
  stores_all | jq -r --arg cm "$1" '.[]? | select(.ClientMachine == $cm) | .Storepath' | norm_path | sort
}

# schedule_inventory IDS... : immediate inventory
schedule_inventory() {
  local body ids
  [ $# -gt 0 ] || return 0
  dry && { dsay "POST /CertificateStores/Schedule (immediate inventory for $# store(s))"; return 0; }
  body=$(mktemp "$WORK/tmp/sch.XXXXXX")
  ids=$(printf '%s\n' "$@" | jq -R . | jq -s -c .)
  jq -n --argjson ids "$ids" '{StoreIds:$ids,Schedule:{Immediate:true}}' > "$body"
  api POST /CertificateStores/Schedule "$body" >/dev/null
  rm -f "$body"
}

# store_props EXTRA_JSON : the store Properties string. The UO authenticates with
# its in-cluster identity, so the server username is the literal "kubeconfig"
# and no server password is sent.
store_props() {
  jq -n -c --argjson e "$1" '{ServerUsername:"kubeconfig",ServerUseSsl:"false"} + $e'
}

# mk_store CM PATH TYPE PROPS_JSON USE_PW(yes|"") CREATE_IF_MISSING(true|false)
#   creates (or reuses) an approved store served by the UO. USE_PW=yes sends the
#   run's keystore password as the store password (read from a file, never argv).
#   Echoes the store id.
mk_store() {
  local cm=$1 path=$2 type=$3 extra=$4 usepw=${5:-} cim=${6:-false} id body props agent
  if dry; then dsay "create store type=$type cm=$cm path=$path props=$extra createIfMissing=$cim"; return 0; fi
  id=$(store_find "$cm" "$path")
  if [ -n "$id" ]; then printf '%s' "$id"; return 0; fi
  agent=$(state_get agent.id)
  body=$(mktemp "$WORK/tmp/mk.XXXXXX")
  props=$(store_props "$extra")
  jq -n --arg cm "$cm" --arg sp "$path" --argjson t "$(st_id "$type")" --arg props "$props" \
        --arg agent "$agent" --argjson cim "$cim" --arg usepw "$usepw" --rawfile pw "$KSPW_FILE" \
        '{ClientMachine:$cm,Storepath:$sp,CertStoreType:$t,CreateIfMissing:$cim,Properties:$props,AgentId:$agent,AgentAssigned:true}
         + (if $cim then {} else {InventorySchedule:{Immediate:true}} end)
         + (if $usepw == "" then {} else {Password:{SecretValue:$pw}} end)' > "$body"
  id=$(api POST /CertificateStores "$body" | jq -r '.Id // empty')
  rm -f "$body"
  [ -n "$id" ] || return 1
  printf '%s' "$id"
}

# store_inventory ID : inventory rows as JSON array
store_inventory() { api GET "/CertificateStores/$1/Inventory?PageReturned=1&ReturnLimit=500"; }

# inv_check ID DESC STOREID "ROW|ROW..." [MODE] [ALIAS_REGEX] [ISSUE]
#   rows are "alias|key|certs" one per line (as separate args joined by newline)
#   alias  : exact alias or * (any)
#   key    : yes | no | *
#   certs  : comma list of cert names (exact set), ~a,b (contains all), or *
#   MODE   : exact (default) | extra-no (extra rows allowed if they have no private key)
#            | subset (extra rows allowed)
#   ALIAS_REGEX : only consider actual rows whose alias matches (used for K8SCluster)
inv_check() {
  local id=$1 desc=$2 sid=$3 exp=$4 mode=${5:-exact} are=${6:-} issue=${7:-} inv res
  want "$id" || return 0
  if dry; then verdict "$id" 1 "$desc" "$(printf '%s' "$exp" | csv)" "" "$issue"; return 0; fi
  inv=$(store_inventory "$sid") || { verdict "$id" 0 "$desc" "$(printf '%s' "$exp" | csv)" "could not read inventory (store $sid)" "$issue"; return 0; }
  res=$(printf '%s' "$inv" | jq -r --rawfile exp <(printf '%s\n' "$exp") --slurpfile m "$WORK/pki/thumbs.json" \
        --arg mode "$mode" --arg are "$are" '
    def pk: ((.Parameters.PrivateKeyEntry // "") | tostring | ascii_downcase) as $p
            | if ($p == "yes" or $p == "true") then "yes" elif ($p == "no" or $p == "false") then "no" else $p end;
    def ok($e; $a):
      ($e.a == "*" or $e.a == $a.a) and ($e.p == "*" or $e.p == $a.p)
      and (if $e.c == "*" then true
           elif ($e.c | startswith("~")) then ($e.c[1:] | split(",") | all(. as $x | any($a.c[]; . == $x)))
           else (($e.c | split(",") | sort) == $a.c) end);
    ($exp | split("\n") | map(select(length > 0) | split("|") | {a: .[0], p: .[1], c: .[2]})) as $E
    | ([ .[]? | {a: .Name, p: pk,
                 c: ([.Certificates[]? | ((.Thumbprint | ascii_downcase) as $t | ($m[0][$t] // $t))] | sort)}
         | select($are == "" or (.a | test($are))) ]) as $A
    | ( [ $E[] | . as $e | select(([ $A[] | select(ok($e; .)) ] | length) == 0) | "missing \(.a)|\(.p)|\(.c)" ]
      + ( if $mode == "subset" then []
          else [ $A[] | . as $a
                 | select(([ $E[] | select(ok(.; $a)) ] | length) == 0)
                 | select($mode == "exact" or $a.p != "no")
                 | "unexpected \($a.a)|\($a.p)|\($a.c | join(","))" ] end ) ) as $problems
    | if ($problems | length) == 0 then "OK" else ($problems | join("; ")) end')
  if [ "$res" = OK ]; then
    verdict "$id" 1 "$desc" "$(printf '%s' "$exp" | csv)" "inventory matches" "$issue"
  else
    verdict "$id" 0 "$desc" "$(printf '%s' "$exp" | csv)" "$res" "$issue"
  fi
}

# --------------------------------------------------------- pki / keystores ---
thumb_name() { # THUMB -> name or thumb
  local n
  n=$(jq -r --arg t "$1" '.[$t] // empty' "$WORK/pki/thumbs.json" 2>/dev/null)
  printf '%s' "${n:-$1}"
}

cert_thumb() { openssl x509 -in "$1" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }

# pem_names FILE : names of the certificates in a PEM file, in file order, one per line
pem_names() {
  local f=$1 n i d
  dry && return 0
  [ -s "$f" ] || return 0
  n=$(grep -c 'BEGIN CERTIFICATE' "$f" || true)
  [ "${n:-0}" -gt 0 ] || return 0
  d=$(mktemp -d "$WORK/tmp/pem.XXXXXX")
  awk -v d="$d" '/-----BEGIN CERTIFICATE-----/ {k++} k > 0 {print > (d "/c" k ".pem")}' "$f"
  i=1
  while [ "$i" -le "$n" ]; do
    thumb_name "$(cert_thumb "$d/c$i.pem")"; printf '\n'
    i=$((i + 1))
  done
  rm -rf "$d"
}

# sec_json NS NAME
sec_json() { kube_get -n "$1" get secret "$2" -o json 2>/dev/null; }
sec_exists() { sec_json "$1" "$2" | jq -e '.metadata.name' >/dev/null 2>&1; }
sec_type()   { sec_json "$1" "$2" | jq -r '.type // empty'; }
sec_keys()   { sec_json "$1" "$2" | jq -r '(.data // {}) | keys[]' | sort; }
# sec_field NS NAME FIELD OUTFILE : decoded data field into OUTFILE (empty file if absent)
sec_field() {
  : > "$4"
  sec_json "$1" "$2" | jq -r --arg f "$3" '.data[$f] // empty' | base64 --decode > "$4" 2>/dev/null || true
}
# sec_chain NS NAME FIELD : ordered names of the certs in a PEM field, comma separated
sec_chain() {
  local f; f=$(mktemp "$WORK/tmp/fld.XXXXXX")
  sec_field "$1" "$2" "$3" "$f"
  pem_names "$f" | csv
  rm -f "$f"
}
# sec_has_key NS NAME FIELD : yes | no (non-empty private key material present)
sec_has_key() {
  local f r; f=$(mktemp "$WORK/tmp/fld.XXXXXX")
  sec_field "$1" "$2" "$3" "$f"
  if grep -q 'PRIVATE KEY' "$f" 2>/dev/null; then r=yes; else r=no; fi
  rm -f "$f"; printf '%s' "$r"
}
# sec_field_size NS NAME FIELD : bytes (0 when absent or empty)
sec_field_size() {
  local f s; f=$(mktemp "$WORK/tmp/fld.XXXXXX")
  sec_field "$1" "$2" "$3" "$f"
  s=$(wc -c < "$f" | tr -d ' ')
  rm -f "$f"; printf '%s' "$s"
}

# ks_fetch NS NAME FIELD OUTFILE
ks_fetch() { sec_field "$1" "$2" "$3" "$4"; }
# ks_aliases FILE TYPE : "alias:entrytype" lines (JKS | PKCS12)
ks_aliases() {
  dry && return 0
  [ -s "$1" ] || return 0
  keytool -list -keystore "$1" -storetype "$2" -storepass:file "$KSPW_FILE" 2>/dev/null \
    | sed -nE 's/^([^,]+), .*, (PrivateKeyEntry|trustedCertEntry),?.*$/\1:\2/p' | sort
}
ks_alias_thumb() { # FILE TYPE ALIAS -> leaf cert name
  local t
  dry && return 0
  t=$(keytool -list -v -keystore "$1" -storetype "$2" -storepass:file "$KSPW_FILE" -alias "$3" 2>/dev/null \
      | sed -nE 's/^[[:space:]]*SHA1: *//p' | head -1 | tr -d ':' | tr 'A-F' 'a-f')
  [ -n "$t" ] && thumb_name "$t"
}
ks_alias_chainlen() { # FILE TYPE ALIAS
  dry && return 0
  keytool -list -v -keystore "$1" -storetype "$2" -storepass:file "$KSPW_FILE" -alias "$3" 2>/dev/null \
    | sed -nE 's/^Certificate chain length: ([0-9]+).*/\1/p' | head -1
}
# ks_count FILE TYPE : number of entries
ks_count() { ks_aliases "$1" "$2" | sed '/^$/d' | wc -l | tr -d ' '; }

# gen_pki : throwaway test PKI in $WORK/pki (idempotent). Names embed the prefix.
gen_pki() {
  local d=$WORK/pki n alg
  if dry; then dsay "generate throwaway test PKI (root, intermediate, leaf1-6 (leaf2 = EC P-256), JKS + PKCS12 keystores) in a temp dir"; return 0; fi
  if [ -s "$d/thumbs.json" ] && [ -s "$d/store.jks" ] && [ -s "$KSPW_FILE" ]; then
    say "PKI already present in $d (reusing)"; return 0
  fi
  command -v openssl >/dev/null || die "openssl is required"
  command -v keytool >/dev/null || die "keytool (a JDK) is required to build the JKS/PKCS12 fixtures"
  ( umask 077
    rm -rf "$d"; mkdir -p "$d"
    openssl rand -hex 16 | tr -d '\n' > "$KSPW_FILE" )
  (
    set -e
    cd "$d"
    umask 077
    openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.crt -days 30 \
      -subj "/CN=$PREFIX Root CA" -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -keyout int.key -out int.csr -subj "/CN=$PREFIX Intermediate CA" 2>/dev/null
    printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > int.ext
    openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -out int.crt -days 30 -extfile int.ext 2>/dev/null
    for n in leaf1 leaf2 leaf3 leaf4 leaf5 leaf6; do
      alg=rsa; [ "$n" = leaf2 ] && alg=ec
      if [ "$alg" = ec ]; then
        openssl ecparam -name prime256v1 -genkey -noout -out "$n.ec.key" 2>/dev/null
        openssl pkcs8 -topk8 -nocrypt -in "$n.ec.key" -out "$n.key"
      else
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$n.key" 2>/dev/null
      fi
      openssl req -new -key "$n.key" -out "$n.csr" -subj "/CN=$n.$PREFIX.example.test" 2>/dev/null
      printf 'basicConstraints=CA:FALSE\nsubjectAltName=DNS:%s.%s.example.test\n' "$n" "$PREFIX" > "$n.ext"
      openssl x509 -req -in "$n.csr" -CA int.crt -CAkey int.key -CAcreateserial -out "$n.crt" -days 30 -extfile "$n.ext" 2>/dev/null
      cat "$n.crt" int.crt > "$n.chain2.pem"
    done
    cat int.crt root.crt > introot.crt
    # keystores: leaf1 key entry (+ chain) and the root as a trusted-cert entry
    openssl pkcs12 -export -inkey leaf1.key -in leaf1.crt -certfile int.crt -name leaf1 \
      -out p12tmp.p12 -passout "file:$KSPW_FILE" 2>/dev/null
    cp p12tmp.p12 store.p12
    keytool -importcert -noprompt -storetype PKCS12 -keystore store.p12 -storepass:file "$KSPW_FILE" \
      -alias trustedroot -file root.crt >/dev/null 2>&1
    rm -f store.jks
    keytool -importkeystore -srckeystore p12tmp.p12 -srcstoretype PKCS12 -srcstorepass:file "$KSPW_FILE" \
      -destkeystore store.jks -deststoretype JKS -deststorepass:file "$KSPW_FILE" -destkeypass:file "$KSPW_FILE" \
      -srcalias leaf1 -destalias leaf1 -noprompt >/dev/null 2>&1
    keytool -importcert -noprompt -storetype JKS -keystore store.jks -storepass:file "$KSPW_FILE" \
      -alias trustedroot -file root.crt >/dev/null 2>&1
    cp store.jks store2.jks; cp store.p12 store2.p12
    # PFX bundles for the Command import (with chain incl. root so Command can sort it)
    for n in leaf2 leaf3 leaf4; do
      openssl pkcs12 -export -inkey "$n.key" -in "$n.crt" -certfile introot.crt -name "$n" \
        -out "$n.pfx" -passout "file:$KSPW_FILE" 2>/dev/null
    done
    openssl x509 -in leaf6.crt -outform DER -out leaf6.der
  ) || die "PKI generation failed"
  ( cd "$d" || exit 1
    for n in leaf1 leaf2 leaf3 leaf4 leaf5 leaf6 int root; do
      f=$n.crt; [ "$n" = int ] && f=int.crt; [ "$n" = root ] && f=root.crt
      printf '%s\t%s\n' "$(cert_thumb "$f")" "$n"
    done > thumbs.tsv )
  jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add' "$d/thumbs.tsv" > "$d/thumbs.json"
  say "generated test PKI (leaf1-6, intermediate, root) and keystores"
}

# name_thumb NAME : the lower-case sha1 thumbprint of a generated cert
name_thumb() { jq -r --arg n "$1" 'to_entries[] | select(.value == $n) | .key' "$WORK/pki/thumbs.json"; }

# ------------------------------------------------------- command certificates
# cert_lookup NAME : Command certificate id for a generated cert, found by thumbprint
cert_lookup() {
  local th; th=$(upper "$(name_thumb "$1")")
  api GET "/Certificates?QueryString=$(printf 'Thumbprint -eq "%s"' "$th" | jq -sRr @uri)&PageReturned=1&ReturnLimit=5" \
    | jq -r '[.[]? | .Id] | first // empty'
}

# cert_import NAME [pfx|der] : import into Command once; stores state cid.NAME
cert_import() {
  local n=$1 kind=${2:-pfx} body id
  if dry; then dsay "import test certificate $n ($kind) into Command"; return 0; fi
  id=$(cert_lookup "$n")
  if [ -z "$id" ]; then
    body=$(mktemp "$WORK/tmp/imp.XXXXXX")
    if [ "$kind" = pfx ]; then
      jq -n --rawfile c <(base64 < "$WORK/pki/$n.pfx" | tr -d '\n') --rawfile p "$KSPW_FILE" '{Certificate:$c,Password:$p}' > "$body"
    else
      jq -n --rawfile c <(base64 < "$WORK/pki/$n.der" | tr -d '\n') '{Certificate:$c}' > "$body"
    fi
    api POST /Certificates/Import "$body" >/dev/null || { rm -f "$body"; return 1; }
    rm -f "$body"
    id=$(cert_lookup "$n")
  fi
  [ -n "$id" ] || return 1
  state_set "cid.$n" "$id"
}
cid() { state_get "cid.$1"; }

# ------------------------------------------------------------- discovery ----
# disc_submit TYPE CM DIRS IGNORED EXTENSIONS PATTERNS [KUBECONFIG_FILE]
#   Schedules a Command discovery job on the UO. Without KUBECONFIG_FILE the
#   job uses the UO's in-cluster identity (blank server password); with it the
#   given kubeconfig is sent as the server password (scoped-SA cases).
#   Leftover stores of the same client machine are removed first (idempotent).
disc_submit() {
  local type=$1 cm=$2 dirs=$3 ign=${4:-} ext=${5:-} pat=${6:-} kcf=${7:-} body now
  purge_cm "$cm"
  if dry; then
    dsay "PUT /CertificateStores/DiscoveryJob type=$type cm=$cm dirs='$dirs' ignored='$ign' extensions='$ext' patterns='$pat'${kcf:+ (scoped service-account kubeconfig as credential)}"
    return 0
  fi
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  body=$(mktemp "$WORK/tmp/disc.XXXXXX")
  jq -n --arg cm "$cm" --argjson t "$(st_id "$type")" --arg agent "$(state_get agent.id)" --arg now "$now" \
        --arg dirs "$dirs" --arg ign "$ign" --arg ext "$ext" --arg pat "$pat" --arg kcf "$kcf" \
        --rawfile kc "${kcf:-/dev/null}" '
    {ClientMachine:$cm, AgentId:$agent, Type:$t, JobExecutionTimestamp:$now,
     Dirs:$dirs, IgnoredDirs:(if $ign == "" then null else $ign end),
     Extensions:(if $ext == "" then null else $ext end),
     NamePatterns:(if $pat == "" then null else $pat end),
     SymLinks:false, Compatibility:false,
     ServerUsername:{SecretValue:"kubeconfig"}, ServerUseSsl:false}
    + (if $kcf == "" then {} else {ServerPassword:{SecretValue:$kc}} end)' > "$body"
  api PUT /CertificateStores/DiscoveryJob "$body" >/dev/null || { rm -f "$body"; return 1; }
  rm -f "$body"
}

# ns_live : every namespace name in the cluster, sorted
ns_live() { kube_get get ns -o json | jq -r '.items[].metadata.name' | sort; }

# fixture_only : keep only normalised secret paths in the fixture namespaces
fixture_only() { grep -E "^(${PREFIX}-(a|b|c|ign|empty)|all)/" || true; }
