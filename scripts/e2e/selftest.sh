#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC1091,SC2030,SC2031  # lib.sh is sourced inside subshells on purpose; variables set there must not leak
#
# selftest.sh - offline self-test of the suite's own safety nets. Needs no lab, no Command,
# no cluster: curl, kubectl and kfclab are replaced by mocks on PATH. Run it after changing
# lib.sh, cleanup.sh or any helper that schedules a job:
#
#   scripts/e2e/selftest.sh
#
# What it proves
#   - cleanup FAILS CLOSED: with a Command that cannot be reached (HTTP 000), answers HTTP
#     500, answers something that is not a list, or gives no token, cleanup exits non-zero
#     and never prints "verified" (the first real run printed "verified" after it could not
#     reach Command at all)
#   - the same for an unreachable cluster
#   - the positive control: a reachable, empty lab does end in "verified" with exit 0
#   - a missing scratch dir is recreated, and a child phase does not remove its parent's
#     scratch space
#   - a rejected scheduling request is a FAIL at once with Command's reason, and three in a
#     row abort the phase
#   - --dry-run makes no external call at all
set -u -o pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/e2e-selftest.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
FAILS=0
ok()   { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; FAILS=$((FAILS + 1)); }

# ---- mocks -------------------------------------------------------------------
mkdir -p "$T/bin"
cat > "$T/bin/curl" <<'EOF'
#!/usr/bin/env bash
# mock curl: MOCK_CURL = down | http500 | notarray | empty | rejected | history
out=""; method=GET; url=""
while [ $# -gt 0 ]; do
  case $1 in
    -o) out=$2; shift 2 ;;
    -X) method=$2; shift 2 ;;
    -w|-H|--data|--cacert|-K) shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
cat > /dev/null
printf '%s %s\n' "$method" "$url" >> "$MOCK_LOG"
case ${MOCK_CURL:-down} in
  down)     printf '000'; exit 7 ;;
  http500)  printf '{"Message":"boom"}' > "$out"; printf '500' ;;
  notarray) printf '{}' > "$out"; printf '200' ;;
  empty)    printf '[]' > "$out"; printf '200' ;;
  rejected) printf '{"ErrorCode":"0xA0110010","Message":"Jobs could not be scheduled.","FailedOperations":[{"Identifier":"x","Reason":"No private key could be found for the given certificate"}]}' > "$out"; printf '400' ;;
  history)  case $url in *JobHistory*) cp "$MOCK_HIST" "$out" ;; *) printf '{}' > "$out" ;; esac; printf '200' ;;
esac
EOF
cat > "$T/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
printf 'kubectl %s\n' "$*" >> "$MOCK_LOG"
[ "${MOCK_KUBE:-ok}" = down ] && { echo "Unable to connect to the server" >&2; exit 1; }
exit 0
EOF
cat > "$T/bin/kfclab" <<'EOF'
#!/usr/bin/env bash
printf 'kfclab %s\n' "$*" >> "$MOCK_LOG"
exit 0
EOF
chmod +x "$T/bin/curl" "$T/bin/kubectl" "$T/bin/kfclab"

export MOCK_LOG=$T/calls.log
export PATH=$T/bin:$PATH
export E2E_KUBE_CONTEXT=selftest-ctx E2E_COMMAND_URL=https://command.invalid/KeyfactorAPI
export E2E_TOKEN_CMD='printf "a.b.c"' E2E_UO_NAME=selftest-uo E2E_JOB_TIMEOUT=2 E2E_JOB_POLL=1
export E2E_KFCLAB_SPEC=$T/spec.yaml E2E_EXT_BUILD_PATH=$T/build   # only named, never read (dry run, no staging)
unset E2E_ENV_FILE E2E_CA_CERT E2E_KUBECONFIG
P=e2e-selftest

# run_cleanup CURLMODE KUBEMODE [extra env assignments...] -> output in $T/out, status in $RC
run_cleanup() {
  local cm=$1 km=$2; shift 2
  rm -rf "$T/work"; : > "$MOCK_LOG"
  env MOCK_CURL="$cm" MOCK_KUBE="$km" "$@" "$HERE/cleanup.sh" --prefix "$P" --workdir "$T/work" > "$T/out" 2>&1
  RC=$?
}

expect_cleanup_fails() { # DESC CURLMODE KUBEMODE [env...]
  local d=$1; shift
  run_cleanup "$@"
  if [ "$RC" -ne 0 ] && ! grep -q 'cleanup verified' "$T/out"; then ok "cleanup fails closed: $d (exit $RC)"
  else fail "cleanup must fail and never say 'verified': $d (exit $RC)"; sed 's/^/        /' "$T/out" | tail -5; fi
}

expect_cleanup_fails "Command unreachable (HTTP 000)"        down   ok
expect_cleanup_fails "Command answers HTTP 500"              http500 ok
expect_cleanup_fails "Command answers something not a list"  notarray ok
expect_cleanup_fails "no API token"                          empty  ok E2E_TOKEN_CMD=false
expect_cleanup_fails "cluster unreachable"                   empty  down

run_cleanup empty ok
if [ "$RC" -eq 0 ] && grep -q 'cleanup verified' "$T/out"; then ok "positive control: an empty, reachable lab ends in 'verified' (exit 0)"
else fail "positive control: expected 'verified' and exit 0 (exit $RC)"; tail -5 "$T/out"; fi

# ---- scratch dir ---------------------------------------------------------------
# a child phase (cleanup.sh -> stage-extension.sh) must not remove its parent's scratch space
# shellcheck source=scripts/e2e/lib.sh
(
  PHASE=selftest
  . "$HERE/lib.sh"
  e2e_init --prefix "$P" --workdir "$T/w2"
  parent_tmp=$TMPD
  bash -c '. "$1/lib.sh"; PHASE=child; e2e_init --prefix "$2" --workdir "$3"' _ "$HERE" "$P" "$T/w2" > /dev/null 2>&1
  [ -d "$parent_tmp" ] || exit 1
  # and a vanished scratch dir is recreated instead of breaking every API call
  rm -rf "$T/w2/tmp"
  export MOCK_CURL=empty
  api GET /Agents > /dev/null || exit 2
  [ -d "$parent_tmp" ] || exit 3
) > /dev/null 2>&1
case $? in
  0) ok "a child phase leaves the parent's scratch dir alone; a vanished scratch dir is recreated" ;;
  *) fail "scratch dir handling (code $?)" ;;
esac

# ---- scheduling guard ----------------------------------------------------------
sched_out=$(
  PHASE=selftest
  . "$HERE/lib.sh"
  e2e_init --prefix "$P" --workdir "$T/w3" > /dev/null
  export MOCK_CURL=rejected E2E_MAX_REJECTS=3
  for i in 1 2 3 4 5; do
    api POST /CertificateStores/Certificates/Add > /dev/null 2>&1
    sched_fail "w1.X$i" "Add leaf to store 'x$i'" 2>/dev/null
  done
  echo "NOT REACHED"
) 2>&1
rc=$?
if [ "$rc" -eq 1 ] && ! printf '%s' "$sched_out" | grep -q 'NOT REACHED' \
   && [ "$(printf '%s\n' "$sched_out" | grep -c '^FAIL ')" -eq 3 ] \
   && printf '%s' "$sched_out" | grep -q 'No private key could be found' \
   && printf '%s' "$sched_out" | grep -q 'ABORTING phase'; then
  ok "rejected requests: FAIL with Command's reason, phase aborted after 3 in a row (exit 1)"
else
  fail "scheduling guard (exit $rc)"; printf '%s\n' "$sched_out" | tail -8
fi

# ---- expect-rejection mode -------------------------------------------------------
# A case whose expected outcome is a refusal passes when EITHER Command rejects at scheduling
# (4xx: recorded as the job result "Refused", not a FAIL, the abort streak is left alone) OR the
# job runs and fails with the extension's message. It must still fail when the request is
# accepted and succeeded. A 5xx is no refusal.
ref_out=$(
  PHASE=selftest
  . "$HERE/lib.sh"
  e2e_init --prefix "$P" --workdir "$T/w4" > /dev/null
  export MOCK_CURL=rejected E2E_MAX_REJECTS=3
  api POST /CertificateStores/Certificates/Add > /dev/null 2>&1
  sched_fail "r1" "Add a" 2>/dev/null
  sched_fail "r2" "Add b" 2>/dev/null
  sched_refused "rr" "Add c" 2>/dev/null          # expected refusal: neither a FAIL nor part of the streak
  echo "AFTER-REFUSAL streak=$SCHED_STREAK fails=$N_FAIL result=$(job_result rr) layer=$(refusal_layer rr)"
  refused_ok rr 'already exists' && echo "REFUSED-AT-SCHEDULING-OK"
  # the job ran and the extension refused
  jq -n '{Result:"Failure",Status:"CompletedWillRetry",Message:"Secret x already exists. Set overwrite=true to replace."}' > "$WORK/jobs/ext.json"
  refused_ok ext 'already exists' && echo "REFUSED-BY-EXTENSION-OK layer=$(refusal_layer ext)"
  # failed for some other reason, or succeeded (the existing alias was replaced): NOT a refusal
  jq -n '{Result:"Failure",Message:"Kubernetes API timeout"}' > "$WORK/jobs/other.json"
  refused_ok other 'already exists' || echo "OTHER-FAILURE-NOT-A-REFUSAL"
  jq -n '{Result:"Success",Status:"Completed",Message:""}' > "$WORK/jobs/ok.json"
  refused_ok ok 'already exists' || echo "SUCCESS-NOT-A-REFUSAL layer=$(refusal_layer ok)"
  # the third REAL rejection in a row still aborts, so the refusal did not reset or advance the streak
  sched_fail "r3" "Add d" 2>/dev/null
  echo "NOT REACHED"
) 2>&1
ref_rc=$?
if [ "$ref_rc" -eq 1 ] \
   && printf '%s' "$ref_out" | grep -q 'AFTER-REFUSAL streak=2 fails=2 result=Refused layer=command-scheduling' \
   && printf '%s' "$ref_out" | grep -q 'REFUSED-AT-SCHEDULING-OK' \
   && printf '%s' "$ref_out" | grep -q 'REFUSED-BY-EXTENSION-OK layer=extension-job' \
   && printf '%s' "$ref_out" | grep -q 'OTHER-FAILURE-NOT-A-REFUSAL' \
   && printf '%s' "$ref_out" | grep -q 'SUCCESS-NOT-A-REFUSAL layer=none' \
   && printf '%s' "$ref_out" | grep -q 'ABORTING phase' \
   && ! printf '%s' "$ref_out" | grep -q 'NOT REACHED' \
   && [ "$(printf '%s\n' "$ref_out" | grep -c '^FAIL ')" -eq 3 ]; then
  ok "expect-rejection mode: Command's 4xx and the extension's failure both count as a refusal, a success or another failure does not, and an expected refusal stays out of the abort streak"
else
  fail "expect-rejection mode (exit $ref_rc)"; printf '%s\n' "$ref_out" | tail -12
fi

h500=$(
  PHASE=selftest
  . "$HERE/lib.sh"
  e2e_init --prefix "$P" --workdir "$T/w5" > /dev/null
  export MOCK_CURL=http500 E2E_MAX_REJECTS=3
  api POST /CertificateStores/Certificates/Add > /dev/null 2>&1
  sched_refused "r5" "Add e" 2>/dev/null
  echo "RESULT=$(job_result r5) fails=$N_FAIL"
) 2>&1
if printf '%s' "$h500" | grep -q 'RESULT=Rejected fails=1' && printf '%s\n' "$h500" | grep -q '^FAIL '; then
  ok "expect-rejection mode: an HTTP 5xx is not a refusal (it is a FAIL)"
else
  fail "expect-rejection mode must not take an HTTP 5xx for a refusal"; printf '%s\n' "$h500" | tail -5
fi

# ---- failed jobs are unscheduled ---------------------------------------------------
# Command re-runs a failed job every ~5 minutes; a retry of a refused Add recreated a secret that
# a later Remove had deleted (first real run, M7). batch_wait unschedules such a job.
export MOCK_HIST=$T/hist.json
jq -n '[{JobHistoryId:5,JobId:"11111111-2222-3333-4444-555555555555",ClientMachine:"cm-x",StorePath:"ns/sec",JobType:"K8SSecretManagement",Status:"CompletedWillRetry",Result:"Failure",Message:"refused"},
        {JobHistoryId:6,JobId:"66666666-2222-3333-4444-555555555555",ClientMachine:"cm-x",StorePath:"ns/other",JobType:"K8SSecretManagement",Status:"Completed",Result:"Success",Message:""}]' > "$MOCK_HIST"
unsched() { # NO_UNSCHEDULE (true|false) -> number of Unschedule calls
  : > "$MOCK_LOG"
  (
    PHASE=selftest
    . "$HERE/lib.sh"
    e2e_init --prefix "$P" --workdir "$T/w6$$$RANDOM" > /dev/null
    export MOCK_CURL=history
    export E2E_NO_UNSCHEDULE=$1
    BATCH_BASE=0
    job_register fail1 cm-x ns/sec 'Management$'
    job_register good1 cm-x ns/other 'Management$'
    batch_wait
    echo "RESULTS $(job_result fail1)/$(job_result good1)"
  ) > "$T/unsched.out" 2>&1
  grep -c 'POST .*OrchestratorJobs/Unschedule' "$MOCK_LOG" || true
}
n_un=$(unsched false)
if [ "$n_un" = 1 ] && grep -q 'RESULTS Failure/Success' "$T/unsched.out"; then
  ok "a failed (CompletedWillRetry) job is unscheduled, a successful one is left alone (1 Unschedule call)"
else
  fail "batch_wait must unschedule exactly the failed job (calls: $n_un)"; tail -5 "$T/unsched.out"
fi
n_un=$(unsched true)
if [ "$n_un" = 0 ]; then ok "E2E_NO_UNSCHEDULE=true keeps Command's retries (0 Unschedule calls)"
else fail "E2E_NO_UNSCHEDULE=true must not unschedule (calls: $n_un)"; fi

# ---- dry run -------------------------------------------------------------------
: > "$MOCK_LOG"
for s in fixtures discovery inventory management rbac baseline cleanup; do
  "$HERE/$s.sh" --dry-run --prefix "$P" > /dev/null 2>&1 || fail "dry-run of $s.sh exited non-zero"
done
"$HERE/run-all.sh" --dry-run --prefix "$P" > /dev/null 2>&1 || fail "dry-run of run-all.sh exited non-zero"
if [ ! -s "$MOCK_LOG" ]; then ok "--dry-run made no curl, kubectl or kfclab call in any phase"
else fail "--dry-run made external calls:"; sed 's/^/        /' "$MOCK_LOG" | head -5; fi

echo
if [ "$FAILS" -eq 0 ]; then echo "selftest: all checks passed"; exit 0; fi
echo "selftest: $FAILS check(s) FAILED"; exit 1
