#!/usr/bin/env bash
# shellcheck shell=bash
#
# run-all.sh - run the whole suite in order and clean up afterwards.
#
#   [stage-extension stage]  fixtures  discovery  inventory  management  rbac
#   [stage-extension restore + baseline]  cleanup
#
# Options (besides --prefix / --dry-run / --workdir / --only):
#   --stage      stage the build under test (E2E_EXT_BUILD_PATH) on the UO first,
#                and restore the previous extension at the end
#   --baseline   also run the previous-build comparison (implies --stage): after
#                the main cases the previous extension is restored and baseline.sh
#                runs against it
#   --keep       do not run cleanup at the end (cleanup.sh must then be run by hand)
#
# Cleanup runs even when a phase fails. The exit status is non-zero when any
# phase reports an unexpected FAIL or cannot run. XFAIL (known issue) does not
# fail the run; XPASS is reported loudly.
PHASE=e2e
E2E_USAGE_EXTRA="[--stage] [--baseline] [--keep]"
# shellcheck source=scripts/e2e/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
e2e_init "$@"
STAGE=0 BASELINE=0 KEEP=0
for a in ${E2E_REST[@]+"${E2E_REST[@]}"}; do
  case $a in
    --stage)    STAGE=1 ;;
    --baseline) STAGE=1; BASELINE=1 ;;
    --keep)     KEEP=1 ;;
    *) die "unknown argument: $a (try --help)" ;;
  esac
done
lab_require_command
[ "$STAGE" = 1 ] && lab_require_stage

common=(--prefix "$PREFIX")
[ -n "$WORK_ARG" ] && common+=(--workdir "$WORK_ARG")
dry && common+=(--dry-run)
[ -n "$ONLY" ] && common+=(--only "$ONLY")
ccommon=(--prefix "$PREFIX")           # cleanup / restore take no --only
[ -n "$WORK_ARG" ] && ccommon+=(--workdir "$WORK_ARG")
dry && ccommon+=(--dry-run)

RC=0 ABORT=0
dry || rm -f "$RESULTS"

run_phase() { # NAME SCRIPT ARGS...
  local name=$1 script=$2 rc; shift 2
  [ "$ABORT" = 1 ] && { say "-- skipping $name (an earlier phase could not run)"; return 0; }
  say ""; say "######## $name"
  "$E2E_DIR/$script" "$@"; rc=$?
  case $rc in
    0) : ;;
    1) RC=1 ;;
    *) RC=1; ABORT=1; say "-- $name stopped with a hard error (exit $rc)" ;;
  esac
}

[ "$STAGE" = 1 ] && run_phase "stage-extension (build under test)" stage-extension.sh stage "${common[@]}"
run_phase fixtures   fixtures.sh   "${common[@]}"
run_phase discovery  discovery.sh  "${common[@]}"
run_phase inventory  inventory.sh  "${common[@]}"
run_phase management management.sh "${common[@]}"
run_phase rbac       rbac.sh       "${common[@]}"
if [ "$BASELINE" = 1 ]; then
  run_phase "stage-extension (previous build)" stage-extension.sh restore "${ccommon[@]}"
  run_phase "baseline (previous build)" baseline.sh "${common[@]}"
fi

# ---- aggregate (before cleanup removes the work dir) -------------------------
if ! dry && [ -s "$RESULTS" ]; then
  say ""; say "######## results by case"
  awk -F'\t' '{printf "%-8s %-8s %-7s %s\n", $2, $3, ($4 == "" ? "" : "#" $4), $1}' "$RESULTS" | sort -V -k1,1 2>/dev/null || cat "$RESULTS"
  say ""
  say "totals: $(cut -f3 "$RESULTS" | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}')"
  if cut -f3 "$RESULTS" | grep -qx XPASS; then
    say "NOTE: XPASS above means a known-issue case now passes; remove its known-issue tag"
  fi
fi

# ---- always clean up, unless asked not to -----------------------------------
if [ "$KEEP" = 1 ]; then
  say ""; say "-- --keep: resources and work dir left in place; run: cleanup.sh --prefix $PREFIX"
else
  # restore the extension even when the baseline step did not run
  run_cleanup() { ABORT=0; run_phase cleanup cleanup.sh "${ccommon[@]}"; }
  run_cleanup
fi

say ""
if dry; then
  # A dry run still reports configuration errors (a missing E2E_* variable stops a phase with a hard error);
  # it must not claim success then.
  if [ "$RC" = 0 ]; then say "== dry-run complete: nothing was executed against any lab system"
  else say "== dry-run found problems (see above): nothing was executed against any lab system"; fi
  exit "$RC"
fi
if [ "$RC" = 0 ]; then say "== e2e suite finished: no unexpected failures"; else say "== e2e suite finished: FAILURES or errors (see above)"; fi
exit "$RC"
