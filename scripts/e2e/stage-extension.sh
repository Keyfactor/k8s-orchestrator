#!/usr/bin/env bash
# shellcheck shell=bash
#
# stage-extension.sh stage|restore|status
#
#   stage    put the build under test (E2E_EXT_BUILD_PATH) on the UO. First records
#            the UO's CURRENT extension entry and snapshots its local artifact into
#            the work dir so it can be put back byte-for-byte.
#   restore  put the recorded previous extension back and confirm it.
#   status   show whether this run has an extension staged.
#
# How: a private copy of the kfclab spec (E2E_KFCLAB_SPEC, copied into the work
# dir with mode 600 because it can contain lab credentials) is edited and
# `kfclab extension update` re-stages the artifact and restarts the UO pod.
# The original spec is never modified. Restarting the UO interrupts any other
# job running on it; run this against a lab you own.
#
# `stage` leaves the UO running the build under test until `restore` (or
# cleanup.sh, which calls restore if a stage is still outstanding).
PHASE=stage-extension
# shellcheck source=scripts/e2e/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
E2E_USAGE_EXTRA="stage|restore|status"
e2e_init "$@"
MODE=${E2E_REST[0]:-}
case $MODE in stage|restore|status) : ;; *) e2e_usage >&2; die "first argument must be stage, restore or status" ;; esac
case $MODE in
  status)  lab_require_kube ;;
  restore) lab_require_stage restore ;;
  *)       lab_require_stage ;;
esac

SPEC=$WORK/state/kfclab-spec.yaml
NODE_ORIG=$WORK/state/ext.orig.json
FP_BEFORE=$WORK/state/ext.fp.before
# The UO checks in with Command about every 5 minutes, so allow a little more than that.
: "${E2E_STAGE_TIMEOUT:=420}"

agent_seen() {
  api GET "/Agents?PageReturned=1&ReturnLimit=500" | jq -r --arg n "$E2E_UO_AGENT" '[.[]? | select(.ClientMachine == $n) | (.LastSeen // "")] | first // ""'
}

# wait_uo_back BEFORE : the UO restarts; wait until Command sees it check in again
wait_uo_back() {
  local before=$1 now deadline
  deadline=$(( $(date +%s) + E2E_STAGE_TIMEOUT ))
  say "-- waiting for the UO to restart and check in (timeout ${E2E_STAGE_TIMEOUT}s)"
  sleep 10
  while [ "$(date +%s)" -lt "$deadline" ]; do
    now=$(agent_seen)
    if [ -n "$now" ] && [ "$now" != "$before" ]; then say "UO checked in again"; return 0; fi
    sleep 5
  done
  warn "the UO's LastSeen did not change within ${E2E_STAGE_TIMEOUT}s; verify the UO is healthy before relying on the results"
}

expand_home() { case $1 in "~"/*) printf '%s' "$HOME/${1#"~"/}" ;; *) printf '%s' "$1" ;; esac; }

case $MODE in
status)
  say "extension staged by this run: $(state_get ext.staged | grep -q yes && echo yes || echo no)"
  [ -f "$NODE_ORIG" ] && say "recorded previous entry: $(jq -r '[.name, .source, ((.path // .repo // .url // "") | split("/") | last)] | join(" ")' "$NODE_ORIG")"
  exit 0 ;;

stage)
  if dry; then
    dsay "copy the kfclab spec into the work dir (mode 600), record the '$E2E_EXT_NAME' entry of orchestrator '$E2E_UO_NAME'"
    dsay "fingerprint what the UO pod has deployed (kubectl exec sha256sum) and refuse to continue if the previous local artifact differs from it"
    dsay "snapshot the previous local artifact into the work dir"
    dsay "point the spec copy's plugin path at E2E_EXT_BUILD_PATH and run: $E2E_KFCLAB_BIN extension update --uo $E2E_UO_NAME --extension $E2E_EXT_NAME -f <spec copy>"
    dsay "wait for the UO to restart and check in with Command"
    finish
  fi
  if [ "$(state_get ext.staged)" = yes ]; then say "an extension is already staged for this run; run '$0 restore' first to stage again"; exit 0; fi
  ( umask 077; cp "$E2E_KFCLAB_SPEC" "$SPEC" ) || die "could not copy the kfclab spec"
  chmod 600 "$SPEC"
  node=$(lab_ext_get_node "$SPEC") || die "yq failed reading the spec"
  [ -n "$node" ] || die "extension '$E2E_EXT_NAME' not found under orchestrator '$E2E_UO_NAME' in the kfclab spec"
  src=$(printf '%s' "$node" | jq -r '.source // ""')
  # What the UO really runs right now. The spec names a build directory that may have been
  # rebuilt since it was deployed; restoring from it must put back exactly what is there now.
  if lab_ext_deployed_fp > "$FP_BEFORE.new" 2>/dev/null; then
    mv "$FP_BEFORE.new" "$FP_BEFORE"
  else
    rm -f "$FP_BEFORE.new" "$FP_BEFORE"
    warn "could not read the UO's deployed extension (kubectl exec); cannot confirm that the spec's previous extension is what is deployed"
  fi
  if [ "$src" = local ]; then
    oldpath=$(expand_home "$(printf '%s' "$node" | jq -r '.path // ""')")
    [ -e "$oldpath" ] || die "the previous extension's local path does not exist, cannot snapshot it for restore"
    if [ -s "$FP_BEFORE" ] && [ -d "$oldpath" ] && [ "$(lab_ext_dir_fp "$oldpath")" != "$(cat "$FP_BEFORE")" ]; then
      if [ "${E2E_ALLOW_PREVIOUS_MISMATCH:-false}" = true ]; then
        warn "the spec's previous extension differs from what the UO has deployed; restore will NOT return the UO to its current build (E2E_ALLOW_PREVIOUS_MISMATCH=true)"
      else
        die "the previous extension recorded in the spec ($oldpath) differs from what the UO has deployed. Restoring from it would change the UO's build. Rebuild or fix the spec's path first (set E2E_ALLOW_PREVIOUS_MISMATCH=true to continue anyway)"
      fi
    fi
    ( umask 077; mkdir -p "$WORK/prev-ext"; rm -rf "${WORK:?}/prev-ext"/*; cp -R "$oldpath" "$WORK/prev-ext/" )
    snap=$WORK/prev-ext/$(basename "$oldpath")
    printf '%s' "$node" | jq --arg p "$snap" '.path = $p' > "$NODE_ORIG"
    say "previous extension snapshotted (path rewritten to the snapshot for restore)"
  else
    printf '%s' "$node" > "$NODE_ORIG"
    warn "the previous extension has source='$src' (not local): restore re-applies the recorded entry, so it must still resolve to the previous build"
  fi
  chmod 600 "$NODE_ORIG"
  before=$(agent_seen)
  newnode=$(printf '%s' "$node" | jq -c --arg p "$(cd "$(dirname "$E2E_EXT_BUILD_PATH")" && pwd)/$(basename "$E2E_EXT_BUILD_PATH")" \
    '.source = "local" | .path = $p | del(.repo, .version, .url, .checksum, .assetPattern)')
  lab_ext_set_node "$SPEC" "$newnode" || die "could not edit the spec copy"
  state_set ext.staged yes        # set before applying: a half-applied stage must still be restored
  say "-- staging $(basename "$E2E_EXT_BUILD_PATH") on $E2E_UO_NAME"
  lab_ext_apply "$SPEC" || die "kfclab extension update failed; run '$0 restore' to put the previous extension back"
  wait_uo_back "$before"
  if [ -d "$E2E_EXT_BUILD_PATH" ] && lab_ext_deployed_fp > "$WORK/tmp/ext.fp.staged" 2>/dev/null; then
    if [ "$(lab_ext_dir_fp "$E2E_EXT_BUILD_PATH")" = "$(cat "$WORK/tmp/ext.fp.staged")" ]; then
      say "verified: the UO's extension directory matches the build under test"
    else
      warn "the UO's extension directory differs from E2E_EXT_BUILD_PATH after staging; results may not reflect the build under test"
    fi
  fi
  say "extension staged"
  ;;

restore)
  if dry; then
    dsay "write the recorded previous '$E2E_EXT_NAME' entry back into the spec copy and run: $E2E_KFCLAB_BIN extension update --uo $E2E_UO_NAME --extension $E2E_EXT_NAME -f <spec copy>"
    dsay "wait for the UO to restart, then compare the pod's extension directory fingerprint with the one taken before staging"
    finish
  fi
  if [ "$(state_get ext.staged)" != yes ]; then say "no extension staged by this run; nothing to restore"; exit 0; fi
  [ -s "$NODE_ORIG" ] && [ -s "$SPEC" ] || die "the recorded previous extension is missing from $WORK/state; restore it manually with kfclab"
  before=$(agent_seen)
  lab_ext_set_node "$SPEC" "$(jq -c . "$NODE_ORIG")" || die "could not edit the spec copy"
  say "-- restoring the previous extension on $E2E_UO_NAME"
  lab_ext_apply "$SPEC" || die "kfclab extension update failed while restoring; the previous entry is in $NODE_ORIG"
  wait_uo_back "$before"
  state_set ext.staged no
  if [ -s "$FP_BEFORE" ] && lab_ext_deployed_fp > "$WORK/tmp/ext.fp.after" 2>/dev/null; then
    if [ "$(cat "$FP_BEFORE")" = "$(cat "$WORK/tmp/ext.fp.after")" ]; then
      say "restored: the UO's extension directory matches what was deployed before staging"
    else
      warn "the UO's extension directory differs from what was deployed before staging; compare $FP_BEFORE with the pod's extension directory"
    fi
  else
    warn "could not compare the deployed extension with the one recorded before staging; verify the previous extension is back"
  fi
  ;;
esac
finish
