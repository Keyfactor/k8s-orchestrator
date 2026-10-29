#!/usr/bin/env bash
# shellcheck shell=bash
#
# cleanup.sh - remove everything this suite created, and verify it is gone.
#
# Scope is the run prefix and nothing else; there is deliberately no "delete
# everything" mode:
#   Command    stores whose client machine is <prefix> or starts with <prefix>-;
#              certificates whose issuer is CN=<prefix> Root CA / Intermediate CA
#   Kubernetes namespaces, CSRs, ClusterRoles and ClusterRoleBindings that carry
#              the label e2e-suite=<prefix> AND are named <prefix>-* (the single
#              exception is the namespace literally named "all", which is deleted
#              only when it carries our label)
#   Extension  if this run staged a build on the UO and has not restored the
#              previous one, it is restored first (see stage-extension.sh)
#   Local      the work dir (generated keys, kubeconfig, state), only after every
#              check above passed
#
# Exit status is non-zero when anything could not be removed or verified.
# Needs: the same variables as the other phases (see lab-env.sh).
PHASE=cleanup
E2E_USAGE_EXTRA="[--keep-workdir] [--k8s-only]"
# shellcheck source=scripts/e2e/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
e2e_init "$@"
KEEP=0 K8S_ONLY=0
for a in ${E2E_REST[@]+"${E2E_REST[@]}"}; do
  case $a in
    --keep-workdir) KEEP=1 ;;
    --k8s-only)     K8S_ONLY=1 ;;
    *) die "unknown argument: $a (try --help)" ;;
  esac
done
if [ "$K8S_ONLY" = 1 ]; then lab_require_kube; else lab_require_command; fi

LEFT=0
leftover() { warn "$*"; LEFT=$((LEFT + 1)); }

# owned NAME : our naming scheme (prefix-*) or the fixed namespace "all"
owned() { case $1 in "$PREFIX"-*|all) return 0 ;; *) return 1 ;; esac; }

# ---- 1. extension ------------------------------------------------------------
if [ "$K8S_ONLY" = 0 ] && { [ "$(state_get ext.staged)" = yes ] || dry; }; then
  say "-- restoring the UO's previous extension (if this run staged one)"
  rargs=(restore --prefix "$PREFIX")
  [ -n "$WORK_ARG" ] && rargs+=(--workdir "$WORK_ARG")
  dry && rargs+=(--dry-run)
  "$E2E_DIR/stage-extension.sh" "${rargs[@]}" || die "could not restore the previous extension; nothing else was removed (fix this first)"
fi

# ---- 2. command --------------------------------------------------------------
# FAIL CLOSED: an API error (no token, HTTP 000, non-2xx, unparsable answer) is never read as
# "nothing there". own_store_ids / own_cert_ids return non-zero when Command cannot be asked,
# and every list below is checked for that before it is used, both before the delete and for
# the final verification.
cleanup_abort() {
  say "== cleanup FAILED: $*"
  say "==   NOTHING is verified: resources carrying prefix $PREFIX may still exist. Work dir kept at $WORK."
  say "==   Fix the cause and run cleanup.sh --prefix $PREFIX again."
  exit 1
}
count_lines() { printf '%s\n' "$1" | grep -c . || true; }

if [ "$K8S_ONLY" = 0 ]; then
  say "-- Command: stores with client machine '$PREFIX' / '$PREFIX-*'"
  if dry; then
    dsay "list stores owned by prefix $PREFIX, DELETE /CertificateStores for them, then verify none remain"
    dsay "find certificates issued by CN=$PREFIX Root/Intermediate CA, DELETE /Certificates for them, then verify none remain"
  else
    ids=$(own_store_ids) || cleanup_abort "could not list the Command stores (API error, see above); not treating that as an empty list"
    n=$(count_lines "$ids")
    say "found $n store(s)"
    if [ "$n" -gt 0 ]; then
      # shellcheck disable=SC2086
      delete_stores $ids || leftover "Command did not accept the store delete"
    fi
    left_ids=$(own_store_ids) || cleanup_abort "could not re-list the Command stores to verify the delete (API error, see above)"
    left=$(count_lines "$left_ids")
    [ "$left" -gt 0 ] && leftover "$left Command store(s) still present after delete"

    say "-- Command: certificates issued by the suite's test CAs"
    cids=$(own_cert_ids) || cleanup_abort "could not list the Command certificates (API error, see above); not treating that as an empty list"
    n=$(count_lines "$cids")
    say "found $n certificate(s)"
    if [ "$n" -gt 0 ]; then
      body=$(mktemp "$TMPD/delc.XXXXXX") || cleanup_abort "cannot create a scratch file in $TMPD"
      printf '%s\n' "$cids" | jq -R 'tonumber' | jq -s . > "$body"
      api DELETE /Certificates "$body" >/dev/null || warn "certificate delete was rejected by Command"
      rm -f "$body"
      left_ids=$(own_cert_ids) || cleanup_abort "could not re-list the Command certificates to verify the delete (API error, see above)"
      left=$(count_lines "$left_ids")
      [ "$left" -gt 0 ] && leftover "$left test certificate(s) still present in Command (is certificate deletion permitted for this token?)"
    fi
  fi
fi

# ---- 3. kubernetes -----------------------------------------------------------
# k8s_list KIND [SELECTOR] : object names of KIND (label selector optional), one per line.
# Non-zero when the cluster cannot be asked.
k8s_list() {
  local out
  if [ -n "${2:-}" ]; then out=$(lab_kubectl get "$1" -l "$2" -o name) || return 1
  else out=$(lab_kubectl get "$1" -o name) || return 1; fi
  printf '%s\n' "$out" | sed 's#^[^/]*/##' | sed '/^$/d'
}

say "-- Kubernetes: objects labelled $LBL_KEY=$LBL_VAL"
if dry; then
  dsay "delete namespaces / CSRs / ClusterRoleBindings / ClusterRoles labelled $LBL_KEY=$LBL_VAL and named $PREFIX-* (or the namespace 'all' when labelled), then verify none remain"
else
  sel="$LBL_KEY=$LBL_VAL"
  names=$(k8s_list ns "$sel") || cleanup_abort "could not list namespaces in kube context $E2E_KUBE_CONTEXT"
  for ns in $names; do
    if owned "$ns"; then lab_kubectl delete ns "$ns" --wait=true --timeout=180s >/dev/null || leftover "namespace $ns could not be deleted"
    else leftover "namespace $ns carries our label but is not named $PREFIX-*; not deleting it"; fi
  done
  for kind in csr clusterrolebinding clusterrole; do
    names=$(k8s_list "$kind" "$sel") || cleanup_abort "could not list $kind objects in kube context $E2E_KUBE_CONTEXT"
    for o in $names; do
      case $o in "$PREFIX"-*) lab_kubectl delete "$kind" "$o" >/dev/null || leftover "$kind $o could not be deleted" ;;
                 *) leftover "$kind $o carries our label but is not named $PREFIX-*; not deleting it" ;; esac
    done
  done
  # verify
  for kind in ns csr clusterrolebinding clusterrole; do
    names=$(k8s_list "$kind" "$sel") || cleanup_abort "could not re-list $kind objects to verify the delete"
    left=$(count_lines "$names")
    [ "$left" -gt 0 ] && leftover "$left $kind object(s) labelled $sel still present"
  done
  # unlabelled look-alikes are reported, never deleted
  names=$(k8s_list ns) || cleanup_abort "could not list namespaces in kube context $E2E_KUBE_CONTEXT"
  for ns in $(printf '%s\n' "$names" | grep -E "^${PREFIX}-" || true); do
    leftover "namespace $ns matches the prefix but is not labelled; it was not created by this suite or lost its label. Not deleting it."
  done
fi


# ---- 4. local ----------------------------------------------------------------
if dry; then
  dsay "remove the work dir (generated keys, kubeconfig, state) if everything above verified"
  finish
fi
if [ "$LEFT" -gt 0 ]; then
  say "== cleanup incomplete: $LEFT problem(s); work dir kept at $WORK for a retry"
  exit 1
fi
if [ "$KEEP" = 1 ]; then
  say "work dir kept (--keep-workdir): $WORK"
else
  case $WORK in ""|/|"$HOME") die "refusing to remove work dir '$WORK'" ;; esac
  [ -f "$WORK/.e2e-suite-workdir" ] || die "refusing to remove $WORK: it is not a suite work dir"
  rm -rf "$WORK"
  [ -e "$WORK" ] && { say "== cleanup incomplete: could not remove $WORK"; exit 1; }
  say "work dir removed"
fi
if [ "$K8S_ONLY" = 1 ]; then
  say "== cleanup verified (Kubernetes only; Command was not checked): nothing carrying prefix $PREFIX remains in the cluster"
else
  say "== cleanup verified: nothing carrying prefix $PREFIX remains in Command or the cluster"
fi
exit 0
