#!/usr/bin/env bash
# shellcheck shell=bash
#
# rbac.sh - cases D17..D19: discovery with a scoped service account that can
# list secrets only in namespaces <a> and <b> (not in <ign>, kube-system, ...).
#
#   D17  dirs=all with every other namespace ignored            -> Success, only a/b results
#   D18  dirs=<a>,<ign> with ignored=<ign>                      -> Success
#   D19  negative control: same SA, <ign> NOT ignored           -> fails Forbidden
#
# D19 proves the RBAC is real and that excluding ignored namespaces BEFORE any
# secret is listed is what makes D17/D18 pass.
#
# Creates (all labelled e2e-suite=<prefix>, all named <prefix>-...): namespace
# <prefix>-rbac, service account <prefix>-scoped, ClusterRole + ClusterRoleBinding
# <prefix>-ns-lister (get/list namespaces only), and a Role + RoleBinding
# <prefix>-secrets in <a> and <b>. The short-lived SA token is written into a
# kubeconfig under the work dir (mode 600) and sent to Command only as the
# credential of these discovery jobs.
#
# Needs: fixtures.sh has run; the operator may impersonate service accounts.
PHASE=rbac
# shellcheck source=scripts/e2e/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
e2e_init "$@"; e2e_no_extra
lab_require_command
resolve_lab

A=$NS_A B=$NS_B I=$NS_IGN
SA=$PREFIX-scoped
SA_USER=system:serviceaccount:$NS_RBAC:$SA
KC=$WORK/state/scoped-kubeconfig.json

# create_labelled KUBECTL_CREATE_ARGS... : client-side create rendered to json, labelled, applied
create_labelled() {
  if dry; then dsay "apply labelled: kubectl create $*"; return 0; fi
  lab_kubectl create "$@" --dry-run=client -o json | apply_labelled || die "could not create: $*"
}

setup_rbac() {
  local ns tok ca
  mk_namespace "$NS_RBAC"
  create_labelled serviceaccount "$SA" -n "$NS_RBAC"
  create_labelled clusterrole "$PREFIX-ns-lister" --verb=get,list --resource=namespaces
  create_labelled clusterrolebinding "$PREFIX-ns-lister" --clusterrole="$PREFIX-ns-lister" --serviceaccount="$NS_RBAC:$SA"
  for ns in "$A" "$B"; do
    create_labelled role "$PREFIX-secrets" -n "$ns" --verb=get,list,watch,create,update,patch,delete --resource=secrets
    create_labelled rolebinding "$PREFIX-secrets" -n "$ns" --role="$PREFIX-secrets" --serviceaccount="$NS_RBAC:$SA"
  done
  if dry; then
    dsay "check the service account's permissions with 'kubectl auth can-i --as=$SA_USER' (list secrets: $A yes, $I no, kube-system no; list namespaces yes)"
    dsay "mint a short-lived token for $SA and write a kubeconfig (mode 600) under the work dir"
    return 0
  fi
  # preconditions: the RBAC must be what the cases assume
  lab_kubectl --as="$SA_USER" auth can-i list secrets -n "$A" >/dev/null 2>&1 || die "precondition: $SA cannot list secrets in $A"
  lab_kubectl --as="$SA_USER" auth can-i list secrets -n "$B" >/dev/null 2>&1 || die "precondition: $SA cannot list secrets in $B"
  if lab_kubectl --as="$SA_USER" auth can-i list secrets -n "$I" >/dev/null 2>&1; then die "precondition: $SA can list secrets in $I (it must not)"; fi
  if lab_kubectl --as="$SA_USER" auth can-i list secrets -n kube-system >/dev/null 2>&1; then die "precondition: $SA can list secrets in kube-system (it must not)"; fi
  lab_kubectl --as="$SA_USER" auth can-i list namespaces >/dev/null 2>&1 || die "precondition: $SA cannot list namespaces"
  tok=$(lab_kubectl -n "$NS_RBAC" create token "$SA" --duration=1h) || die "could not mint a token for $SA"
  ca=$(lab_kubectl -n "$NS_RBAC" get configmap kube-root-ca.crt -o jsonpath='{.data.ca\.crt}' | base64 | tr -d '\n')
  [ -n "$ca" ] || die "could not read the cluster CA (configmap kube-root-ca.crt in $NS_RBAC)"
  ( umask 077
    jq -n --arg t "$tok" --arg ca "$ca" --arg srv "$E2E_RBAC_API_SERVER" --arg u "$SA" --arg ns "$A" '
      {kind:"Config",apiVersion:"v1",preferences:{},
       clusters:[{name:"lab",cluster:{server:$srv,"certificate-authority-data":$ca}}],
       users:[{name:$u,user:{token:$t}}],
       contexts:[{name:"ctx",context:{cluster:"lab",user:$u,namespace:$ns}}],
       "current-context":"ctx"}' > "$KC" )
  say "scoped kubeconfig written (token not shown)"
}

L() { printf '%s\n' "$@"; }

setup_rbac

# every namespace except the two the SA can read; and the same list without <ign> (negative control)
IGN=$(ns_live | grep -vx "$A" | grep -vx "$B" | paste -sd, -)
IGN2=$(ns_live | grep -vx "$A" | grep -vx "$B" | grep -vx "$I" | paste -sd, -)
dry && { IGN="<every namespace except $A and $B>"; IGN2="<same, without $I>"; }

batch_begin
disc_submit K8SSecret   "$PREFIX-sa-sec"  all "$IGN"  "" "" "$KC"; job_register d.D17a "$PREFIX-sa-sec"  "" 'Discovery$'
disc_submit K8STLSSecr  "$PREFIX-sa-tls"  all "$IGN"  "" "" "$KC"; job_register d.D17b "$PREFIX-sa-tls"  "" 'Discovery$'
disc_submit K8SJKS      "$PREFIX-sa-jks"  all "$IGN"  "" "" "$KC"; job_register d.D17c "$PREFIX-sa-jks"  "" 'Discovery$'
disc_submit K8SPKCS12   "$PREFIX-sa-p12"  all "$IGN"  "" "" "$KC"; job_register d.D17d "$PREFIX-sa-p12"  "" 'Discovery$'
disc_submit K8SSecret   "$PREFIX-sa-list" "$A,$I" "$I" "" "" "$KC"; job_register d.D18 "$PREFIX-sa-list" "" 'Discovery$'
disc_submit K8SSecret   "$PREFIX-sa-neg"  all "$IGN2" "" "" "$KC"; job_register d.D19 "$PREFIX-sa-neg"  "" 'Discovery$'
say "-- waiting for the UO to run the discovery jobs (timeout ${E2E_JOB_TIMEOUT}s each)"
batch_wait

# D17 / D18: Success and exactly the expected paths (the SA cannot see anything else)
d_ok() { # ID CM EXPECTED DESC
  local id=$1 cm=$2 exp=$3 desc=$4 res
  if dry; then verdict "$id" 1 "$desc" "$(printf '%s\n' "$exp" | csv)" ""; return 0; fi
  res=$(job_result "d.$id")
  if [ "$res" != Success ]; then
    verdict "$id" 0 "$desc" "discovery job Success" "job result='$res' message='$(job_message "d.$id" | cut -c1-200)'"
    return 0
  fi
  set_eq "$id" "$desc" "$exp" "$(discovered_paths "$cm")"
}
d_ok D17a "$PREFIX-sa-sec" "$(L "$A/secrets/op-pem" "$A/secrets/op-certonly" "$B/secrets/op-b")" \
  "K8SSecret, scoped SA, dirs=all, every other namespace ignored: Success, only a/b results"
d_ok D17b "$PREFIX-sa-tls" "$(L "$A/secrets/tls-full" "$A/secrets/tls-certonly" "$B/secrets/tls-b")" \
  "K8STLSSecr, scoped SA, dirs=all, every other namespace ignored: Success, only a/b results"
d_ok D17c "$PREFIX-sa-jks" "$(L "$A/secrets/jks-a" "$B/secrets/jks-b")" \
  "K8SJKS, scoped SA, dirs=all, every other namespace ignored: Success, only a/b results"
d_ok D17d "$PREFIX-sa-p12" "$(L "$A/secrets/p12-a" "$B/secrets/p12-b")" \
  "K8SPKCS12, scoped SA, dirs=all, every other namespace ignored: Success, only a/b results"
d_ok D18 "$PREFIX-sa-list" "$(L "$A/secrets/op-pem" "$A/secrets/op-certonly")" \
  "K8SSecret, scoped SA, dirs=<a>,<ign> with ignored=<ign>: Success"

# D19: the negative control must FAIL with Forbidden
if want D19; then
  if dry; then
    verdict D19 1 "negative control: scoped SA with <ign> not ignored fails Forbidden" "job Failure mentioning Forbidden" ""
  else
    res=$(job_result d.D19); msg=$(job_message d.D19)
    ok=0; [ "$res" = Failure ] && printf '%s' "$msg" | grep -Eqi 'forbidden|403' && ok=1
    verdict D19 "$ok" "negative control: scoped SA with <ign> not ignored fails Forbidden" "job Failure mentioning Forbidden/403" \
      "job result='$res' status='$(job_status d.D19)' message='$(printf '%s' "$msg" | cut -c1-200)'"
  fi
fi

finish
