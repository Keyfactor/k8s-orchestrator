#!/usr/bin/env bash
# shellcheck shell=bash
#
# discovery.sh - cases D1..D19 (D17-D19 live in rbac.sh).
#
# Submits one Command discovery job per case (PUT /CertificateStores/DiscoveryJob),
# waits for the UO to finish them, then compares the stores Command received
# for that case's client machine with the expected set. Secret-level results are
# compared only inside the fixture namespaces, so unrelated lab secrets cannot
# make a case fail.
#
# Needs: fixtures.sh has run; E2E_KUBE_CONTEXT + the Command variables.
PHASE=discovery
# shellcheck source=scripts/e2e/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
e2e_init "$@"; e2e_no_extra
lab_require_command
resolve_lab

L() { printf '%s\n' "$@"; }
A=$NS_A B=$NS_B C=$NS_C I=$NS_IGN
UP=$(upper "$PREFIX")

# ID|TYPE|CLIENT-MACHINE|DIRS|IGNORED|EXTENSIONS|PATTERNS|DESCRIPTION
cases() {
  cat <<EOF
D1|K8SNS|$PREFIX-ns-all|all|||| K8SNS dirs=all: one store per namespace incl. the empty one and the one named 'all'
D2|K8SNS|$PREFIX-ns-list|$A,$B|||| K8SNS dirs=<a>,<b>: exactly those two
D3|K8SNS|$PREFIX-ns-ign|all|$I||| K8SNS dirs=all, ignored=<ign>: everything but <ign>
D4|K8SNS|$PREFIX-ns-ci|all|$UP-IGN,ALL||| K8SNS ignored list is case-insensitive: <ign> and 'all' absent
D5|K8SSecret|$PREFIX-sec-all|all|||| K8SSecret dirs=all: only secrets holding a certificate field
D6|K8SSecret|$PREFIX-sec-list|$A,$B|||| K8SSecret dirs=<a>,<b>
D7|K8SSecret|$PREFIX-sec-ign|all|$I||| K8SSecret ignored=<ign>: op-ign absent
D8|K8SSecret|$PREFIX-sec-ci|all| $UP-IGN , all ||| K8SSecret ignored list is case/whitespace tolerant: op-ign and op-all absent
D9|K8SSecret|$PREFIX-sec-pat|$A|||tls.key| K8SSecret patterns=tls.key (additive): also finds op-keyonly
D10|K8STLSSecr|$PREFIX-tls-all|all|||| K8STLSSecr dirs=all: every kubernetes.io/tls secret incl. tls-certonly
D11a|K8STLSSecr|$PREFIX-tls-list|$A,$B|||| K8STLSSecr dirs=<a>,<b>
D11b|K8STLSSecr|$PREFIX-tls-ign|all|$I||| K8STLSSecr ignored=<ign>: tls-ign absent
D12|K8SJKS|$PREFIX-jks-all|all|||| K8SJKS dirs=all: keystore fields matched by suffix (.jks)
D13a|K8SJKS|$PREFIX-jks-list|$A,$B|||| K8SJKS dirs=<a>,<b>
D13b|K8SJKS|$PREFIX-jks-ign|all|$I||| K8SJKS ignored=<ign>: jks-ign absent
D14a|K8SPKCS12|$PREFIX-p12-all|all|||| K8SPKCS12 dirs=all: p12/pfx fields
D14b|K8SPKCS12|$PREFIX-p12-list|$A,$B|||| K8SPKCS12 dirs=<a>,<b>
D14c|K8SPKCS12|$PREFIX-p12-ign|all|$I||| K8SPKCS12 ignored=<ign>
D15|K8SCert|$PREFIX-cert-all|all|||| K8SCert dirs=all: the issued CSR is found
EOF
}

# expected normalised results for a case id (secret types: <ns>/secrets/<name>; K8SNS: namespace names)
expected() {
  case $1 in
    D1)   ns_live ;;
    D2)   L "$A" "$B" ;;
    D3)   ns_live | grep -vx "$I" ;;
    D4)   ns_live | grep -vx "$I" | grep -vx all ;;
    D5)   L "$A/secrets/op-pem" "$A/secrets/op-certonly" "$B/secrets/op-b" "$I/secrets/op-ign" "all/secrets/op-all" ;;
    D6)   L "$A/secrets/op-pem" "$A/secrets/op-certonly" "$B/secrets/op-b" ;;
    D7)   L "$A/secrets/op-pem" "$A/secrets/op-certonly" "$B/secrets/op-b" "all/secrets/op-all" ;;
    D8)   L "$A/secrets/op-pem" "$A/secrets/op-certonly" "$B/secrets/op-b" ;;
    D9)   L "$A/secrets/op-pem" "$A/secrets/op-certonly" "$A/secrets/op-keyonly" ;;
    D10)  L "$A/secrets/tls-full" "$A/secrets/tls-certonly" "$B/secrets/tls-b" "$C/secrets/tls-c" "$I/secrets/tls-ign" "all/secrets/tls-all" ;;
    D11a) L "$A/secrets/tls-full" "$A/secrets/tls-certonly" "$B/secrets/tls-b" ;;
    D11b) L "$A/secrets/tls-full" "$A/secrets/tls-certonly" "$B/secrets/tls-b" "$C/secrets/tls-c" "all/secrets/tls-all" ;;
    D12)  L "$A/secrets/jks-a" "$B/secrets/jks-b" "$I/secrets/jks-ign" ;;
    D13a|D13b) L "$A/secrets/jks-a" "$B/secrets/jks-b" ;;
    D14a|D14b|D14c) L "$A/secrets/p12-a" "$B/secrets/p12-b" ;;
    D15)  L "$CSR_NAME" ;;
  esac
}

# ---- phase 1: submit everything --------------------------------------------
batch_begin
SUBMITTED=""
while IFS='|' read -r -u 3 id type cm dirs ign ext pat desc; do
  [ -n "$id" ] || continue
  desc=${desc# }
  want "$id" || continue
  disc_submit "$type" "$cm" "$dirs" "$ign" "$ext" "$pat" || { sched_fail "d.$id" "discovery job for $id ($type)"; continue; }
  sched_ok
  job_register "d.$id" "$cm" "" 'Discovery$'
  SUBMITTED="$SUBMITTED $id"
done 3<<EOF
$(cases)
EOF

# D16: K8SCluster has no discovery capability in the shipped store type
if want D16; then
  if dry; then
    dsay "D16: would check the K8SCluster store type's Discovery capability and skip when it is false"
  elif [ "$(state_get st.K8SCluster.discovery)" = false ]; then
    skip D16 "K8SCluster discovery" "store type K8SCluster has Discovery=false in this Command; not testable"
  else
    skip D16 "K8SCluster discovery" "K8SCluster reports Discovery=true here; expected behaviour is not defined, case not codified"
  fi
fi

say "-- waiting for the UO to run the discovery jobs (timeout ${E2E_JOB_TIMEOUT}s each)"
batch_wait

# ---- phase 2: evaluate -----------------------------------------------------
while IFS='|' read -r -u 3 id type cm dirs ign ext pat desc; do
  [ -n "$id" ] || continue
  desc=${desc# }
  want "$id" || continue
  if dry; then
    e=$(expected "$id" | csv)
    [ -n "$e" ] || e="<every namespace in the cluster, minus the ignored ones>"
    verdict "$id" 1 "$desc" "$e" ""
    continue
  fi
  res=$(job_result "d.$id")
  if [ "$res" != Success ]; then
    verdict "$id" 0 "$desc" "discovery job Success" "job result='$res' status='$(job_status "d.$id")' message='$(job_message "d.$id" | cut -c1-200)'"
    continue
  fi
  paths=$(discovered_paths "$cm")
  case $type in
    K8SNS)
      actual=$(printf '%s\n' "$paths" | sed -n 's#^namespace/##p')
      set_eq "$id" "$desc" "$(expected "$id")" "$actual" ;;
    K8SCert)
      # every issued CSR in the cluster is a candidate; only ours matters
      if printf '%s\n' "$paths" | grep -qx "$CSR_NAME"; then
        verdict "$id" 1 "$desc" "$CSR_NAME found" "$CSR_NAME found ($(printf '%s\n' "$paths" | grep -c .) CSR(s) discovered)"
      else
        verdict "$id" 0 "$desc" "$CSR_NAME found" "not among $(printf '%s\n' "$paths" | grep -c .) discovered CSR(s)"
      fi ;;
    *)
      actual=$(printf '%s\n' "$paths" | fixture_only)
      set_eq "$id" "$desc" "$(expected "$id")" "$actual" ;;
  esac
done 3<<EOF
$(cases)
EOF

say "-- discovery cases D17-D19 (scoped service account) run in rbac.sh"
finish
