#!/usr/bin/env bash
# shellcheck shell=bash
#
# inventory.sh - cases I1..I13: approve stores that discovery found, run
# inventory, and compare what Command received (alias, private-key flag,
# certificate thumbprints mapped back to the generated cert names) with the
# fixtures.
#
# Stores are approved from the discovered entries WITHOUT pre-filling the
# namespace or secret name, so the extension's resolution of discovered store
# paths is part of what is tested. The two exceptions are I4 (a key-only secret
# that discovery correctly does not report) and I12 (K8SCluster has no
# discovery); those stores are created by hand.
#
# Needs: fixtures.sh and discovery.sh have run (the discovered stores must exist).
PHASE=inventory
# shellcheck source=scripts/e2e/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
e2e_init "$@"; e2e_no_extra
lab_require_command
resolve_lab

A=$NS_A B=$NS_B C=$NS_C I=$NS_IGN
CM_MANUAL=$PREFIX-manual

# ID|TYPE|SOURCE|PATH|PROPS|USEPW|DESCRIPTION
#   SOURCE: a discovery client machine suffix (path = normalised discovered path), or
#           "manual" (path = the store path to create)
cases() {
  cat <<EOF
I1|K8SSecret|sec-list|$A/secrets/op-pem|{}||K8SSecret op-pem: leaf + intermediate, private key
I2|K8SSecret|sec-list|$A/secrets/op-certonly|{}||K8SSecret op-certonly: leaf4, no key
I3|K8SSecret|sec-list|$B/secrets/op-b|{}||K8SSecret op-b: leaf3, private key
I4|K8SSecret|manual|$A/op-keyonly|{"KubeNamespace":"$A","KubeSecretName":"op-keyonly"}||K8SSecret key-only secret: Success, 'No certificates found in store'
I5|K8STLSSecr|tls-list|$A/secrets/tls-full|{}||K8STLSSecr tls-full: leaf1 + intermediate, private key
I6|K8STLSSecr|tls-list|$A/secrets/tls-certonly|{}||K8STLSSecr tls-certonly (empty tls.key): leaf5, no key
I7|K8SJKS|jks-list|$A/secrets/jks-a|{"CertificateDataFieldName":"keystore.jks"}|yes|K8SJKS jks-a: key alias + trusted root alias without key
I8|K8SJKS|jks-list|$B/secrets/jks-b|{"CertificateDataFieldName":"app.jks"}|yes|K8SJKS jks-b (field app.jks): same shape
I9a|K8SPKCS12|p12-list|$A/secrets/p12-a|{"CertificateDataFieldName":"keystore.p12"}|yes|K8SPKCS12 p12-a: key alias + trusted root alias without key
I9b|K8SPKCS12|p12-list|$B/secrets/p12-b|{"CertificateDataFieldName":"app.pfx"}|yes|K8SPKCS12 p12-b (field app.pfx): same shape
I10a|K8SNS|ns-list|namespace/$A|{}||K8SNS namespace a: 4 entries (2 tls, 2 opaque)
I10b|K8SNS|ns-list|namespace/$B|{}||K8SNS namespace b: 2 entries
I10c|K8SNS|ns-all|namespace/$C|{}||K8SNS namespace c: tls-c only
I10d|K8SNS|ns-all|namespace/$PREFIX-empty|{}||K8SNS empty namespace: Success with no certificates
I11|K8SNS|ns-all|namespace/all|{}||K8SNS namespace literally named 'all': only its own two secrets
I12|K8SCluster|manual|$PREFIX-cluster|{}||K8SCluster: every Opaque and tls secret with a certificate, alias <ns>/secrets/<type>/<name>
I13|K8SCert|cert-all|$CSR_NAME|{"KubeSecretName":"$CSR_NAME"}||K8SCert csr1: the issued certificate, no key
EOF
}

expected() { # ID -> expected rows (alias|key|certs), one per line
  case $1 in
    I1)   L '*|yes|int,leaf2' ;;
    I2)   L '*|no|leaf4' ;;
    I3)   L '*|yes|leaf3' ;;
    I4)   : ;;
    I5)   L '*|yes|int,leaf1' ;;
    I6)   L '*|no|leaf5' ;;
    I7)   L 'keystore.jks/leaf1|yes|~leaf1' 'keystore.jks/trustedroot|no|root' ;;
    I8)   L 'app.jks/leaf1|yes|~leaf1' 'app.jks/trustedroot|no|root' ;;
    I9a)  L 'keystore.p12/leaf1|yes|~leaf1' 'keystore.p12/trustedroot|no|root' ;;
    I9b)  L 'app.pfx/leaf1|yes|~leaf1' 'app.pfx/trustedroot|no|root' ;;
    I10a) L 'tls/tls-full|yes|~leaf1' 'tls/tls-certonly|no|leaf5' 'opaque/op-pem|yes|~leaf2' 'opaque/op-certonly|no|leaf4' ;;
    I10b) L 'tls/tls-b|yes|~leaf2' 'opaque/op-b|yes|~leaf3' ;;
    I10c) L 'tls/tls-c|yes|~leaf5' ;;
    I10d) : ;;
    I11)  L 'opaque/op-all|yes|~leaf6' 'tls/tls-all|yes|~leaf6' ;;
    I12)  L "$A/secrets/tls/tls-full|yes|~leaf1" "$A/secrets/tls/tls-certonly|no|leaf5" \
            "$A/secrets/opaque/op-pem|yes|~leaf2" "$A/secrets/opaque/op-certonly|no|leaf4" \
            "$B/secrets/tls/tls-b|yes|~leaf2" "$B/secrets/opaque/op-b|yes|~leaf3" \
            "$C/secrets/tls/tls-c|yes|~leaf5" \
            "$I/secrets/tls/tls-ign|yes|~leaf4" "$I/secrets/opaque/op-ign|yes|~leaf4" \
            "all/secrets/tls/tls-all|yes|~leaf6" "all/secrets/opaque/op-all|yes|~leaf6" ;;
    I13)  L "$CSR_NAME|no|csr1" ;;
  esac
}
L() { printf '%s\n' "$@"; }

# approve_discovered STOREID TYPE PROPS USEPW
approve_discovered() {
  local sid=$1 type=$2 extra=$3 usepw=$4 body
  body=$(mktemp "$TMPD/appr.XXXXXX")
  jq -n --arg id "$sid" --argjson t "$(st_id "$type")" --arg props "$(store_props "$extra")" \
        --arg usepw "$usepw" --rawfile pw "$KSPW_FILE" '
    [{Id:$id,CertStoreType:$t,Properties:$props,InventorySchedule:{Immediate:true}}
     + (if $usepw == "" then {} else {Password:{SecretValue:$pw}} end)]' > "$body"
  api POST /CertificateStores/Approve "$body" >/dev/null
  local rc=$?
  rm -f "$body"
  return $rc
}

# ---- phase 1: approve / create stores and trigger inventory -----------------
batch_begin
while IFS='|' read -r -u 3 id type src path props usepw desc; do
  [ -n "$id" ] || continue
  desc=${desc# }
  want "$id" || continue
  if dry; then
    if [ "$src" = manual ]; then dsay "$id: create $type store by hand, client machine $CM_MANUAL, path $path, then inventory"
    else dsay "$id: approve the $type store discovered at '$path' (client machine $PREFIX-$src) with props $props${usepw:+ and the keystore password}, then inventory"; fi
    continue
  fi
  if [ "$src" = manual ]; then
    cm=$CM_MANUAL
    existing=$(store_find "$cm" "$path")
    sid=$(mk_store "$cm" "$path" "$type" "$props" "$usepw" false)
    [ -n "$existing" ] && schedule_inventory "$sid"
    psuf=$path
  else
    cm=$PREFIX-$src
    sid=$(store_find_suffix "$cm" "$path")
    if [ -z "$sid" ]; then
      state_set "sid.$id" ""
      warn "$id: no discovered store ending in '$path' for client machine $cm (run discovery.sh first)"
      continue
    fi
    if [ "$(stores_all | jq -r --arg id "$sid" '[.[]? | select(.Id == $id) | .Approved][0] // false')" = true ]; then
      schedule_inventory "$sid"
    else
      approve_discovered "$sid" "$type" "$props" "$usepw" || { warn "$id: approve failed"; continue; }
    fi
    psuf=$path
  fi
  state_set "sid.$id" "$sid"
  job_register "i.$id" "$cm" "$psuf" 'Inventory$'
done 3<<EOF
$(cases)
EOF

say "-- waiting for the UO to run the inventory jobs (timeout ${E2E_JOB_TIMEOUT}s each)"
batch_wait

# ---- phase 2: compare --------------------------------------------------------
while IFS='|' read -r -u 3 id type src path props usepw desc; do
  [ -n "$id" ] || continue
  desc=${desc# }
  want "$id" || continue
  if dry; then verdict "$id" 1 "$desc" "$(expected "$id" | csv)" ""; continue; fi
  sid=$(state_get "sid.$id")
  if [ -z "$sid" ]; then verdict "$id" 0 "$desc" "store present" "store not discovered/created (see warnings above)"; continue; fi
  res=$(job_result "i.$id")
  if [ "$res" != Success ]; then
    verdict "$id" 0 "$desc" "inventory job Success" "job result='$res' status='$(job_status "i.$id")' message='$(job_message "i.$id" | cut -c1-200)'"
    continue
  fi
  case $id in
    I4|I10d)
      n=$(store_inventory "$sid" | jq 'length')
      msg=$(job_message "i.$id")
      ok=0; [ "$n" = 0 ] && ok=1
      if [ "$id" = I4 ] && [ -n "$msg" ] && ! printf '%s' "$msg" | grep -qi 'No certificates found'; then ok=0; fi
      verdict "$id" "$ok" "$desc" "0 inventory entries, job Success${msg:+, message 'No certificates found in store'}" "$n entries, message='$(printf '%s' "$msg" | cut -c1-120)'" ;;
    I9a|I9b)
      # an extra intermediate-CA alias without a key is expected parity with 1.3.0
      inv_check "$id" "$desc" "$sid" "$(expected "$id")" extra-no ;;
    I12)
      inv_check "$id" "$desc" "$sid" "$(expected "$id")" exact "^(${PREFIX}-(a|b|c|ign|empty)|all)/" ;;
    *)
      inv_check "$id" "$desc" "$sid" "$(expected "$id")" exact ;;
  esac
done 3<<EOF
$(cases)
EOF

finish
