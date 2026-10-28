#!/usr/bin/env bash
# shellcheck shell=bash
#
# baseline.sh - the "previous build" regression comparison (cases B1..B5).
#
# Run it while the PREVIOUS extension build is staged on the UO (stage-extension.sh
# restore, or stage a specific old build). It re-runs a few of the discovery and
# inventory cases against the previous build and reports REPRO when the old,
# buggy behaviour is reproduced (which is what shows the change under test fixes
# something) or NOREPRO when the old build already behaves correctly.
#
# Exit code is 0 unless something could not be run; with --require-repro a
# NOREPRO is treated as a failure (use it only against a build known to carry
# the old behaviour).
#
# Needs: fixtures.sh + discovery.sh + inventory.sh have run (inventory.sh creates
# the approved stores this phase re-inventories).
PHASE=baseline
E2E_USAGE_EXTRA="[--require-repro]"
# shellcheck source=scripts/e2e/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
e2e_init "$@"
REQUIRE=0
for a in ${E2E_REST[@]+"${E2E_REST[@]}"}; do
  case $a in --require-repro) REQUIRE=1 ;; *) die "unknown argument: $a (try --help)" ;; esac
done
lab_require_command
resolve_lab

A=$NS_A
CM_MANUAL=$PREFIX-manual

# ---- B1: dirs=all discovery on 6 store types -------------------------------
B1_SPECS="K8SSecret:base-sec-all:all K8SSecret:base-sec-ign:all K8SNS:base-ns-all:all K8STLSSecr:base-tls-all:all K8SJKS:base-jks-all:all K8SPKCS12:base-p12-all:all"
batch_begin
i=0
for spec in $B1_SPECS; do
  type=${spec%%:*}; rest=${spec#*:}; cm=$PREFIX-${rest%%:*}; dirs=${rest#*:}
  ign=""; case $cm in *-sec-ign) ign=$NS_IGN ;; esac
  disc_submit "$type" "$cm" "$dirs" "$ign" "" "" && job_register "b.B1.$i" "$cm" "" 'Discovery$'
  i=$((i + 1))
done

# ---- B2..B5: re-inventory stores approved by inventory.sh -------------------
sid_jks=""; sid_p12=""; sid_ns=""; sid_key=""
if ! dry; then
  sid_key=$(store_find "$CM_MANUAL" "$A/op-keyonly")
  sid_jks=$(store_find_suffix "$PREFIX-jks-list" "$A/secrets/jks-a")
  sid_p12=$(store_find_suffix "$PREFIX-p12-list" "$A/secrets/p12-a")
  sid_ns=$(store_find_suffix "$PREFIX-ns-all" "namespace/all")
  # shellcheck disable=SC2086
  schedule_inventory $sid_key $sid_jks $sid_p12 $sid_ns
  [ -n "$sid_key" ] && job_register b.B2 "$CM_MANUAL" "$A/op-keyonly" 'Inventory$'
  [ -n "$sid_jks" ] && job_register b.B3 "$PREFIX-jks-list" "$A/secrets/jks-a" 'Inventory$'
  [ -n "$sid_p12" ] && job_register b.B4 "$PREFIX-p12-list" "$A/secrets/p12-a" 'Inventory$'
  [ -n "$sid_ns" ] && job_register b.B5 "$PREFIX-ns-all" "namespace/all" 'Inventory$'
else
  dsay "re-inventory the approved stores for op-keyonly, jks-a, p12-a and namespace 'all' with the previous build"
fi

say "-- waiting for the UO (previous build) to run the jobs"
batch_wait

# ---- evaluate ---------------------------------------------------------------
if dry; then
  repro B1 1 "dirs=all discovery returns 0 stores on every store type" "0 stores on all 6 discovery jobs ('Failed to parse discovery directories')" ""
  repro B2 1 "key-only Opaque secret inventory fails" "Failure with a Base-64 error" ""
  repro B3 1 "JKS trusted-certificate alias is missing from inventory" "no keystore.jks/trustedroot row" ""
  repro B4 1 "PKCS12 private-key flag is 'Yes' for every alias" "trustedroot reported with a private key" ""
  repro B5 1 "K8SNS store for the namespace named 'all' inventories other namespaces too" "more than op-all and tls-all, or errors" ""
  finish
fi

counts=""; allzero=1
i=0
for spec in $B1_SPECS; do
  rest=${spec#*:}; cm=${rest%%:*}
  res=$(job_result "b.B1.$i")
  n=$(discovered_paths "$PREFIX-$cm" | grep -c . || true)
  counts="$counts $cm=$n($res)"
  [ "${n:-0}" -gt 0 ] && allzero=0
  i=$((i + 1))
done
repro B1 "$allzero" "dirs=all discovery returns 0 stores on every store type" "0 stores on all 6 discovery jobs ('Failed to parse discovery directories')" "$counts"

if [ -z "$sid_key" ]; then skip B2 "key-only Opaque inventory" "store $CM_MANUAL $A/op-keyonly not found (run inventory.sh first)"
else
  r=$(job_result b.B2); m=$(job_message b.B2 | cut -c1-160)
  rr=0; [ "$r" != Success ] && rr=1
  repro B2 "$rr" "key-only Opaque secret inventory fails" "Failure with a Base-64 error" "job=$r message='$m'"
fi

if [ -z "$sid_jks" ]; then skip B3 "JKS trusted alias" "store jks-a not found (run inventory.sh first)"
else
  rows=$(store_inventory "$sid_jks" | jq -r '.[]? | .Name')
  rr=1; printf '%s\n' "$rows" | grep -qx 'keystore.jks/trustedroot' && rr=0
  repro B3 "$rr" "JKS trusted-certificate alias is missing from inventory" "no keystore.jks/trustedroot row" "aliases: $(printf '%s\n' "$rows" | csv)"
fi

if [ -z "$sid_p12" ]; then skip B4 "PKCS12 key flag" "store p12-a not found (run inventory.sh first)"
else
  pk=$(store_inventory "$sid_p12" | jq -r '[.[]? | select(.Name | endswith("/trustedroot")) | ((.Parameters.PrivateKeyEntry // "") | tostring | ascii_downcase)][0] // ""')
  rr=0; case $pk in yes|true) rr=1 ;; esac
  repro B4 "$rr" "PKCS12 private-key flag is 'Yes' for every alias (trustedroot shown with a key)" "trustedroot reported with a private key" "trustedroot key flag='${pk:-<alias absent>}'"
fi

if [ -z "$sid_ns" ]; then skip B5 "K8SNS namespace 'all'" "store namespace/all not found (run inventory.sh first)"
else
  r=$(job_result b.B5)
  rows=$(store_inventory "$sid_ns" | jq -r '.[]? | .Name' | sort)
  want_rows=$(printf '%s\n' opaque/op-all tls/tls-all)
  rr=0; { [ "$r" != Success ] || [ "$rows" != "$(printf '%s\n' "$want_rows" | sort)" ]; } && rr=1
  repro B5 "$rr" "K8SNS store for the namespace named 'all' inventories other namespaces too" "more than op-all and tls-all, or errors" \
    "job=$r $(printf '%s\n' "$rows" | grep -c .) row(s)"
fi

if [ "$REQUIRE" = 1 ] && [ "$N_NOREPRO" -gt 0 ]; then
  say "-- --require-repro: $N_NOREPRO case(s) did not reproduce the old behaviour"
  N_FAIL=$((N_FAIL + N_NOREPRO))
fi
finish
