#!/usr/bin/env bash
# shellcheck shell=bash
#
# management.sh - cases M1..M24 and the known-issue cases K105..K108.
#
# Imports test certificates into Command, creates management stores in the
# <prefix>-m namespace with CreateIfMissing, then drives Add/Remove through the
# Command API in lock-step "waves" (at most one operation per store per wave, so
# every Command job can be attributed unambiguously). After each wave it checks
# the job result in Command and the resulting Kubernetes secret / keystore
# contents directly with kubectl, openssl and keytool.
#
# All operations run (the sequence is dependent: later waves use what earlier
# waves created); --only only filters which verdicts are reported.
#
# Needs: fixtures.sh has run. Does not need discovery.sh.
PHASE=management
# shellcheck source=scripts/e2e/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
e2e_init "$@"; e2e_no_extra
lab_require_command
resolve_lab

M=$NS_M
MG_CM=$PREFIX-mgmt
TOUCHED=""
KS_FILE=$WORK/tmp/ks.file
KS_FIELD=""

# ------------------------------------------------------------- helpers ------
# store NAME TYPE PATH PROPS USEPW : create (CreateIfMissing) once; register its create job
mg_store() {
  local name=$1 type=$2 path=$3 props=$4 usepw=$5 existing sid
  if dry; then dsay "create store '$name' type=$type path=$path (CreateIfMissing=true)"; return 0; fi
  existing=$(store_find "$MG_CM" "$path")
  sid=$(mk_store "$MG_CM" "$path" "$type" "$props" "$usepw" true) || die "could not create store '$name'"
  state_set "sid.mg.$name" "$sid"
  state_set "path.mg.$name" "$path"
  if [ -z "$existing" ]; then
    state_set "fresh.mg.$name" yes
    job_register "c.$name" "$MG_CM" "$path" 'Management$'
  else
    state_set "fresh.mg.$name" no
  fi
}

touch_store() { case " $TOUCHED " in *" $1 "*) : ;; *) TOUCHED="$TOUCHED $1" ;; esac; }

# mg_add LABEL STORE CERT ALIAS KEY OVERWRITE
mg_add() {
  local label=$1 name=$2 cert=$3 alias=$4 key=$5 ow=$6 body sid
  if dry; then dsay "Add cert=$cert -> store '$name' alias='$alias' includePrivateKey=$key overwrite=$ow  [$label]"; return 0; fi
  sid=$(state_get "sid.mg.$name")
  body=$(mktemp "$WORK/tmp/add.XXXXXX")
  jq -n --arg s "$sid" --argjson c "$(cid "$cert")" --arg a "$alias" --argjson k "$key" --argjson o "$ow" --rawfile pw "$KSPW_FILE" '
    {CertificateId:$c,
     CertificateStores:[({CertificateStoreId:$s,Overwrite:$o,IncludePrivateKey:$k}
                         + (if $a == "" then {} else {Alias:$a} end)
                         + (if $k then {PfxPassword:$pw} else {} end))],
     Schedule:{Immediate:true}}' > "$body"
  api POST /CertificateStores/Certificates/Add "$body" >/dev/null || warn "Add request for $label was rejected by Command"
  rm -f "$body"
  job_register "$label" "$MG_CM" "$(state_get "path.mg.$name")" 'Management$'
  touch_store "$name"
}

# mg_rm LABEL STORE ALIAS
mg_rm() {
  local label=$1 name=$2 alias=$3 body sid
  if dry; then dsay "Remove alias='$alias' from store '$name'  [$label]"; return 0; fi
  sid=$(state_get "sid.mg.$name")
  body=$(mktemp "$WORK/tmp/rm.XXXXXX")
  jq -n --arg s "$sid" --arg a "$alias" '
    {CertificateStores:[({CertificateStoreId:$s} + (if $a == "" then {} else {Alias:$a} end))],Schedule:{Immediate:true}}' > "$body"
  api POST /CertificateStores/Certificates/Remove "$body" >/dev/null || warn "Remove request for $label was rejected by Command"
  rm -f "$body"
  job_register "$label" "$MG_CM" "$(state_get "path.mg.$name")" 'Management$'
  touch_store "$name"
}

wave_begin() { TOUCHED=""; batch_begin; }

# wave_end : wait for the wave's jobs, then refresh Command's inventory of the
# stores it touched (Remove/overwrite by alias requires the alias in Command's inventory)
wave_end() {
  local n sid ids=""
  batch_wait
  dry && return 0
  batch_begin
  for n in $TOUCHED; do
    sid=$(state_get "sid.mg.$n")
    ids="$ids $sid"
    job_register "inv.$n" "$MG_CM" "$(state_get "path.mg.$n")" 'Inventory$'
  done
  # shellcheck disable=SC2086
  schedule_inventory $ids
  batch_wait
}

# chain_is ACTUAL_CSV FIRST SET_CSV : leaf first, and exactly this set of certs
chain_is() {
  local a=$1 first=$2 set=$3
  [ "${a%%,*}" = "$first" ] || return 1
  [ "$(printf '%s' "$a" | tr ',' '\n' | sort | csv)" = "$(printf '%s' "$set" | tr ',' '\n' | sort | csv)" ]
}

# ks_load NS NAME TYPE : download the keystore field into $KS_FILE, field name in $KS_FIELD
ks_load() {
  KS_FIELD=""; : > "$KS_FILE"
  dry && return 0
  KS_FIELD=$(sec_keys "$1" "$2" | head -1)
  [ -n "$KS_FIELD" ] && ks_fetch "$1" "$2" "$KS_FIELD" "$KS_FILE"
  return 0
}
ks_has() { ks_aliases "$KS_FILE" "$1" | grep -qx "$2"; }   # TYPE alias:entrytype

# inv_pk STOREID ALIAS : private key flag Command holds for an alias (yes|no|""); ALIAS '*' = first entry
inv_pk() {
  store_inventory "$1" | jq -r --arg a "$2" '[.[]? | select($a == "*" or .Name == $a) | ((.Parameters.PrivateKeyEntry // "") | tostring | ascii_downcase)][0]
    | if . == "yes" or . == "true" then "yes" elif . == "no" or . == "false" then "no" else "" end'
}

jr() { job_result "$1"; }
jm() { job_message "$1" | cut -c1-160; }

# ---------------------------------------------------------- setup ----------
# The wave sequence is single-shot: it assumes the management namespace holds no
# secrets yet. After a run (or an aborted run) use cleanup.sh, then fixtures.sh.
if ! dry; then
  kube_get get ns "$M" >/dev/null 2>&1 || die "namespace $M not found; run fixtures.sh first"
  if [ "$(kube_get -n "$M" get secrets -o name | grep -c .)" -gt 0 ]; then
    die "namespace $M already holds secrets from an earlier run; run cleanup.sh and fixtures.sh first (or use a new --prefix)"
  fi
fi
say "-- importing test certificates into Command"
for c in leaf2 leaf3 leaf4; do cert_import "$c" pfx || die "could not import $c into Command"; done
cert_import leaf6 der || die "could not import leaf6 into Command"

say "-- creating management stores (CreateIfMissing)"
batch_begin
KP='"KubeNamespace":"'$M'"'
mg_store mg-opaque          K8SSecret  "$M/mg-opaque"          "{$KP,\"KubeSecretName\":\"mg-opaque\",\"IncludeCertChain\":\"true\",\"SeparateChain\":\"false\"}" ""
mg_store mg-opaque-sep      K8SSecret  "$M/mg-opaque-sep"      "{$KP,\"KubeSecretName\":\"mg-opaque-sep\",\"IncludeCertChain\":\"true\",\"SeparateChain\":\"true\"}" ""
mg_store mg-opaque-nochain  K8SSecret  "$M/mg-opaque-nochain"  "{$KP,\"KubeSecretName\":\"mg-opaque-nochain\",\"IncludeCertChain\":\"false\",\"SeparateChain\":\"false\"}" ""
mg_store mg-opaque2         K8SSecret  "$M/mg-opaque2"         "{$KP,\"KubeSecretName\":\"mg-opaque2\",\"IncludeCertChain\":\"true\",\"SeparateChain\":\"false\"}" ""
mg_store mg-tls             K8STLSSecr "$M/mg-tls"             "{$KP,\"KubeSecretName\":\"mg-tls\",\"IncludeCertChain\":\"true\",\"SeparateChain\":\"false\"}" ""
mg_store mg-tls-sep         K8STLSSecr "$M/mg-tls-sep"         "{$KP,\"KubeSecretName\":\"mg-tls-sep\",\"IncludeCertChain\":\"true\",\"SeparateChain\":\"true\"}" ""
mg_store mg-tls-conflict    K8STLSSecr "$M/mg-tls-conflict"    "{$KP,\"KubeSecretName\":\"mg-tls-conflict\",\"IncludeCertChain\":\"false\",\"SeparateChain\":\"true\"}" ""
mg_store mg-tls2            K8STLSSecr "$M/mg-tls2"            "{$KP,\"KubeSecretName\":\"mg-tls2\",\"IncludeCertChain\":\"true\",\"SeparateChain\":\"false\"}" ""
mg_store mg-jks             K8SJKS     "$M/mg-jks"             "{$KP,\"KubeSecretName\":\"mg-jks\",\"CertificateDataFieldName\":\"keystore.jks\"}" yes
mg_store mg-jks-nochain     K8SJKS     "$M/mg-jks-nochain"     "{$KP,\"KubeSecretName\":\"mg-jks-nochain\",\"CertificateDataFieldName\":\"keystore.jks\",\"IncludeCertChain\":\"false\"}" yes
mg_store mg-jks-field       K8SJKS     "$M/mg-jks-field"       "{$KP,\"KubeSecretName\":\"mg-jks-field\",\"CertificateDataFieldName\":\"app.jks\"}" yes
mg_store mg-p12             K8SPKCS12  "$M/mg-p12"             "{$KP,\"KubeSecretName\":\"mg-p12\",\"CertificateDataFieldName\":\"keystore.p12\"}" yes
mg_store mg-ns              K8SNS      "$M"                    "{$KP,\"IncludeCertChain\":\"true\",\"SeparateChain\":\"false\"}" ""
mg_store mg-cluster         K8SCluster "$PREFIX-cluster"       "{}" ""
say "-- waiting for the Create jobs"
batch_wait

# K107: K8SNS CreateIfMissing
if want K107; then
  if dry; then
    verdict K107 1 "K8SNS store with CreateIfMissing: the Create job succeeds" "Management job Success (not retried)" "" 107
  elif [ "$(state_get fresh.mg.mg-ns)" != yes ]; then
    skip K107 "K8SNS CreateIfMissing" "the store already existed from an earlier run; use a fresh --prefix"
  else
    r=$(jr c.mg-ns)
    verdict K107 "$([ "$r" = Success ] && echo 1 || echo 0)" "K8SNS store with CreateIfMissing: the Create job succeeds" \
      "Management job Success (not retried)" "result='$r' status='$(job_status c.mg-ns)' message='$(jm c.mg-ns)'" 107
  fi
fi
for n in mg-opaque mg-opaque-sep mg-opaque-nochain mg-opaque2 mg-tls mg-tls-sep mg-tls-conflict mg-tls2 mg-jks mg-jks-nochain mg-jks-field mg-p12 mg-cluster; do
  dry && break
  if [ "$(state_get "fresh.mg.$n")" = yes ] && [ "$(jr "c.$n")" != Success ]; then
    warn "Create job for store $n: result='$(jr "c.$n")' message='$(jm "c.$n")'"
  fi
done

# ---------------------------------------------------------- wave 1 ---------
say "-- wave 1: Add with key / cert-only on fresh secrets"
wave_begin
mg_add w1.O1 mg-opaque         leaf3 ""  true  false
mg_add w1.O2 mg-opaque-sep     leaf3 ""  true  false
mg_add w1.O3 mg-opaque-nochain leaf3 ""  true  false
mg_add w1.O4 mg-opaque2        leaf6 ""  false false
mg_add w1.T1 mg-tls            leaf3 ""  true  false
mg_add w1.T2 mg-tls-sep        leaf3 ""  true  false
mg_add w1.T3 mg-tls-conflict   leaf3 ""  true  false
mg_add w1.T4 mg-tls2           leaf6 ""  false false
mg_add w1.J1 mg-jks            leaf3 leaf3 true false
mg_add w1.J2 mg-jks-nochain    leaf3 leaf3 true false
mg_add w1.J3 mg-jks-field      leaf3 leaf3 true false
mg_add w1.P1 mg-p12            leaf3 leaf3 true false
mg_add w1.N1 mg-ns             leaf3 tls/ns-tls1 true false
mg_add w1.C1 mg-cluster        leaf4 "$M/secrets/opaque/cl-op1" true false
wave_end

# M24 needs no wave: Command must refuse at scheduling
if want M24; then
  if dry; then
    dsay "M24: create a K8SCert store, POST Certificates/Add and Certificates/Remove for it, expect an HTTP 4xx refusal"
    verdict M24 1 "K8SCert Add/Remove is refused by Command at scheduling" "HTTP 4xx for both" ""
  else
    ksid=$(mk_store "$MG_CM" "$CSR_NAME" K8SCert "{\"KubeSecretName\":\"$CSR_NAME\"}" "" false)
    body=$(mktemp "$WORK/tmp/m24.XXXXXX")
    jq -n --arg s "$ksid" --argjson c "$(cid leaf3)" '{CertificateId:$c,CertificateStores:[{CertificateStoreId:$s,Overwrite:false,IncludePrivateKey:false}],Schedule:{Immediate:true}}' > "$body"
    api POST /CertificateStores/Certificates/Add "$body" >/dev/null 2>&1; add_code=$(api_code)
    jq -n --arg s "$ksid" --arg a "$CSR_NAME" '{CertificateStores:[{CertificateStoreId:$s,Alias:$a}],Schedule:{Immediate:true}}' > "$body"
    api POST /CertificateStores/Certificates/Remove "$body" >/dev/null 2>&1; rm_code=$(api_code)
    rm -f "$body"
    ok=0; case $add_code in 4??) case $rm_code in 4??) ok=1 ;; esac ;; esac
    verdict M24 "$ok" "K8SCert Add/Remove is refused by Command at scheduling" "HTTP 4xx for both" "Add=HTTP $add_code Remove=HTTP $rm_code"
  fi
fi

# ---- verify wave 1
r=$(jr w1.O1); chain=$(sec_chain "$M" mg-opaque tls.crt); key=$(sec_has_key "$M" mg-opaque tls.key)
ok=0; [ "$r" = Success ] && chain_is "$chain" leaf3 leaf3,int,root && [ "$key" = yes ] && ok=1
verdict M1 "$ok" "K8SSecret Add leaf3+key, IncludeCertChain=true: tls.crt has 3 certs, tls.key present" \
  "job Success; tls.crt = leaf3,int,root; tls.key present" "job=$r tls.crt=$chain tls.key=$key $(jm w1.O1)"

r=$(jr w1.O2); chain=$(sec_chain "$M" mg-opaque-sep tls.crt); ca=$(sec_chain "$M" mg-opaque-sep ca.crt); key=$(sec_has_key "$M" mg-opaque-sep tls.key)
ok=0; [ "$r" = Success ] && [ "$chain" = leaf3 ] && chain_is "$ca" "${ca%%,*}" int,root && [ "$key" = yes ] && ok=1
verdict M2 "$ok" "K8SSecret SeparateChain=true: tls.crt = leaf only, ca.crt = intermediate+root, tls.key present" \
  "job Success; tls.crt = leaf3; ca.crt = {int,root}; tls.key present" "job=$r tls.crt=$chain ca.crt=$ca tls.key=$key"

r=$(jr w1.O3); chain=$(sec_chain "$M" mg-opaque-nochain tls.crt); ca=$(sec_chain "$M" mg-opaque-nochain ca.crt)
ok=0; [ "$r" = Success ] && [ "$chain" = leaf3 ] && [ -z "$ca" ] && ok=1
verdict M3 "$ok" "K8SSecret IncludeCertChain=false: tls.crt = leaf only" \
  "job Success; tls.crt = leaf3; no ca.crt" "job=$r tls.crt=$chain ca.crt=${ca:-<none>}"

r=$(jr w1.O4); chain=$(sec_chain "$M" mg-opaque2 tls.crt); key=$(sec_has_key "$M" mg-opaque2 tls.key)
o4sid=$(state_get sid.mg.mg-opaque2); pk=$(inv_pk "$o4sid" '*')
ok=0; [ "$r" = Success ] && [ "${chain%%,*}" = leaf6 ] && [ "$key" = no ] && [ "$pk" = no ] && ok=1
verdict M6 "$ok" "K8SSecret cert-only Add on a fresh secret: Success, key=No" \
  "job Success; tls.crt = leaf6; no private key; Command shows key=No" "job=$r tls.crt=$chain key=$key command-key=${pk:-<n/a>} $(jm w1.O4)"

r=$(jr w1.T1); typ=$(sec_type "$M" mg-tls); chain=$(sec_chain "$M" mg-tls tls.crt); key=$(sec_has_key "$M" mg-tls tls.key)
ok=0; [ "$r" = Success ] && [ "$typ" = kubernetes.io/tls ] && chain_is "$chain" leaf3 leaf3,int,root && [ "$key" = yes ] && ok=1
verdict M8a "$ok" "K8STLSSecr Add with key (IncludeCertChain=true): tls.crt has 3 certs, tls.key present" \
  "job Success; type kubernetes.io/tls; tls.crt = leaf3,int,root; tls.key present" "job=$r type=$typ tls.crt=$chain tls.key=$key"

r=$(jr w1.T2); chain=$(sec_chain "$M" mg-tls-sep tls.crt); ca=$(sec_chain "$M" mg-tls-sep ca.crt); key=$(sec_has_key "$M" mg-tls-sep tls.key)
ok=0; [ "$r" = Success ] && [ "$chain" = leaf3 ] && chain_is "$ca" "${ca%%,*}" int,root && [ "$key" = yes ] && ok=1
verdict M8b "$ok" "K8STLSSecr SeparateChain=true: tls.crt = leaf only, ca.crt = intermediate+root" \
  "job Success; tls.crt = leaf3; ca.crt = {int,root}; tls.key present" "job=$r tls.crt=$chain ca.crt=$ca tls.key=$key"

r=$(jr w1.T3); chain=$(sec_chain "$M" mg-tls-conflict tls.crt); ca=$(sec_chain "$M" mg-tls-conflict ca.crt); key=$(sec_has_key "$M" mg-tls-conflict tls.key)
ok=0; [ "$r" = Success ] && [ "$chain" = leaf3 ] && [ -z "$ca" ] && [ "$key" = yes ] && ok=1
verdict M9 "$ok" "K8STLSSecr SeparateChain=true + IncludeCertChain=false: SeparateChain overridden, 1 cert, no ca.crt" \
  "job Success; tls.crt = leaf3 (1 cert); no ca.crt; tls.key present" "job=$r tls.crt=$chain ca.crt=${ca:-<none>} tls.key=$key"

r=$(jr w1.T4); typ=$(sec_type "$M" mg-tls2); chain=$(sec_chain "$M" mg-tls2 tls.crt)
hasfield=$(sec_keys "$M" mg-tls2 | grep -cx tls.key); ksz=$(sec_field_size "$M" mg-tls2 tls.key)
pk=$(inv_pk "$(state_get sid.mg.mg-tls2)" '*')
ok=0; [ "$r" = Success ] && [ "$typ" = kubernetes.io/tls ] && [ "${chain%%,*}" = leaf6 ] && [ "${hasfield:-0}" = 1 ] && [ "$ksz" = 0 ] && [ "$pk" = no ] && ok=1
verdict M11 "$ok" "K8STLSSecr cert-only Add on a fresh secret: created with empty tls.key, key=No" \
  "job Success; type tls; tls.crt = leaf6; tls.key present but empty; Command shows key=No" "job=$r type=$typ tls.crt=$chain tls.key-field=${hasfield:-0} size=$ksz command-key=${pk:-<n/a>}"

ks_load "$M" mg-jks JKS
r=$(jr w1.J1); ok=0; [ "$r" = Success ] && [ "$KS_FIELD" = keystore.jks ] && ks_has JKS leaf3:PrivateKeyEntry && ok=1
verdict M13 "$ok" "K8SJKS Add leaf3+key: key entry present" "job Success; alias leaf3 is a PrivateKeyEntry" \
  "job=$r field=$KS_FIELD entries=$(ks_aliases "$KS_FILE" JKS | csv)"

ks_load "$M" mg-jks-nochain JKS
r=$(jr w1.J2); cl=$(ks_alias_chainlen "$KS_FILE" JKS leaf3)
ok=0; [ "$r" = Success ] && ks_has JKS leaf3:PrivateKeyEntry && [ "$cl" = 1 ] && ok=1
verdict M16 "$ok" "K8SJKS IncludeCertChain=false: leaf only" "job Success; alias leaf3 key entry with chain length 1" \
  "job=$r entries=$(ks_aliases "$KS_FILE" JKS | csv) chain-length=${cl:-<n/a>}"

ks_load "$M" mg-jks-field JKS
r=$(jr w1.J3); keys=$(sec_keys "$M" mg-jks-field | csv)
verdict K105a "$([ "$r" = Success ] && [ "$keys" = app.jks ] && echo 1 || echo 0)" \
  "K8SJKS create/Add honours CertificateDataFieldName=app.jks" "secret data key = app.jks" "job=$r secret data keys='$keys'" 105

ks_load "$M" mg-p12 PKCS12
P1F=${KS_FIELD:-keystore.p12}
r=$(jr w1.P1); keys=$(sec_keys "$M" mg-p12 | csv)
ok=0; [ "$r" = Success ] && ks_has PKCS12 leaf3:PrivateKeyEntry && ok=1
verdict M18a "$ok" "K8SPKCS12 Add leaf3+key: key entry present" "job Success; alias leaf3 is a PrivateKeyEntry" \
  "job=$r field=$KS_FIELD entries=$(ks_aliases "$KS_FILE" PKCS12 | csv)"
verdict K105b "$([ "$r" = Success ] && [ "$keys" = keystore.p12 ] && echo 1 || echo 0)" \
  "K8SPKCS12 create/Add honours CertificateDataFieldName=keystore.p12" "secret data key = keystore.p12" "job=$r secret data keys='$keys'" 105

# ---------------------------------------------------------- wave 2 ---------
say "-- wave 2: refusals, overwrite, removes, second ops on shared stores"
wave_begin
mg_add w2.O1 mg-opaque      leaf6 ""           false false
mg_add w2.O2 mg-opaque-sep  leaf4 mg-opaque-sep true true
mg_rm  w2.O4 mg-opaque2     mg-opaque2
mg_add w2.T1 mg-tls         leaf6 ""           false true
mg_rm  w2.T2 mg-tls-sep     ""
mg_rm  w2.T4 mg-tls2        mg-tls2
mg_add w2.J1 mg-jks         leaf6 leaf6        false false
mg_add w2.J2 mg-jks-nochain leaf4 leaf3        true  false
mg_add w2.P1 mg-p12         leaf6 leaf6        false false
mg_add w2.N1 mg-ns          leaf4 opaque/ns-op1 true false
mg_add w2.C1 mg-cluster     leaf3 "$M/secrets/tls/cl-tls1" true false
wave_end

r=$(jr w2.O1); m=$(jm w2.O1); chain=$(sec_chain "$M" mg-opaque tls.crt); key=$(sec_has_key "$M" mg-opaque tls.key)
ok=0; [ "$r" = Failure ] && printf '%s' "$(job_message w2.O1)" | grep -qi 'already exists' && chain_is "$chain" leaf3 leaf3,int,root && [ "$key" = yes ] && ok=1
verdict M4 "$ok" "K8SSecret Add on an existing secret with overwrite=false is refused ('already exists. Set overwrite=true')" \
  "job Failure mentioning 'already exists'; secret unchanged (leaf3,int,root + key)" "job=$r tls.crt=$chain tls.key=$key message='$m'"

r=$(jr w2.O2); chain=$(sec_chain "$M" mg-opaque-sep tls.crt); ca=$(sec_chain "$M" mg-opaque-sep ca.crt); key=$(sec_has_key "$M" mg-opaque-sep tls.key)
ok=0; [ "$r" = Success ] && [ "$chain" = leaf4 ] && chain_is "$ca" "${ca%%,*}" int,root && [ "$key" = yes ] && ok=1
verdict M5 "$ok" "K8SSecret overwrite=true via the inventory alias (secret name): replaced" \
  "job Success; tls.crt = leaf4; ca.crt = {int,root}; key present" "job=$r tls.crt=$chain ca.crt=$ca tls.key=$key"

ok=0; [ "$(jr w2.O4)" = Success ] && ! sec_exists "$M" mg-opaque2 && ok=1
verdict M6b "$ok" "K8SSecret Remove of the cert-only secret (inventory alias): secret deleted" "job Success; secret gone" \
  "job=$(jr w2.O4) secret-exists=$(sec_exists "$M" mg-opaque2 && echo yes || echo no)"

r=$(jr w2.T1); chain=$(sec_chain "$M" mg-tls tls.crt); key=$(sec_has_key "$M" mg-tls tls.key)
ok=0; [ "$r" = Failure ] && chain_is "$chain" leaf3 leaf3,int,root && [ "$key" = yes ] && ok=1
verdict M10 "$ok" "K8STLSSecr cert-only Add (overwrite=true) onto a secret that has a key is refused (intentional guard)" \
  "job Failure; secret unchanged (leaf3,int,root + key)" "job=$r tls.crt=$chain tls.key=$key message='$(jm w2.T1)'"

ok=0; [ "$(jr w2.T2)" = Success ] && ! sec_exists "$M" mg-tls-sep && ok=1
verdict M8c "$ok" "K8STLSSecr Remove (no alias): secret deleted" "job Success; secret gone" \
  "job=$(jr w2.T2) secret-exists=$(sec_exists "$M" mg-tls-sep && echo yes || echo no)"

ok=0; [ "$(jr w2.T4)" = Success ] && ! sec_exists "$M" mg-tls2 && ok=1
verdict M11b "$ok" "K8STLSSecr Remove of the cert-only secret: secret deleted" "job Success; secret gone" \
  "job=$(jr w2.T4) secret-exists=$(sec_exists "$M" mg-tls2 && echo yes || echo no)"

ks_load "$M" mg-jks JKS
r=$(jr w2.J1); pk=$(inv_pk "$(state_get sid.mg.mg-jks)" "$KS_FIELD/leaf6")
ok=0; [ "$r" = Success ] && ks_has JKS leaf6:trustedCertEntry && ks_has JKS leaf3:PrivateKeyEntry && [ "$pk" = no ] && ok=1
verdict M14 "$ok" "K8SJKS cert-only Add (alias leaf6): trusted-cert entry, key=No" \
  "job Success; leaf6 is a trustedCertEntry; leaf3 untouched; Command shows key=No" "job=$r entries=$(ks_aliases "$KS_FILE" JKS | csv) command-key=${pk:-<n/a>}"

ks_load "$M" mg-jks-nochain JKS
r=$(jr w2.J2); t=$(ks_alias_thumb "$KS_FILE" JKS leaf3)
verdict K106a "$([ "$r" = Failure ] && [ "$t" = leaf3 ] && echo 1 || echo 0)" \
  "K8SJKS Add on an existing alias with overwrite=false is refused" "job Failure; alias leaf3 still holds leaf3" "job=$r alias leaf3 holds ${t:-<none>}" 106

ks_load "$M" mg-p12 PKCS12
r=$(jr w2.P1)
ok=0; [ "$r" = Success ] && ks_has PKCS12 leaf6:trustedCertEntry && ks_has PKCS12 leaf3:PrivateKeyEntry && ok=1
verdict M18b "$ok" "K8SPKCS12 cert-only Add (alias leaf6): trusted-cert entry" "job Success; leaf6 is a trustedCertEntry" \
  "job=$r entries=$(ks_aliases "$KS_FILE" PKCS12 | csv)"

# M19 / M23a need both ops (wave 1 and 2) done
r1=$(jr w1.N1); r2=$(jr w2.N1)
t1=$(sec_type "$M" ns-tls1); t2=$(sec_type "$M" ns-op1)
k1=$(sec_has_key "$M" ns-tls1 tls.key); k2=$(sec_has_key "$M" ns-op1 tls.key)
ok=0; [ "$r1" = Success ] && [ "$r2" = Success ] && [ "$t1" = kubernetes.io/tls ] && [ "$t2" = Opaque ] && [ "$k1" = yes ] && [ "$k2" = yes ] && ok=1
verdict M19 "$ok" "K8SNS Add tls/ns-tls1 and opaque/ns-op1 with key: secrets created" \
  "both jobs Success; ns-tls1 type tls, ns-op1 type Opaque, both with a key" "jobs=$r1/$r2 types=$t1/$t2 keys=$k1/$k2"
inv_check M19i "K8SNS store inventory lists the created secrets" "$(state_get sid.mg.mg-ns)" \
  "$(printf '%s\n' 'tls/ns-tls1|yes|~leaf3' 'opaque/ns-op1|yes|~leaf4')" subset

r1=$(jr w1.C1); r2=$(jr w2.C1)
t1=$(sec_type "$M" cl-op1); t2=$(sec_type "$M" cl-tls1)
k1=$(sec_has_key "$M" cl-op1 tls.key); k2=$(sec_has_key "$M" cl-tls1 tls.key)
ok=0; [ "$r1" = Success ] && [ "$r2" = Success ] && [ "$t1" = Opaque ] && [ "$t2" = kubernetes.io/tls ] && [ "$k1" = yes ] && [ "$k2" = yes ] && ok=1
verdict M23a "$ok" "K8SCluster Add with key (alias <ns>/secrets/<type>/<name>): opaque/cl-op1 and tls/cl-tls1 created" \
  "both jobs Success; cl-op1 Opaque, cl-tls1 tls, both with a key" "jobs=$r1/$r2 types=$t1/$t2 keys=$k1/$k2"

# ---------------------------------------------------------- wave 3 ---------
say "-- wave 3"
wave_begin
mg_rm  w3.O1 mg-opaque      mg-opaque
mg_add w3.T1 mg-tls         leaf4 mg-tls            true true
mg_add w3.J1 mg-jks         leaf2 keystore.jks/leaf3 true true
mg_add w3.P1 mg-p12         leaf4 leaf3             true false
mg_add w3.N1 mg-ns          leaf2 opaque/ns-op1     true true
mg_rm  w3.C1 mg-cluster     "$M/secrets/opaque/cl-op1"
wave_end

ok=0; [ "$(jr w3.O1)" = Success ] && ! sec_exists "$M" mg-opaque && ok=1
verdict M7 "$ok" "K8SSecret Remove via the inventory alias: secret deleted" "job Success; secret gone" \
  "job=$(jr w3.O1) secret-exists=$(sec_exists "$M" mg-opaque && echo yes || echo no)"

r=$(jr w3.T1); chain=$(sec_chain "$M" mg-tls tls.crt); key=$(sec_has_key "$M" mg-tls tls.key)
ok=0; [ "$r" = Success ] && chain_is "$chain" leaf4 leaf4,int,root && [ "$key" = yes ] && ok=1
verdict M12a "$ok" "K8STLSSecr overwrite with leaf4+key (alias = secret name): replaced" \
  "job Success; tls.crt = leaf4,int,root; key present" "job=$r tls.crt=$chain tls.key=$key"

ks_load "$M" mg-jks JKS
r=$(jr w3.J1); t=$(ks_alias_thumb "$KS_FILE" JKS leaf3)
ok=0; [ "$r" = Success ] && [ "$t" = leaf2 ] && ks_has JKS leaf3:PrivateKeyEntry && ok=1
verdict M15 "$ok" "K8SJKS Add on an existing alias with overwrite=true (alias keystore.jks/leaf3): replaced" \
  "job Success; alias leaf3 now holds leaf2 as a key entry" "job=$r alias leaf3 holds ${t:-<none>}"

ks_load "$M" mg-p12 PKCS12
r=$(jr w3.P1); t=$(ks_alias_thumb "$KS_FILE" PKCS12 leaf3)
verdict K106b "$([ "$r" = Failure ] && [ "$t" = leaf3 ] && echo 1 || echo 0)" \
  "K8SPKCS12 Add on an existing alias with overwrite=false is refused" "job Failure; alias leaf3 still holds leaf3" "job=$r alias leaf3 holds ${t:-<none>}" 106

r=$(jr w3.N1); chain=$(sec_chain "$M" ns-op1 tls.crt); key=$(sec_has_key "$M" ns-op1 tls.key)
ok=0; [ "$r" = Success ] && chain_is "$chain" leaf2 leaf2,int,root && [ "$key" = yes ] && ok=1
verdict M20 "$ok" "K8SNS overwrite opaque/ns-op1 with an EC cert (leaf2): replaced" \
  "job Success; tls.crt = leaf2,int,root; key present" "job=$r tls.crt=$chain tls.key=$key"

ok=0; [ "$(jr w3.C1)" = Success ] && ! sec_exists "$M" cl-op1 && ok=1
verdict M23c "$ok" "K8SCluster Remove <ns>/secrets/opaque/cl-op1: secret deleted" "job Success; secret gone" \
  "job=$(jr w3.C1) secret-exists=$(sec_exists "$M" cl-op1 && echo yes || echo no)"

# ---------------------------------------------------------- wave 4 ---------
say "-- wave 4"
wave_begin
mg_rm  w4.T1 mg-tls      mg-tls
mg_rm  w4.J1 mg-jks      keystore.jks/leaf6
mg_add w4.P1 mg-p12      leaf2 "$P1F/leaf3" true true
mg_add w4.N1 mg-ns       leaf4 tls/ns-tls1 true false
mg_add w4.C1 mg-cluster  leaf2 "$M/secrets/tls/cl-tls1" true true
wave_end

ok=0; [ "$(jr w4.T1)" = Success ] && ! sec_exists "$M" mg-tls && ok=1
verdict M12b "$ok" "K8STLSSecr Remove (alias = secret name): secret deleted" "job Success; secret gone" \
  "job=$(jr w4.T1) secret-exists=$(sec_exists "$M" mg-tls && echo yes || echo no)"

ks_load "$M" mg-jks JKS
r=$(jr w4.J1)
ok=0; [ "$r" = Success ] && ! ks_has JKS leaf6:trustedCertEntry && ks_has JKS leaf3:PrivateKeyEntry && ok=1
verdict M17a "$ok" "K8SJKS Remove alias leaf6: trusted entry removed, leaf3 remains" "job Success; entries = leaf3 only" \
  "job=$r entries=$(ks_aliases "$KS_FILE" JKS | csv)"

ks_load "$M" mg-p12 PKCS12
r=$(jr w4.P1); t=$(ks_alias_thumb "$KS_FILE" PKCS12 leaf3)
ok=0; [ "$r" = Success ] && [ "$t" = leaf2 ] && ok=1
verdict M18c "$ok" "K8SPKCS12 overwrite existing alias (<field>/leaf3) with leaf2+key: replaced" \
  "job Success; alias leaf3 now holds leaf2" "job=$r alias leaf3 holds ${t:-<none>}"

r=$(jr w4.N1); chain=$(sec_chain "$M" ns-tls1 tls.crt)
ok=0; [ "$r" = Failure ] && chain_is "$chain" leaf3 leaf3,int,root && ok=1
verdict M21 "$ok" "K8SNS Add on an existing alias with overwrite=false is refused" \
  "job Failure; tls/ns-tls1 unchanged (leaf3,int,root)" "job=$r tls.crt=$chain message='$(jm w4.N1)'"

r=$(jr w4.C1); chain=$(sec_chain "$M" cl-tls1 tls.crt)
ok=0; [ "$r" = Success ] && chain_is "$chain" leaf2 leaf2,int,root && ok=1
verdict M23b "$ok" "K8SCluster overwrite tls/cl-tls1 with leaf2: replaced" "job Success; tls.crt = leaf2,int,root" "job=$r tls.crt=$chain"

# ---------------------------------------------------------- wave 5 ---------
say "-- wave 5"
wave_begin
mg_rm  w5.J1 mg-jks     keystore.jks/leaf3
mg_rm  w5.P1 mg-p12     "$P1F/leaf6"
mg_add w5.N1 mg-ns      leaf6 opaque/ns-nokey false false
mg_add w5.C1 mg-cluster leaf6 "$M/secrets/opaque/cl-nokey" false false
wave_end

ks_load "$M" mg-jks JKS
r=$(jr w5.J1); n=$(ks_count "$KS_FILE" JKS)
ok=0; [ "$r" = Success ] && [ -s "$KS_FILE" ] && [ "$n" = 0 ] && ok=1
verdict M17b "$ok" "K8SJKS Remove the last alias (leaf3): removed, an empty keystore remains" \
  "job Success; keystore secret still present with 0 entries" "job=$r keystore-bytes=$(wc -c < "$KS_FILE" | tr -d ' ') entries=$n"

ks_load "$M" mg-p12 PKCS12
r=$(jr w5.P1)
ok=0; [ "$r" = Success ] && ! ks_has PKCS12 leaf6:trustedCertEntry && ks_has PKCS12 leaf3:PrivateKeyEntry && ok=1
verdict M18d "$ok" "K8SPKCS12 Remove alias leaf6: removed" "job Success; entries = leaf3 only" \
  "job=$r entries=$(ks_aliases "$KS_FILE" PKCS12 | csv)"

r=$(jr w5.N1); typ=$(sec_type "$M" ns-nokey); chain=$(sec_chain "$M" ns-nokey tls.crt); key=$(sec_has_key "$M" ns-nokey tls.key)
ok=0; [ "$r" = Success ] && [ "$typ" = Opaque ] && [ "${chain%%,*}" = leaf6 ] && [ "$key" = no ] && ok=1
verdict M22a "$ok" "K8SNS cert-only Add opaque/ns-nokey: created, no key" "job Success; Opaque secret, tls.crt = leaf6, no key" \
  "job=$r type=$typ tls.crt=$chain key=$key"

r=$(jr w5.C1); typ=$(sec_type "$M" cl-nokey); chain=$(sec_chain "$M" cl-nokey tls.crt); key=$(sec_has_key "$M" cl-nokey tls.key)
ok=0; [ "$r" = Success ] && [ "$typ" = Opaque ] && [ "${chain%%,*}" = leaf6 ] && [ "$key" = no ] && ok=1
verdict M23d "$ok" "K8SCluster cert-only Add <ns>/secrets/opaque/cl-nokey: created, no key" "job Success; Opaque secret, tls.crt = leaf6, no key" \
  "job=$r type=$typ tls.crt=$chain key=$key"

# ---------------------------------------------------------- wave 6 ---------
say "-- wave 6"
wave_begin
mg_rm  w6.P1 mg-p12     "$P1F/leaf3"
mg_add w6.N1 mg-ns      leaf6 tls/ns-tlsnokey false false
mg_rm  w6.C1 mg-cluster "$M/secrets/tls/cl-tls1"
wave_end

ks_load "$M" mg-p12 PKCS12
r=$(jr w6.P1); n=$(ks_count "$KS_FILE" PKCS12)
ok=0; [ "$r" = Success ] && [ -s "$KS_FILE" ] && [ "$n" = 0 ] && ok=1
verdict M18e "$ok" "K8SPKCS12 Remove the last alias (leaf3): removed, an empty keystore remains" \
  "job Success; keystore secret still present with 0 entries" "job=$r entries=$n"

r=$(jr w6.N1); typ=$(sec_type "$M" ns-tlsnokey); chain=$(sec_chain "$M" ns-tlsnokey tls.crt); ksz=$(sec_field_size "$M" ns-tlsnokey tls.key)
ok=0; [ "$r" = Success ] && [ "$typ" = kubernetes.io/tls ] && [ "${chain%%,*}" = leaf6 ] && [ "$ksz" = 0 ] && ok=1
verdict M22b "$ok" "K8SNS cert-only Add tls/ns-tlsnokey: created with an empty tls.key" "job Success; tls secret, tls.crt = leaf6, empty tls.key" \
  "job=$r type=$typ tls.crt=$chain tls.key-size=$ksz"

ok=0; [ "$(jr w6.C1)" = Success ] && ! sec_exists "$M" cl-tls1 && ok=1
verdict M23e "$ok" "K8SCluster Remove <ns>/secrets/tls/cl-tls1: secret deleted" "job Success; secret gone" \
  "job=$(jr w6.C1) secret-exists=$(sec_exists "$M" cl-tls1 && echo yes || echo no)"

# ---------------------------------------------------------- wave 7 / 8 -----
say "-- wave 7"
wave_begin
mg_rm w7.N1 mg-ns      opaque/ns-op1
mg_rm w7.C1 mg-cluster "$M/secrets/opaque/cl-nokey"
wave_end

ok=0; [ "$(jr w7.N1)" = Success ] && ! sec_exists "$M" ns-op1 && ok=1
verdict M22c "$ok" "K8SNS Remove opaque/ns-op1 (<type>/<name> alias): secret deleted" "job Success; secret gone" \
  "job=$(jr w7.N1) secret-exists=$(sec_exists "$M" ns-op1 && echo yes || echo no)"
ok=0; [ "$(jr w7.C1)" = Success ] && ! sec_exists "$M" cl-nokey && ok=1
verdict M23f "$ok" "K8SCluster Remove <ns>/secrets/opaque/cl-nokey: secret deleted" "job Success; secret gone" \
  "job=$(jr w7.C1) secret-exists=$(sec_exists "$M" cl-nokey && echo yes || echo no)"

say "-- wave 8"
wave_begin
mg_rm w8.N1 mg-ns tls/ns-tlsnokey
wave_end

ok=0; [ "$(jr w8.N1)" = Success ] && ! sec_exists "$M" ns-tlsnokey && ok=1
verdict M22d "$ok" "K8SNS Remove tls/ns-tlsnokey: secret deleted" "job Success; secret gone" \
  "job=$(jr w8.N1) secret-exists=$(sec_exists "$M" ns-tlsnokey && echo yes || echo no)"

# ---------------------------------------------------------- K108 ------------
# Error/Warn log lines emitted by the extension during jobs that SUCCEEDED.
if want K108; then
  if dry; then
    verdict K108 1 "no Error/Warn log lines from the extension for successful jobs" "0 lines" "" 108
  elif [ -z "${E2E_UO_LOG_CMD:-}" ]; then
    skip K108 "log noise on successful jobs" "E2E_UO_LOG_CMD is not set (command that prints the UO log)"
  else
    E2E_HIST_LIMIT=2000
    hist_recent | jq -r --arg p "$PREFIX" '.[]? | select((.ClientMachine | startswith($p + "-")) and .Result == "Success") | .JobHistoryId' > "$WORK/tmp/okids"
    lab_uo_logs > "$WORK/tmp/uolog" || true
    if [ ! -s "$WORK/tmp/uolog" ]; then
      skip K108 "log noise on successful jobs" "E2E_UO_LOG_CMD printed nothing"
    else
      # log line: <date> <time> <jobguid> <jobhistoryid> <logger> [Level] - message   (messages are never printed)
      noise=$(awk 'NR == FNR {ids[$1] = 1; next}
                   ($4 in ids) && $5 ~ /^Keyfactor\.Extensions\.Orchestrator\.K8S/ && ($6 == "[Error]" || $6 == "[Warn]") {n++; c[$5 " " $6]++}
                   END {print n + 0; for (k in c) print "  " c[k] "x " k}' "$WORK/tmp/okids" "$WORK/tmp/uolog")
      n=$(printf '%s\n' "$noise" | head -1)
      verdict K108 "$([ "$n" = 0 ] && echo 1 || echo 0)" "no Error/Warn log lines from the extension for successful jobs" \
        "0 lines" "$n line(s); top sources: $(printf '%s\n' "$noise" | sed 1d | sort -rn | head -5 | csv)" 108
    fi
  fi
fi

finish
