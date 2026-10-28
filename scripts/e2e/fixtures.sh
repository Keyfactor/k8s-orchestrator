#!/usr/bin/env bash
# shellcheck shell=bash
#
# fixtures.sh - create the Kubernetes-side fixtures (namespaces, secrets, one
# issued CSR) and the throwaway test PKI. Idempotent: reruns reuse what exists.
#
# Every namespace/secret/CSR carries the label e2e-suite=<prefix>; names carry
# the prefix (except the one namespace that must literally be named "all", which
# is refused if it already exists without our label).
#
# Needs: E2E_KUBE_CONTEXT only. Does not talk to Command.
PHASE=fixtures
# shellcheck source=scripts/e2e/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
e2e_init "$@"; e2e_no_extra
lab_require_kube

# mk_secret NS NAME generic|tls ARGS...  (ARGS are kubectl create secret args)
mk_secret() {
  local ns=$1 name=$2 kind=$3; shift 3
  if dry; then dsay "secret $ns/$name ($kind)"; return 0; fi
  lab_kubectl -n "$ns" create secret "$kind" "$name" "$@" --dry-run=client -o json | apply_labelled \
    || die "could not create secret $ns/$name"
}

main() {
  local P=$WORK/pki ns
  if ! dry; then
    say "kube context: $E2E_KUBE_CONTEXT"
    lab_kubectl version --request-timeout=15s >/dev/null 2>&1 || die "kube context '$E2E_KUBE_CONTEXT' is not reachable"
  fi
  gen_pki

  for ns in "$NS_A" "$NS_B" "$NS_C" "$NS_IGN" "$NS_EMPTY" "$NS_M" "$NS_ALL"; do
    mk_namespace "$ns"
  done

  # ---- a
  mk_secret "$NS_A" tls-full tls --cert="$P/leaf1.chain2.pem" --key="$P/leaf1.key"
  mk_secret "$NS_A" op-pem generic --from-file=tls.crt="$P/leaf2.chain2.pem" --from-file=tls.key="$P/leaf2.key"
  mk_secret "$NS_A" op-keyonly generic --from-file=tls.key="$P/leaf3.key"
  mk_secret "$NS_A" op-certonly generic --from-file=tls.crt="$P/leaf4.crt"
  mk_secret "$NS_A" op-noise generic --from-literal=foo=bar
  mk_secret "$NS_A" jks-a generic --from-file=keystore.jks="$P/store.jks"
  mk_secret "$NS_A" p12-a generic --from-file=keystore.p12="$P/store.p12"
  mk_secret "$NS_A" docker-noise docker-registry --docker-server=registry.invalid --docker-username=u --docker-password=p
  # cert-only kubernetes.io/tls: tls.crt present, tls.key present but empty
  if dry; then
    dsay "secret $NS_A/tls-certonly (kubernetes.io/tls, tls.crt + empty tls.key)"
  else
    jq -n --arg ns "$NS_A" --rawfile c <(base64 < "$P/leaf5.crt" | tr -d '\n') \
      '{apiVersion:"v1",kind:"Secret",metadata:{name:"tls-certonly",namespace:$ns},type:"kubernetes.io/tls",data:{"tls.crt":$c,"tls.key":""}}' \
      | apply_labelled || die "the API server rejected a kubernetes.io/tls secret with an empty tls.key; cases D10, D11, I6, M11 cannot run on this cluster"
  fi
  # ---- b
  mk_secret "$NS_B" tls-b tls --cert="$P/leaf2.crt" --key="$P/leaf2.key"
  mk_secret "$NS_B" op-b generic --from-file=tls.crt="$P/leaf3.crt" --from-file=tls.key="$P/leaf3.key"
  mk_secret "$NS_B" jks-b generic --from-file=app.jks="$P/store2.jks"
  mk_secret "$NS_B" p12-b generic --from-file=app.pfx="$P/store2.p12"
  # ---- c
  mk_secret "$NS_C" tls-c tls --cert="$P/leaf5.crt" --key="$P/leaf5.key"
  mk_secret "$NS_C" c-noise generic --from-literal=hello=world
  # ---- ign
  mk_secret "$NS_IGN" tls-ign tls --cert="$P/leaf4.crt" --key="$P/leaf4.key"
  mk_secret "$NS_IGN" op-ign generic --from-file=tls.crt="$P/leaf4.crt" --from-file=tls.key="$P/leaf4.key"
  mk_secret "$NS_IGN" jks-ign generic --from-file=keystore.jks="$P/store2.jks"
  # ---- all (a namespace literally named "all")
  mk_secret "$NS_ALL" tls-all tls --cert="$P/leaf6.crt" --key="$P/leaf6.key"
  mk_secret "$NS_ALL" op-all generic --from-file=tls.crt="$P/leaf6.crt" --from-file=tls.key="$P/leaf6.key"

  mk_csr
  dry || say "fixtures ready (prefix $PREFIX, label $LBL_KEY=$LBL_VAL)"
}

# an issued kube-apiserver-client CSR for K8SCert (discovery D15, inventory I13)
mk_csr() {
  local P=$WORK/pki i th
  if dry; then dsay "CSR $CSR_NAME: create, approve, wait for the issued certificate"; return 0; fi
  if ! lab_kubectl get csr "$CSR_NAME" >/dev/null 2>&1; then
    ( umask 077
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$P/csr1.key" 2>/dev/null
      openssl req -new -key "$P/csr1.key" -out "$P/csr1.csr" -subj "/CN=$PREFIX-csr-user/O=$PREFIX" )
    jq -n --arg n "$CSR_NAME" --arg k "$LBL_KEY" --arg v "$LBL_VAL" --rawfile req <(base64 < "$P/csr1.csr" | tr -d '\n') \
      '{apiVersion:"certificates.k8s.io/v1",kind:"CertificateSigningRequest",metadata:{name:$n,labels:{($k):$v}},
        spec:{request:$req,signerName:"kubernetes.io/kube-apiserver-client",usages:["client auth"],expirationSeconds:86400}}' \
      | lab_kubectl apply -f - >/dev/null || die "could not create CSR $CSR_NAME"
    lab_kubectl certificate approve "$CSR_NAME" >/dev/null || die "could not approve CSR $CSR_NAME"
  fi
  i=0
  while [ "$i" -lt 30 ]; do
    lab_kubectl get csr "$CSR_NAME" -o jsonpath='{.status.certificate}' | base64 --decode > "$P/csr1.crt" 2>/dev/null
    [ -s "$P/csr1.crt" ] && break
    i=$((i + 1)); sleep 2
  done
  [ -s "$P/csr1.crt" ] || die "CSR $CSR_NAME was approved but no certificate was issued within 60s (is the kube-apiserver-client signer running?)"
  th=$(cert_thumb "$P/csr1.crt")
  # add csr1 to the thumbprint map
  jq --arg t "$th" '. + {($t): "csr1"}' "$P/thumbs.json" > "$P/thumbs.json.new" && mv "$P/thumbs.json.new" "$P/thumbs.json"
}

main
finish
