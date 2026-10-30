# End-to-End Lab Test Plan

This plan describes the end-to-end cases that drive the Kubernetes Orchestrator Extension through **Keyfactor Command**
and a real **Universal Orchestrator** (UO) against a real Kubernetes cluster. It complements the unit and integration
tests (which exercise the extension code directly) by covering the full path: Command schedules a job, the UO loads the
extension and runs it, and Command stores the result.

The cases were first run by hand against build `8df0e8d3` for [PR #103](https://github.com/Keyfactor/k8s-orchestrator/pull/103)
(discovery and inventory fixes for 2.0.2) and all passed, apart from the known deviations in
[section 8](#8-known-issues-k-cases). They are now codified in [`scripts/e2e/`](../scripts/e2e/README.md); every case ID
below is reported by those scripts under the same ID.

Contents: [1 Prerequisites](#1-prerequisites) · [2 Safety rules](#2-safety-rules) · [3 How to run](#3-how-to-run) ·
[4 Test data](#4-test-data) · [5 Discovery](#5-discovery-cases-d) · [6 Approve and inventory](#6-approve-and-inventory-cases-i) ·
[7 Management](#7-management-cases-m) · [8 Known issues](#8-known-issues-k-cases) ·
[9 Previous-build comparison](#9-previous-build-regression-comparison-b-cases) · [10 Not testable](#10-what-is-not-testable-in-the-lab) ·
[11 Reading results](#11-reading-results-and-keeping-the-plan-current) · [12 Assumptions and their status](#12-assumptions-status-after-the-read-only-lab-probe)

## 1. Prerequisites

Lab pieces (no credentials belong in this repository; they are supplied through environment variables, see
[`scripts/e2e/lab-env.sh`](../scripts/e2e/lab-env.sh)):

| Piece | Needed for | Notes |
|---|---|---|
| Keyfactor Command, reachable API | everything except `fixtures` | the seven store types (`K8SCert`, `K8SCluster`, `K8SJKS`, `K8SNS`, `K8SPKCS12`, `K8SSecret`, `K8STLSSecr`) must be defined, as in `integration-manifest.json` |
| A Universal Orchestrator, approved in Command, with the extension loaded | everything except `fixtures` | runs **inside the Kubernetes cluster under test** and uses its in-cluster service-account identity (store server username `kubeconfig`, blank server password) |
| A Kubernetes cluster | everything | the UO's service account can read and write secrets cluster-wide, list namespaces and read CSRs; the `kubernetes.io/kube-apiserver-client` CSR signer is running |
| A way to deploy a build to the UO | `--stage` / baseline | the suite uses the `kfclab` CLI (see `lab-env.sh`); any other mechanism can replace the `lab_ext_*` functions |
| The extension build under test, and (for the comparison) a record of the previous build | `--stage` / baseline | |

Roles and permissions:

- **Command API principal** (token): create/approve/delete certificate stores, schedule jobs, read job history,
  read orchestrators and store types, import and delete certificates.
- **Kubernetes operator** (your kube context): create/delete namespaces, secrets, CSRs (and approve them), ClusterRoles
  and ClusterRoleBindings; mint service-account tokens; impersonate service accounts (`kubectl auth can-i --as`).
- **UO service account**: as above. A broader account than the suite's scoped service account (section 5, D17-D19).

Tools on the machine running the suite: `bash`, `kubectl`, `jq`, `curl`, `openssl`, a JDK 17+ `keytool`; `yq` v4 and
`kfclab` for staging.

## 2. Safety rules

1. **Everything the suite creates is prefixed** with the run prefix (default `e2e-suite`; the PR #103 run used
   `e2e-pr103`) and carries the label `e2e-suite=<prefix>`. The single exception is the namespace literally named `all`
   (cases D1, D4, D5, D8, I11 need it): the suite refuses to run if `all` already exists without its label.
2. **Existing lab resources are never touched.** Namespaces that exist without the suite's label are never adopted or
   deleted. Command stores are only deleted when their client machine is `<prefix>` or starts with `<prefix>-`.
3. **The UO's previous extension is recorded and restored.** Before staging, the plugin entry is recorded, checked
   against what the UO pod really has deployed (staging is refused when they differ), and its local artifact
   snapshotted into the work dir; `stage-extension.sh restore` (or `cleanup.sh`) puts it back and compares a
   fingerprint of the pod's extension directory before and after. Staging restarts the UO pod, which interrupts other
   jobs on it, and changes the extension files that every UO of the lab shares (see section 12, item 9c).
4. **Everything created is deleted, and deletion is verified.** `cleanup.sh` removes Command stores and test
   certificates, namespaces, CSRs, ClusterRole/Binding and the work dir, then re-queries each and fails if anything
   remains.
5. **No generic cleanup targets.** There is no "delete all e2e" or `make` target; cleanup is always scoped to one
   prefix. (The existing `make test-cluster-cleanup` belongs to the integration tests and is unrelated.)
6. **No secrets in the repo or in output.** Test keys are generated at run time into a temp dir that cleanup removes;
   keystore passwords are random per run; tokens go to `curl` over stdin; `set -x` is never used.
7. **Dry run first.** `--dry-run` prints every action and assertion without touching a cluster, Command, or kfclab.

## 3. How to run

Full details and the environment variable list: [`scripts/e2e/README.md`](../scripts/e2e/README.md).

1. Set the `E2E_*` variables (or `E2E_ENV_FILE`) for your lab.
2. `scripts/e2e/run-all.sh --dry-run --prefix <prefix>` and read it.
3. `scripts/e2e/run-all.sh --stage --prefix <prefix>`: stages the build under test, runs fixtures, discovery,
   inventory, management and rbac, prints a per-case table, cleans up and restores the previous extension.
   Add `--baseline` for the previous-build comparison (section 9).
4. Phases can be run singly (`fixtures.sh`, `discovery.sh`, `inventory.sh`, `management.sh`, `rbac.sh`, `baseline.sh`,
   `cleanup.sh`, `stage-extension.sh`) and cases selected with `--only`.

Result statuses: `PASS`, `FAIL` (fails the run), `XFAIL` (known issue still present, expected), `XPASS` (known issue
now passes: the issue looks fixed, remove the tag), `SKIP`, and for the baseline `REPRO` / `NOREPRO`.

## 4. Test data

Generated at run time (`openssl`, `keytool`), thumbprints are SHA-1, compared case-insensitively. Names embed the prefix.

| Name | Description |
|---|---|
| `root`, `int` | root CA and intermediate CA (`CN=<prefix> Root CA`, `CN=<prefix> Intermediate CA`) |
| `leaf1`..`leaf6` | leaf certificates `CN=leafN.<prefix>.example.test` issued by `int`; `leaf2` has an EC P-256 key, the others RSA-2048 |
| `csr1` | the certificate issued for the CSR `<prefix>-csr1` (cluster signer) |

Every certificate seen in Command inventory or in a secret is mapped back to these names by thumbprint, so an
expectation reads "`leaf2` and `int`", never a raw hash. A wrong certificate in the right place fails the case.

Namespaces (all labelled): `<prefix>-a`, `-b`, `-c`, `-ign` (the ignored namespace), `-empty`, `-m` (management),
`-rbac` (scoped service account), and `all`.

| Namespace | Secret | Type | Contents |
|---|---|---|---|
| `<p>-a` | `op-pem` | Opaque | `tls.crt` = leaf2 + int, `tls.key` |
| | `op-certonly` | Opaque | `tls.crt` = leaf4 |
| | `op-keyonly` | Opaque | `tls.key` only (leaf3 key) |
| | `op-noise` | Opaque | `foo=bar` (no certificate-like key) |
| | `tls-full` | kubernetes.io/tls | leaf1 + int, key |
| | `tls-certonly` | kubernetes.io/tls | `tls.crt` = leaf5, `tls.key` present but empty |
| | `jks-a` | Opaque | `keystore.jks`: key entry `leaf1` (chain leaf1 + int) and trusted-cert entry `trustedroot` (root) |
| | `p12-a` | Opaque | `keystore.p12`: same two entries |
| | `docker-noise` | docker-registry | noise, must never be reported |
| `<p>-b` | `op-b` | Opaque | leaf3 + key |
| | `tls-b` | kubernetes.io/tls | leaf2 + key |
| | `jks-b` | Opaque | `app.jks` (same shape as jks-a) |
| | `p12-b` | Opaque | `app.pfx` (same shape as p12-a) |
| `<p>-c` | `tls-c` | kubernetes.io/tls | leaf5 + key |
| | `c-noise` | Opaque | `hello=world` |
| `<p>-ign` | `tls-ign`, `op-ign` | tls / Opaque | leaf4 + key |
| | `jks-ign` | Opaque | `keystore.jks` |
| `<p>-empty` | none | | |
| `all` | `tls-all`, `op-all` | tls / Opaque | leaf6 + key |
| `<p>-m` | created by the management cases | | |

Plus the issued CSR `<prefix>-csr1`. The keystore password is random per run.

## 5. Discovery cases (D)

How each is driven: `PUT /CertificateStores/DiscoveryJob` with the store type id, a client machine unique to the case
(`<prefix>-<kind>-<variant>`), `Dirs`, optional `IgnoredDirs` / `NamePatterns`, `ServerUsername=kubeconfig` and a blank
server password (in-cluster identity); the UO runs it. The suite waits for the job in Command job history, then reads
the stores Command received for that client machine. Discovered paths are compared without their leading cluster
segment: `<cluster>/namespace/<ns>` for K8SNS and `<cluster>/<ns>/secrets/<name>` for the other types. For secret types
only paths inside the fixture namespaces are compared, so unrelated lab secrets cannot affect a case. Leftover stores for
the case's client machine are removed first, so reruns are clean.

| ID | Store type | Case | Expected |
|---|---|---|---|
| D1 | K8SNS | dirs=`all` | exactly one store per namespace in the cluster, including the empty namespace and the namespace named `all` |
| D2 | K8SNS | dirs=`<p>-a,<p>-b` | exactly those two |
| D3 | K8SNS | dirs=`all`, ignored=`<p>-ign` | every namespace except `<p>-ign` |
| D4 | K8SNS | dirs=`all`, ignored=`<P>-IGN,ALL` (upper case) | every namespace except `<p>-ign` and `all` (case-insensitive) |
| D5 | K8SSecret | dirs=`all` | `a/op-pem`, `a/op-certonly`, `b/op-b`, `ign/op-ign`, `all/op-all`. NOT `op-keyonly`, `op-noise`, `jks-a`, `p12-a`, the docker secret, or any secret outside the fixture namespaces that the comparison ignores |
| D6 | K8SSecret | dirs=`<p>-a,<p>-b` | `a/op-pem`, `a/op-certonly`, `b/op-b` |
| D7 | K8SSecret | dirs=`all`, ignored=`<p>-ign` | D5 without `ign/op-ign` |
| D8 | K8SSecret | dirs=`all`, ignored=` <P>-IGN , all ` (case and whitespace) | D5 without `ign/op-ign` and `all/op-all` |
| D9 | K8SSecret | dirs=`<p>-a`, patterns=`tls.key` (additive) | `op-pem`, `op-certonly` and now also `op-keyonly` |
| D10 | K8STLSSecr | dirs=`all` | `a/tls-full`, `a/tls-certonly`, `b/tls-b`, `c/tls-c`, `ign/tls-ign`, `all/tls-all` (all `kubernetes.io/tls`, including the cert-only one) |
| D11a | K8STLSSecr | dirs=`<p>-a,<p>-b` | `a/tls-full`, `a/tls-certonly`, `b/tls-b` |
| D11b | K8STLSSecr | dirs=`all`, ignored=`<p>-ign` | D10 without `ign/tls-ign` |
| D12 | K8SJKS | dirs=`all` | `a/jks-a`, `b/jks-b`, `ign/jks-ign` (data keys matched by `.jks` suffix: `keystore.jks`, `app.jks`) |
| D13a | K8SJKS | dirs=`<p>-a,<p>-b` | `a/jks-a`, `b/jks-b` |
| D13b | K8SJKS | dirs=`all`, ignored=`<p>-ign` | `a/jks-a`, `b/jks-b` (`jks-ign` absent) |
| D14a | K8SPKCS12 | dirs=`all` | `a/p12-a`, `b/p12-b` (data keys `keystore.p12`, `app.pfx`) |
| D14b | K8SPKCS12 | dirs=`<p>-a,<p>-b` | `a/p12-a`, `b/p12-b` |
| D14c | K8SPKCS12 | dirs=`all`, ignored=`<p>-ign` | `a/p12-a`, `b/p12-b` |
| D15 | K8SCert | dirs=`all` | `<p>-csr1` is among the discovered CSRs |
| D16 | K8SCluster | discovery | **SKIP**: the shipped K8SCluster store type has `Discovery=false`; the suite reads the capability from Command and skips with that reason |
| D17a-d | K8SSecret, K8STLSSecr, K8SJKS, K8SPKCS12 | scoped service account (section 5.1): dirs=`all`, **every namespace except `<p>-a` and `<p>-b` ignored** | job Success; exactly the secrets of `<p>-a` and `<p>-b` for that type (secret: `op-pem`, `op-certonly`, `op-b`; tls: `tls-full`, `tls-certonly`, `tls-b`; jks: `jks-a`, `jks-b`; pkcs12: `p12-a`, `p12-b`) |
| D18 | K8SSecret | scoped service account, dirs=`<p>-a,<p>-ign`, ignored=`<p>-ign` | job Success; `a/op-pem`, `a/op-certonly` |
| D19 | K8SSecret | scoped service account, same as D17 but `<p>-ign` **not** ignored (negative control) | job **Failure** mentioning Forbidden/403. Proves the RBAC is real and that excluding ignored namespaces *before listing secrets* is what makes D17/D18 pass |

### 5.1 Scoped service account (D17-D19)

`rbac.sh` creates (all prefixed and labelled) namespace `<p>-rbac`, service account `<p>-scoped`, ClusterRole +
ClusterRoleBinding `<p>-ns-lister` (get/list `namespaces` only), and Role + RoleBinding `<p>-secrets` in `<p>-a` and
`<p>-b` (all verbs on secrets). It checks with `kubectl auth can-i --as=...` that the account can list secrets in `a` and
`b`, cannot in `ign` or `kube-system`, and can list namespaces; any other result aborts the phase before a single
discovery job is sent. A 1-hour token is written into a kubeconfig (mode 600, work dir only) pointing at the API server
URL as the UO sees it (`E2E_RBAC_API_SERVER`), and sent to Command only as the discovery job's server password.

## 6. Approve and inventory cases (I)

How each is driven: the store is approved from the discovered entry of the matching discovery case
(`POST /CertificateStores/Approve` with `InventorySchedule.Immediate`, store type id, properties
`{ServerUsername: kubeconfig, ServerUseSsl: false, ...}`), **without pre-filling the namespace or secret name**, so the
extension's resolution of discovered store paths is part of what is tested. Keystore stores also get the keystore
password and `CertificateDataFieldName`. I4 and I12 use stores created by hand (`POST /CertificateStores`), because
discovery correctly does not report a key-only secret and K8SCluster has no discovery. The suite then waits for the
Inventory job in job history (it must be `Success`), reads `GET /CertificateStores/{id}/Inventory`, and compares for each
entry: alias, the private-key flag (`Yes`/`No`) and the **set of certificate thumbprints mapped to the generated names**.
`~x,y` below means "contains at least these"; a plain list is an exact set.

| ID | Store | Expected inventory (per entry: alias, private-key flag, certificates) |
|---|---|---|
| I1 | K8SSecret `a/op-pem` | one entry: key=Yes, certs = {leaf2, int} |
| I2 | K8SSecret `a/op-certonly` | one entry: key=No, certs = {leaf4} |
| I3 | K8SSecret `b/op-b` | one entry: key=Yes, certs = {leaf3} |
| I4 | K8SSecret `a/op-keyonly` (hand-made) | job **Success**, zero entries, message "No certificates found in store" |
| I5 | K8STLSSecr `a/tls-full` | key=Yes, certs = {leaf1, int} |
| I6 | K8STLSSecr `a/tls-certonly` | key=No, certs = {leaf5} |
| I7 | K8SJKS `a/jks-a` (`CertificateDataFieldName=keystore.jks`) | exactly two entries: `keystore.jks/leaf1` key=Yes (certs include leaf1); `keystore.jks/trustedroot` key=No (certs = {root}) |
| I8 | K8SJKS `b/jks-b` (`CertificateDataFieldName=app.jks`) | same shape with aliases `app.jks/leaf1`, `app.jks/trustedroot` |
| I9a | K8SPKCS12 `a/p12-a` (`keystore.p12`) | `keystore.p12/leaf1` key=Yes (includes leaf1); `keystore.p12/trustedroot` key=No (root). One extra intermediate-CA alias with key=No is accepted (parity with 1.3.0); any other extra entry fails |
| I9b | K8SPKCS12 `b/p12-b` (`app.pfx`) | same with `app.pfx/...` |
| I10a | K8SNS namespace `<p>-a` | exactly 4 entries, aliases `<type>/<name>`: `tls/tls-full` (Yes, includes leaf1), `tls/tls-certonly` (No, {leaf5}), `opaque/op-pem` (Yes, includes leaf2), `opaque/op-certonly` (No, {leaf4}) |
| I10b | K8SNS `<p>-b` | `tls/tls-b` (Yes, includes leaf2), `opaque/op-b` (Yes, includes leaf3) |
| I10c | K8SNS `<p>-c` | `tls/tls-c` (Yes, includes leaf5) |
| I10d | K8SNS `<p>-empty` | job Success with no entries |
| I11 | K8SNS namespace literally named `all` | **only** `opaque/op-all` and `tls/tls-all` (Yes, includes leaf6): not the secrets of other namespaces |
| I12 | K8SCluster (hand-made) | every Opaque and tls secret that holds a certificate, alias `<ns>/secrets/<type>/<name>`; compared inside the fixture namespaces: a: `tls/tls-full`, `tls/tls-certonly`, `opaque/op-pem`, `opaque/op-certonly`; b: `tls/tls-b`, `opaque/op-b`; c: `tls/tls-c`; ign: `tls/tls-ign`, `opaque/op-ign`; all: `tls/tls-all`, `opaque/op-all`. No keystore, key-only, noise or docker secrets |
| I13 | K8SCert `<p>-csr1` | one entry, alias `<p>-csr1`, key=No, certs = {csr1} |

## 7. Management cases (M)

How each is driven: certificates are imported into Command (`POST /Certificates/Import`: leaf2, leaf3, leaf4 as PFX
with int + root so Command can build the chain, leaf6 as a bare certificate with no key). The inventory phase has by then
already put the same certificates into Command **without a key**, and an import never adds a key to an existing record,
so a keyless record of a test certificate is deleted first and the PFX imported again (the import fails the phase when
the record still has no private key). Stores in `<p>-m` are created
with `CreateIfMissing` (`POST /CertificateStores`, approved, `AgentAssigned`). Operations use
`POST /CertificateStores/Certificates/Add` (`CertificateId`, `Overwrite`, `IncludePrivateKey`, `Alias`, `PfxPassword`)
and `.../Remove`. They run in **waves** with at most one operation per store per wave, so each Command job can be
attributed unambiguously; after each wave Command's inventory of the touched stores is refreshed (Remove and
overwrite-by-alias need the alias in Command's inventory). Every result is checked twice: the job result and message in
Command job history, and the real Kubernetes object read back with `kubectl`, `openssl` and `keytool` (certificate
order in `tls.crt`, presence and size of `tls.key`, keystore aliases, entry types and thumbprints).

Aliases: K8SSecret / K8STLSSecr: optional, the inventory alias is the secret name; K8SJKS / K8SPKCS12: `<alias>` on add,
`<data field>/<alias>` in inventory; K8SNS: `<tls|opaque>/<secret name>`; K8SCluster: `<ns>/secrets/<tls|opaque>/<name>`.

"3 certs" means leaf, intermediate, root (the chain Command holds for the imported PFX). Where a cert-only add is
checked, only the first certificate (the leaf) is asserted, because whether Command appends a chain to a key-less add is
not part of the contract.

| ID | Store | Operation | Expected |
|---|---|---|---|
| M1 | K8SSecret (IncludeCertChain=true, SeparateChain=false) | Add leaf3 + key | job Success; `tls.crt` = leaf3, int, root (leaf first); `tls.key` present |
| M2 | K8SSecret (SeparateChain=true) | Add leaf3 + key | `tls.crt` = leaf3 only; `ca.crt` = {int, root}; `tls.key` present |
| M3 | K8SSecret (IncludeCertChain=false) | Add leaf3 + key | `tls.crt` = leaf3 only; no `ca.crt` |
| M4 | K8SSecret (existing, M1) | Add cert-only leaf6, overwrite=false | **refused**, at either layer: Command rejects the request at scheduling, or the job **Fails** with "already exists" (Set overwrite=true). Secret unchanged (still leaf3, int, root + key) |
| M5 | K8SSecret (M2) | overwrite=true via the inventory alias (secret name), leaf4 + key | job Success; `tls.crt` = leaf4; `ca.crt` = {int, root}; key present |
| M6 | K8SSecret (fresh) | cert-only Add leaf6 | job Success; `tls.crt` leaf6; no private key; Command shows key=No |
| M6b | same | Remove via inventory alias | job Success; secret deleted |
| M7 | K8SSecret (M1) | Remove via the inventory alias | job Success; secret deleted (and it stays deleted: the refused Add of M4 is unscheduled, see section 12) |
| M8a | K8STLSSecr (include chain) | Add leaf3 + key | type `kubernetes.io/tls`; `tls.crt` = leaf3, int, root; key present |
| M8b | K8STLSSecr (SeparateChain=true) | Add leaf3 + key | `tls.crt` = leaf3; `ca.crt` = {int, root}; key present |
| M8c | same | Remove (alias = secret name; Command refuses an empty alias) | job Success; secret deleted |
| M9 | K8STLSSecr (SeparateChain=true **and** IncludeCertChain=false) | Add leaf3 + key | SeparateChain is overridden: `tls.crt` = leaf3 (1 cert), **no** `ca.crt`; key present |
| M10 | K8STLSSecr (holds leaf3 + key) | cert-only Add leaf6, overwrite=true, alias = secret name (Command refuses an empty alias) | **refused**, at either layer: the job **Fails** (intentional guard in the extension: a cert-only add must not strip an existing key) or Command rejects the request; secret unchanged |
| M11 | K8STLSSecr (fresh) | cert-only Add leaf6 | job Success; type tls; `tls.crt` leaf6; `tls.key` present but **empty** (a warning is logged); Command shows key=No |
| M11b | same | Remove | job Success; secret deleted |
| M12a | K8STLSSecr (M8a) | overwrite=true, alias = secret name, leaf4 + key | `tls.crt` = leaf4, int, root; key present (replaced) |
| M12b | same | Remove (alias = secret name) | secret deleted |
| M13 | K8SJKS | Add leaf3 + key (alias `leaf3`) | alias `leaf3` is a PrivateKeyEntry |
| M14 | K8SJKS (M13) | cert-only Add leaf6 (alias `leaf6`) | `leaf6` is a trustedCertEntry; `leaf3` untouched; Command shows key=No for `keystore.jks/leaf6` |
| M15 | K8SJKS | Add leaf2 + key, alias `keystore.jks/leaf3`, overwrite=true | alias `leaf3` now holds leaf2 as a key entry (replaced) |
| M16 | K8SJKS (IncludeCertChain=false) | Add leaf3 + key | key entry `leaf3` with certificate chain length 1 |
| M17a | K8SJKS | Remove `keystore.jks/leaf6` | trusted entry gone, `leaf3` remains |
| M17b | K8SJKS | Remove `keystore.jks/leaf3` (last alias) | removed; the keystore secret remains, with 0 entries |
| M18a | K8SPKCS12 | Add leaf3 + key | alias `leaf3` is a PrivateKeyEntry |
| M18b | K8SPKCS12 | cert-only Add leaf6 | `leaf6` is a trustedCertEntry |
| M18c | K8SPKCS12 | Add leaf2 + key, alias `<field>/leaf3`, overwrite=true | alias `leaf3` now holds leaf2 |
| M18d | K8SPKCS12 | Remove `<field>/leaf6` | removed |
| M18e | K8SPKCS12 | Remove `<field>/leaf3` (last alias) | removed; keystore remains with 0 entries |
| M19 | K8SNS | Add `tls/ns-tls1` (leaf3 + key) and `opaque/ns-op1` (leaf4 + key) | both jobs Success; secret `ns-tls1` is `kubernetes.io/tls`, `ns-op1` is Opaque, both with a key |
| M19i | K8SNS | inventory afterwards | lists `tls/ns-tls1` and `opaque/ns-op1` |
| M20 | K8SNS | overwrite `opaque/ns-op1` with leaf2 (EC) + key | `tls.crt` = leaf2, int, root; key present (replaced) |
| M21 | K8SNS | Add `tls/ns-tls1` again, overwrite=false | **refused**, at either layer: Command rejects the request at scheduling ("Overwrite must be true in order to replace the certificate with alias ..."; what the lab does), or the job **Fails**. Secret unchanged (leaf3, int, root) |
| M22a | K8SNS | cert-only Add `opaque/ns-nokey` (leaf6) | created, Opaque, `tls.crt` leaf6, no key |
| M22b | K8SNS | cert-only Add `tls/ns-tlsnokey` (leaf6) | created, `kubernetes.io/tls`, `tls.key` present but empty |
| M22c | K8SNS | Remove `opaque/ns-op1` | secret deleted |
| M22d | K8SNS | Remove `tls/ns-tlsnokey` | secret deleted |
| M23a | K8SCluster | Add with key: `<m>/secrets/opaque/cl-op1` (leaf4), `<m>/secrets/tls/cl-tls1` (leaf3) | both jobs Success; Opaque and tls secrets created with keys |
| M23b | K8SCluster | overwrite `<m>/secrets/tls/cl-tls1` with leaf2 + key | `tls.crt` = leaf2, int, root |
| M23c | K8SCluster | Remove `<m>/secrets/opaque/cl-op1` | secret deleted |
| M23d | K8SCluster | cert-only Add `<m>/secrets/opaque/cl-nokey` (leaf6) | created, no key |
| M23e | K8SCluster | Remove `<m>/secrets/tls/cl-tls1` | secret deleted |
| M23f | K8SCluster | Remove `<m>/secrets/opaque/cl-nokey` | secret deleted |
| M24 | K8SCert | Add and Remove | **Command refuses at scheduling** (any HTTP >= 400 for both, no job scheduled; the lab answers the Add with 400 and the Remove with 500, a Command quirk); K8SCert is read-only |

`<m>` is the namespace `<p>-m`. The management sequence is single-shot: it refuses to start if `<p>-m` already holds
secrets.

## 8. Known issues (K cases)

These are real deviations found during the PR #103 run. They pre-date the PR and are tracked as GitHub issues. Each is
codified as a case that asserts the **correct** behaviour and is tagged with its issue number, so it reports `XFAIL` while
the bug exists and `XPASS` (loudly) as soon as it is fixed; removing the tag then turns it into a normal regression case.
They never fail the run (unless `E2E_STRICT_XPASS=true`).

| ID | Issue | Correct behaviour asserted | Current behaviour |
|---|---|---|---|
| K105a | [#105](https://github.com/Keyfactor/k8s-orchestrator/issues/105) | K8SJKS store created with `CertificateDataFieldName=app.jks`: after an Add the secret's data key is `app.jks` | writes `keystore.jks` |
| K105b | #105 | K8SPKCS12 store with `CertificateDataFieldName=keystore.p12`: the data key is `keystore.p12` | writes `keystore.pfx` |
| K106a | [#106](https://github.com/Keyfactor/k8s-orchestrator/issues/106) | K8SJKS Add (leaf4) on an existing alias with overwrite=false is refused (job Failure) and the alias still holds leaf3 | replaces the entry |
| K106b | #106 | the same for K8SPKCS12 | replaces the entry |
| K107 | [#107](https://github.com/Keyfactor/k8s-orchestrator/issues/107) | a K8SNS store created with `CreateIfMissing` completes its Create job with Success | fails with "Invalid namespace alias format: ''" and is retried every 5 minutes |
| K107b | #107 (same class) | a K8SCluster store created with `CreateIfMissing` completes its Create job with Success | fails with "Invalid cluster alias format: ''. Expected: namespace/secrets/type/name" and is retried (the suite unschedules the retries) |
| K108 | [#108](https://github.com/Keyfactor/k8s-orchestrator/issues/108) | jobs that finished `Success` leave no `[Error]` / `[Warn]` log lines from `Keyfactor.Extensions.Orchestrator.K8S.*` in the UO log | noisy Error/Warn lines on successful jobs |

K107 needs a fresh prefix (the Create job only runs when the store is created). K108 needs `E2E_UO_LOG_CMD`; it reads
the UO log, keeps lines whose fourth field (the job history id) belongs to a successful job of this run and whose
logger starts with `Keyfactor.Extensions.Orchestrator.K8S`, counts the `[Error]` and `[Warn]` ones, and prints only
counts per logger (never log messages). Otherwise it reports SKIP.

K106 is the "Add on an existing alias with overwrite=false must be refused" case that the PR #103 run recorded for
JKS and PKCS12.

## 9. Previous-build regression comparison (B cases)

Purpose: show that the behaviours fixed by the change under test really were broken in the build that was deployed
before, using the same stores.

Procedure:

1. Run the main suite with the build under test staged (sections 5-8). This creates the approved stores.
2. Stage the previous build on the UO. With `run-all.sh --stage --baseline` this is automatic: `stage-extension.sh stage`
   records the previous extension entry and snapshots its artifact; after the main phases `stage-extension.sh restore`
   puts it back. (Alternatively stage any older build by hand and run `baseline.sh`.)
3. Run `baseline.sh`. It re-runs discovery with `dirs=all` for six store types and re-inventories four of the stores
   from section 6, then reports for each case `REPRO` (the old behaviour is reproduced) or `NOREPRO` (the previous
   build already behaves correctly, so this case proves nothing for that build).
4. Re-run `inventory.sh` afterwards if you want Command's inventory refreshed by the build under test.

| ID | Old behaviour that must reproduce (observed on the build deployed before PR #103) |
|---|---|
| B1 | `dirs=all` discovery returns **0 stores** on all 6 jobs (K8SSecret x2 [with and without ignored namespace], K8SNS, K8STLSSecr, K8SJKS, K8SPKCS12): "Failed to parse discovery directories" |
| B2 | inventory of the key-only Opaque secret (`op-keyonly`, I4) **fails** with a Base-64 error |
| B3 | JKS inventory of `jks-a` is **missing** the trusted alias `keystore.jks/trustedroot` |
| B4 | PKCS12 `HasPrivateKey` is **always Yes**: `trustedroot` is reported with a private key |
| B5 | the K8SNS store for the namespace literally named `all` inventories other namespaces too (about 93 secret errors in the log); anything other than exactly `op-all` and `tls-all`, or a failed job, counts as reproduced |

`--require-repro` turns a NOREPRO into a failure; use it only against a build known to carry the old behaviour. A live
comparison with 1.3.0 was not possible in the lab (section 10).

## 10. What is not testable in the lab

| Item | Why |
|---|---|
| Reenrollment | the shipped store types have `Enrollment=false` in the lab |
| K8SCluster discovery (D16) | the store type has `Discovery=false`; the suite SKIPs with that reason |
| JKS / PKCS12 password supplied from another Kubernetes secret (`PasswordIsK8SSecret`, `StorePasswordPath`, `PasswordFieldName`) | the lab's store type definitions lacked these properties. A lab whose store types carry them can add cases; the fixtures are cheap (a second secret holding the password, with a trailing newline) |
| A live comparison with 1.3.0 | not deployable alongside in that lab; the previous-build comparison (section 9) uses whatever build was deployed |
| A 1.x-style `secrets/<tls\|opaque>/<name>` alias on K8SNS Remove | Command rejects an alias that is not in its own inventory, so the request never reaches the extension (the extension still accepts the form, which is covered by unit tests) |
| Authentication other than the UO's in-cluster identity (kubeconfig token / client certificate on the store) | the lab UO runs in the cluster under test; only the scoped-service-account discovery cases (D17-D19) send an explicit kubeconfig |

## 11. Reading results and keeping the plan current

- `FAIL` is a real regression (or a lab problem); the `expected:` and `actual:` lines say which. Check the job message
  in Command job history and the UO log for the job id.
- `XFAIL` is a known issue. When an issue is fixed, the case flips to `XPASS`; remove the issue argument from its
  `verdict` call in `management.sh` and move its row from section 8 into the normal tables.
- To add a case: add a row here with an ID, then add the matching case in the right phase script using
  `verdict`/`expect_eq`/`set_eq`/`inv_check` so it reports under that ID. Keep IDs stable; split a row into lettered
  sub-IDs (`M8a`, `M8b`) rather than renumbering.
- When a case changes, change this document and the script together.

## 12. Assumptions: status after the read-only lab probe

Before the first real run the suite's assumptions about the lab and the Command API were checked with read-only calls
(GET/list requests, `kubectl get` / `auth can-i`, and the suite's own read-only helpers): nothing was staged, created,
modified or deleted. The first column gives the original assumption number. Status: **confirmed**, **corrected** (the
suite was changed), or **not probed** (the check would have to change state; the first real run is the check).

| # | Assumption | Status | Evidence / change |
|---|---|---|---|
| 1 | The UO's agent is `ClientMachine == kfclab-uo-<E2E_UO_NAME>` in `GET /Agents` | confirmed | `GET /Agents` returns `AgentId` and `ClientMachine` (`kfclab-uo-<name>`); job history carries the same value in `AgentMachine`; the stores served by the UO have that `AgentId` |
| 2 | Job history matching on client machine, store path suffix, job type, `Completed*` status | confirmed | Fields are `ClientMachine` (the **store's** client machine), `StorePath` (the full store path including the discovered cluster segment; **null** for discovery jobs, which the suite matches without a path), `JobType` (`K8SNSDiscovery`, `K8SSecretInventory`, `K8STLSSecrManagement`, ...), `Status` (`Completed`, `CompletedWillRetry`, `InProcess`), `Result` (`Success`, `Failure`, `Unknown`), `Message`. A job that will be retried is `CompletedWillRetry` and gets a **new** `JobHistoryId` on every retry |
| 2b | `SortAscending=1` returns the newest first | confirmed | The parameter is an enum (0, 1); `1` returns descending `OperationStart`, `0` ascending. `OperationStart` has one-minute resolution, so ties inside a minute are in arbitrary order; harmless because the suite takes the maximum id. The newest 500 entries cover days on a quiet lab; on a lab running hundreds of jobs per hour raise `E2E_HIST_LIMIT` |
| 2c | A job's history entry is unique | **corrected** | A job whose result is a failure is `CompletedWillRetry` and Command re-runs it about every 5 minutes; every retry is a new history entry with a higher `JobHistoryId` but the same `JobId`. A retry of an earlier failed Add (e.g. the overwrite=false case) or of the K107 Create job could therefore be taken for the result of a later job on the same store. The suite now remembers the `JobId` of every job it has waited for and ignores their later retries. A retry also re-applies the request to whatever the store holds by then, which broke M7 (see "What the first complete run taught"); `batch_wait` now unschedules every job it has recorded as failed-and-retrying (`POST /OrchestratorJobs/Unschedule`, HTTP 204; the job id is the history `JobId` and disappears from `GET /OrchestratorJobs/ScheduledJobs`) |
| 3 | `Parameters.PrivateKeyEntry` is `Yes`/`No` | confirmed | Only parameter on inventory rows, values `Yes` / `No`; thumbprints are 40 hex characters |
| 4 | Cert-only add with `IncludeCertChain=true` returns `tls.crt` starting with the leaf | not probed | needs a write |
| 5 | `tls.crt` is leaf-first | not probed | needs a write |
| 6 | Alias forms for overwrite/remove | partly | K8SNS (`<tls\|opaque>/<name>`) and K8SCluster (`<ns>/secrets/<tls\|opaque>/<name>`) aliases were seen in existing inventories. JKS/PKCS12 alias forms and the PKCS12 data field detection could not be observed |
| 7 | `CreateIfMissing` on K8SNS schedules a Management job (K107) | confirmed | History of an earlier run: a `CreateIfMissing` K8SNS store scheduled a `K8SNSManagement` job with the namespace as `StorePath`, `CompletedWillRetry` / `Failure` ("Invalid namespace alias format"), and was re-queued every ~5 minutes while the store existed (one history entry per retry). The other store types scheduled a `*Management` job on creation too. The K8SCluster store behaves the same way: its Create job fails with "Invalid cluster alias format: ''" (first complete run), now case K107b (known issue 107) |
| 8 | The token may delete certificates | confirmed (by permissions, not exercised) | `GET /Security/My` for the token lists the `Administrator` and `InstanceAdmin` roles with `Certificates:Delete` and `CertificateStoreManagement:Modify`/`Schedule`/`Read` (store create/delete, scheduling, discovery). `DELETE /Certificates` takes a JSON array of integer ids and `DELETE /CertificateStores` an array of GUIDs, as `cleanup.sh` sends them. The token is the lab's Command OAuth client, so it is broadly privileged |
| 9 | `kfclab extension update` on an edited private copy of the spec re-stages the build and restarts the UO | confirmed, with corrections | It resolves the artifact, stages it, rollout-restarts the UO, waits for the new pod to be Ready and compares the primary DLL hash in the running pod with the artifact. **Corrected:** `kfclab extension list` is a listing of kfclab's global plugin cache (not per UO), ignores `--json`, and its `--uo` filter compares against the *source* so it never matches; it cannot confirm a restore. The suite now fingerprints the extension directory inside the UO pod (sha256 of every `*.dll` and `manifest.json`, via `kubectl exec`) before staging, after staging and after restore |
| 9b | The spec's "previous" extension is what is deployed | confirmed, now enforced | For the lab checked, the fingerprint of the spec's local build directory equals the pod's. That directory is a developer's working build output though, so `stage-extension.sh` now refuses to stage when it differs (`E2E_ALLOW_PREVIOUS_MISMATCH=true` overrides) |
| 9c | Staging affects only the target UO | **no** | The extension directory is one volume shared by every UO of the lab (mounted per extension by sub-path); `kfclab extension update` restarts only the target UO's pod. The other UOs keep the assemblies they loaded at startup but see the new files on disk, and may load them if they restart or load a dependency lazily. See "Staging risk" in the [README](../scripts/e2e/README.md) |
| 10 | K108 log line layout | confirmed | `<date> <time> <job guid> <job history id> <logger> [Level] - message`; the fourth field equals `JobHistoryId`. The lab's UO logs at Trace and the container log is rotated by size, so the suite now skips K108 instead of reporting XPASS when the log does not reach back to the run's first successful job |
| 11 | Duration | not measured | dominated by waiting on the UO; record the first real run's duration here |

Setup facts the probe established (generic; the real values belong in your env file):

- `kfclab token -f <spec>` prints a bare JWT (three dot-separated segments) valid for about a day, so it works directly as
  `E2E_TOKEN_CMD`. The Command endpoint is served with the lab's own CA, so `E2E_CA_CERT` is required.
- kfclab writes a separate kubeconfig for the lab cluster whose only context has a generic name, so both
  `E2E_KUBECONFIG` and `E2E_KUBE_CONTEXT` are needed. The suite refuses the `kf-integrations` context.
- The UO pod's service account is bound to secrets (all verbs), namespaces (get/list) and CSRs, cluster-wide, as the
  suite assumes; `kubernetes.default.svc` is in the API server certificate, so the default `E2E_RBAC_API_SERVER` works.
- Store type definitions in the lab match the suite: K8SCluster has `Discovery=false`; K8SCert only supports discovery;
  all other types support Add/Remove/Create/Discovery; none supports Enrollment. K8SJKS and K8SPKCS12 have
  `CertificateDataFieldName` (required, default `.p12`, for PKCS12) but none of the password-from-secret properties.
  `KubeNamespace`, `KubeSecretName`, `IncludeCertChain` and `SeparateChain` exist where the suite sets them.

### What the first real run taught

The first full run (discovery D1-D15 and inventory I1-I13 passed; extension staging and restore worked) failed in the
management phase and mis-reported cleanup. Each finding changed the suite:

- **Every Add was refused ("No private key could be found for the given certificate", HTTP 400 `0xA0110010`).**
  Cause: the suite looked a certificate up by thumbprint before importing it and skipped the import when a record
  existed. By the management phase the inventory phase had already put leaf2, leaf3 and leaf4 into Command, because the
  fixture secrets in `<p>-a` / `<p>-b` hold those certificates and a store inventory creates a certificate record
  **without a private key**. Command's `POST /Certificates/Import` does not add a key to an existing record (HTTP 200
  with `ImportStatus` `ExistsMissingOwnerRole`; the record stays keyless), so `cid.leaf3` pointed at a keyless record and
  every Add with `IncludePrivateKey=true` was rejected at scheduling. The earlier manual run imported the PFX files
  before any inventory, which is why it worked. The PFX generation, the import request and the Add body were never the
  problem. `cert_import` now checks the record with `GET /Certificates/{id}?includeHasPrivateKey=true` (the list
  endpoint reports `HasPrivateKey: false` for keyed certificates too), deletes a keyless record of one of the suite's own
  test certificates (issuer = the run's test CA; deleting a certificate that has inventory locations is allowed) and
  imports the PFX again, and fails the phase when the record still has no key afterwards. Proven against the lab with a
  minimal store: keyless record from an inventory -> Add rejected -> `cert_import` replaces it -> Add accepted, the
  Management job completed `Success`, the secret holds leaf, intermediate, root and a private key.
- **Cleanup reported "verified" while 157 stores and 8 certificates were still in Command.** Every phase removed the
  shared `<work dir>/tmp` on exit. `cleanup.sh` starts `stage-extension.sh restore` as a child; when that child exited it
  deleted the directory the parent was still using (a management phase that was still running lost it the same way),
  so every later API call failed ("mkstemp failed", no token, HTTP 000). The listing helpers turned each failure into an
  empty result, and "found 0 store(s)" ended in "cleanup verified" with exit 0. Fixes: scratch space is per process
  (`<work dir>/tmp/<pid>`, only removed by its owner, recreated if it vanishes); every list of owned stores, certificates
  and cluster objects distinguishes "empty" from "could not ask" (no token, HTTP 000, non-2xx, not a JSON array, kubectl
  error) and cleanup then exits non-zero with "cleanup FAILED ... NOTHING is verified"; the post-delete verification
  fails closed the same way. `scripts/e2e/selftest.sh` proves this offline with a mock `curl` (HTTP 000, 500, a body
  that is not a list, no token, unreachable cluster) and a positive control.
- **A rejected Add still waited out the full job timeout.** `mg_add` only warned about the HTTP 400 and registered the
  job anyway, so each of the 12 rejected Adds waited `E2E_JOB_TIMEOUT` (300 s), about an hour in all. Now every helper
  that asks Command to schedule something (Add, Remove, Schedule/inventory refresh, discovery job, approve, store create)
  treats a non-2xx answer as a `FAIL` on the spot, with Command's `FailedOperations` reason (no secrets in it), and does
  not register a job; dependent cases fail with the same reason; `E2E_MAX_REJECTS` (default 3) rejections in a row abort
  the phase. A job history that cannot be read for about a minute also ends the waits.

## Appendix: case IDs to scripts

| IDs | Script |
|---|---|
| D1-D15 (D11a/b, D13a/b, D14a-c), D16 | `discovery.sh` |
| D17a-d, D18, D19 | `rbac.sh` |
| I1-I13 (I9a/b, I10a-d) | `inventory.sh` |
| M1-M24 and sub-IDs, K105-K108 | `management.sh` |
| B1-B5 | `baseline.sh` |
