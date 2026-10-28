# End-to-end lab suite

Runnable version of the test plan in [docs/e2e-lab-test-plan.md](../../docs/e2e-lab-test-plan.md). It drives the
extension through **Keyfactor Command** and a real **Universal Orchestrator** (UO): discovery, approve + inventory,
management (Add/Remove), scoped-service-account discovery, and a comparison against the previously deployed build.
Read the plan first for what each case ID means and what the expected result is.

This is not part of CI and no `make` target runs it. It needs a lab you own: it schedules real jobs, creates
Kubernetes namespaces, and (with `--stage`) restarts a UO.

## Safety model

- Every resource carries the **run prefix** (`--prefix`, default `e2e-suite`; must match `^e2e[a-z0-9-]{3,40}$`):
  namespaces `<prefix>-a|b|c|ign|empty|m|rbac`, the CSR `<prefix>-csr1`, ClusterRole/ClusterRoleBinding
  `<prefix>-ns-lister`, Command client machines `<prefix>-*`, certificate CNs `<prefix> Root CA` etc.
  Kubernetes objects are also labelled `e2e-suite=<prefix>`.
- The one exception is a namespace literally named `all` (case D1/I11 need it). `fixtures.sh` refuses to run if `all`
  already exists without our label, and `cleanup.sh` deletes `all` only when it carries our label.
- Nothing else is ever modified. There is no "delete everything" mode: `cleanup.sh` deletes by prefix and label only,
  then verifies, and exits non-zero if anything is left.
- The UO's previous extension is recorded (and its local artifact snapshotted) before `--stage` replaces it, and is
  restored by `stage-extension.sh restore` or by `cleanup.sh`.
- Generated key material, the keystore password (random per run), the scoped kubeconfig and the lab-spec copy live only
  in the work dir (`${TMPDIR:-/tmp}/e2e-lab-<prefix>`, mode 700), which `cleanup.sh` removes. Nothing secret is printed,
  `set -x` is never used, and the API token is passed to `curl` over stdin, never on a command line.
- `--dry-run` prints what every phase would do and touches nothing (no kubectl, no Command, no kfclab; it uses a
  throwaway temp dir that is removed on exit).

## Requirements

Tools: `bash` (3.2+, macOS is fine), `kubectl`, `jq`, `curl`, `openssl`, a JDK 17+ `keytool`; `yq` (mikefarah v4) and the
`kfclab` CLI only for `stage-extension.sh`. `shellcheck` is optional (used for the static checks).

Lab:

- A Command instance with the seven K8S store types defined (`K8SCert`, `K8SCluster`, `K8SJKS`, `K8SNS`, `K8SPKCS12`,
  `K8SSecret`, `K8STLSSecr`; names as in `integration-manifest.json`) and an **approved** UO with the extension loaded.
- The UO runs **inside the Kubernetes cluster the stores live in** and authenticates with its in-cluster service-account
  identity (store server username `kubeconfig`, blank server password). That service account must be able to read/write
  secrets cluster-wide, list namespaces, and read CSRs.
- An API token (any mechanism, see `E2E_TOKEN_CMD`) allowed to manage certificate stores and certificates, delete
  stores and certificates, and read job history and orchestrators.
- Your kube context may create/delete namespaces, secrets, CSRs, ClusterRoles and ClusterRoleBindings, mint service
  account tokens, and impersonate service accounts (`auth can-i --as`). The cluster must run the
  `kubernetes.io/kube-apiserver-client` CSR signer (any normal cluster does).

## Configuration

All environment-specific settings are in [`lab-env.sh`](lab-env.sh), read from environment variables. Nothing has a
default that is secret or lab-specific. A missing variable stops the run with a message naming it (exit 2).

| Variable | Required for | Meaning |
|---|---|---|
| `E2E_KUBE_CONTEXT` | everything | kubectl context of the cluster the stores live in (and the UO runs in) |
| `E2E_COMMAND_URL` | Command phases | Command API base URL including the API path, e.g. `https://command.example.com/KeyfactorAPI` |
| `E2E_TOKEN_CMD` | Command phases | command line that prints a Command bearer token on stdout, e.g. `kfclab token -f "$E2E_KFCLAB_SPEC"` |
| `E2E_UO_NAME` | Command phases | the UO's name as known to kfclab |
| `E2E_KFCLAB_SPEC` | `--stage` | kfclab lab spec; **copied** into the work dir (mode 600), never modified |
| `E2E_EXT_BUILD_PATH` | `--stage` | directory or `.zip` with the extension build under test |
| `E2E_UO_AGENT` | optional | the UO's orchestrator name in Command (default `kfclab-uo-<E2E_UO_NAME>`) |
| `E2E_KUBECONFIG` | optional | kubeconfig file (default: kubectl's default) |
| `E2E_CA_CERT` | optional | PEM CA bundle for the Command endpoint (default: system trust) |
| `E2E_UO_LOG_CMD` | optional | command that prints the UO log; enables case K108 (otherwise it is SKIPped) |
| `E2E_EXT_NAME` | optional | extension name in the spec (default `k8s-orchestrator`) |
| `E2E_RBAC_API_SERVER` | optional | API server URL **as seen from the UO pod** (default `https://kubernetes.default.svc:443`) |
| `E2E_JOB_TIMEOUT` / `E2E_JOB_POLL` | optional | seconds to wait per job (300) / poll interval (5) |
| `E2E_STRICT_XPASS` | optional | `true`: a known-issue case that unexpectedly passes fails the run |
| `E2E_ENV_FILE` | optional | a shell file sourced first; keep it out of git |

Example (placeholders; put real values in a file outside the repo and point `E2E_ENV_FILE` at it):

```bash
export E2E_KUBE_CONTEXT=my-lab
export E2E_COMMAND_URL=https://command.example.com/KeyfactorAPI
export E2E_TOKEN_CMD='kfclab token -f "$E2E_KFCLAB_SPEC"'
export E2E_UO_NAME=my-uo
export E2E_KFCLAB_SPEC=$HOME/labs/kfclab.yaml
export E2E_EXT_BUILD_PATH=$HOME/src/k8s-orchestrator/kubernetes-orchestrator-extension/bin/Release/net10.0
export E2E_CA_CERT=$HOME/labs/lab-ca.crt
```

To run against a lab that stages extensions differently, replace the `lab_ext_*` functions in `lab-env.sh`;
`stage-extension.sh` only calls those.

## Usage

```bash
scripts/e2e/run-all.sh --dry-run --prefix e2e-pr103      # read what it would do first
scripts/e2e/run-all.sh --stage --prefix e2e-pr103        # stage the build, run everything, clean up, restore
scripts/e2e/run-all.sh --stage --baseline --prefix e2e-pr103   # plus the previous-build comparison
```

Common options (all phase scripts): `--prefix NAME`, `--dry-run`, `--workdir DIR`, `--only ID[,ID...]`, `--help`.
`--only` takes case IDs or globs (`D11` also selects `D11a`, `D11b`; `I*` selects every inventory case). Management
cases form a dependent sequence, so `--only` there filters the report, not what runs.

`run-all.sh` extras: `--stage` (stage the build under test first, restore at the end), `--baseline` (implies
`--stage`; after the main cases restores the previous build and runs `baseline.sh`), `--keep` (skip cleanup).
Cleanup runs even when a phase fails.

Phases (each can be run on its own, in this order):

| Script | Cases | What it does |
|---|---|---|
| `stage-extension.sh stage\|restore\|status` | - | put the build under test on the UO / put the previous one back (restarts the UO pod) |
| `fixtures.sh` | - | test PKI, namespaces, secrets, one issued CSR. Idempotent. Needs only `E2E_KUBE_CONTEXT` |
| `discovery.sh` | D1-D16 | one Command discovery job per case, compared with the expected store set |
| `inventory.sh` | I1-I13 | approve discovered stores (plus two hand-made ones), run inventory, compare alias / key flag / thumbprints |
| `management.sh` | M1-M24, K105-K108 | import certs into Command, create stores with CreateIfMissing, drive Add/Remove in waves, verify with kubectl/openssl/keytool |
| `rbac.sh` | D17-D19 | scoped service account that cannot list secrets in the ignored namespace |
| `baseline.sh` | B1-B5 | re-run key cases against the previous build and report whether the old behaviour reproduces |
| `cleanup.sh` | - | restore the extension if needed, delete everything carrying the prefix, verify, remove the work dir |

`discovery.sh` must precede `inventory.sh` (it approves what discovery found), and `baseline.sh` needs
`inventory.sh` to have created its stores. `management.sh` refuses to start when `<prefix>-m` already holds secrets
(run `cleanup.sh` then `fixtures.sh`, or use a new prefix).

## Output and exit status

One line per case: `PASS|FAIL|XFAIL|XPASS|SKIP|REPRO|NOREPRO  <ID>  <description>`; anything but PASS also prints
`expected:` and `actual:`.

| Status | Meaning | Fails the run? |
|---|---|---|
| PASS / FAIL | case behaved / did not behave as the plan says | FAIL: yes (exit 1) |
| XFAIL | known issue (`K...` cases, tagged with the GitHub issue) still present, as expected | no |
| XPASS | a known-issue case now passes: the issue looks fixed. Printed loudly; remove the tag | only with `E2E_STRICT_XPASS=true` |
| SKIP | cannot run here (reason printed), e.g. K8SCluster has no Discovery capability | no |
| REPRO / NOREPRO | baseline only: the old build did / did not show the old bug | NOREPRO only with `--require-repro` |

Exit codes: `0` ok, `1` at least one unexpected FAIL (or cleanup could not verify), `2` configuration or hard error.
`run-all.sh` prints a per-case table and totals before it cleans up.

## Known limits

- Case IDs come from the plan; sub-IDs (`D11a`, `M8b`, ...) split one plan row into separately reported checks.
- Waiting is by polling Command's job history for a job on the same client machine and store path that is newer than
  the batch start. A job the UO never picks up reports a timeout, which fails the case.
- `K108` needs `E2E_UO_LOG_CMD`; the log line layout it parses is described in the plan.
- The scripts were derived from an earlier manual run and then verified statically and with canned data only; see the
  "Open questions" section of the plan for assumptions to confirm on the first real run.

## Static checks

```bash
for f in scripts/e2e/*.sh; do bash -n "$f"; done
shellcheck -x scripts/e2e/*.sh
scripts/e2e/run-all.sh --dry-run --baseline --prefix e2e-check   # with obviously fake E2E_* values
```
