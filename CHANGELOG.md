# 2.0.0

## Breaking Changes
- refactor(jobs): Monolithic job classes replaced with store-type-specific classes. Each store type (`K8SCert`, `K8SCluster`, `K8SJKS`, `K8SNS`, `K8SPKCS12`, `K8SSecret`, `K8STLSSecr`) now has dedicated `Inventory`, `Management`, and `Discovery` job classes under `Jobs/StoreTypes/<StoreType>/`. The `manifest.json` has been updated accordingly. Any external references to job class namespaces must be updated.
- refactor(jobs): Dead properties removed from `JobBase`: `KubeHost`, `KubeCluster`, `SkipTlsValidation`, `OperationType`, `Overwrite`, `KeyEntry`, `ManagementConfig`, `DiscoveryConfig`, `InventoryConfig`. Any code referencing these properties must be updated.
- refactor(client): Monolithic `KubeClient` split into focused components (`KubeClient`, `SecretOperations`, `CertificateOperations`, `KubeconfigParser`). Direct instantiation of the old client is no longer supported.
- refactor(handlers): Secret operation logic extracted into a handler strategy pattern (`ISecretHandler`, `SecretHandlerFactory`). Store-type-specific logic no longer lives in job base classes.
- refactor(services): Business logic extracted from `JobBase` into dedicated service classes (`StoreConfigurationParser`, `PasswordResolver`, `CertificateChainExtractor`, `JobCertificateParser`, `StorePathResolver`).
- refactor(keystores): `KeystoreManager` class removed. JKS and PKCS12 operations are now handled by `JksSecretHandler` and `Pkcs12SecretHandler` respectively.
- chore(crypto): Remove all usage of `System.Security.Cryptography.X509Certificate2` for certificate store operations. All cryptographic operations now use BouncyCastle exclusively.

## Features
- feat(compat): Add `.NET 10` target — extension now ships builds for both `net8.0` and `net10.0`, supporting Keyfactor Command 24.x (net8.0) and 25.x+ (net10.0).
- feat(terraform): Add reusable Terraform modules for all 7 store types to support dev/test cluster provisioning.
- feat(security): Kubernetes secret replace operations now propagate `resourceVersion` to prevent lost-update races under concurrent writes.
- feat(validation): `StorePathResolver` emits a warning log when namespace or secret name components do not conform to Kubernetes DNS subdomain rules, preserving backwards compatibility while surfacing misconfiguration.
- feat(logging): Add `LoggingUtilities` with safe redaction helpers for passwords, private keys, certificates, kubeconfigs, and tokens — sensitive values are never written to logs.

## Bug Fixes
- fix(inventory): Null reference when secret not found now throws `StoreNotFoundException` instead of propagating as an unhandled null dereference.
- fix(client): `ReadBuddyPass` throws `StoreNotFoundException` on missing password secret rather than returning null.
- fix(chain): `SeparateChain=true` is silently overridden to `false` when `IncludeCertChain=false` — there is no chain to separate.

## Chores
- chore(tests): Add `CachedCertificateProvider` for thread-safe certificate reuse across tests, reducing test suite runtime significantly.
- chore(docs): Add `docs/ARCHITECTURE.md` documenting layer architecture, data flow, design patterns, and authentication model.
- chore(docs): Update compatibility section to include Command 24.x and 25.x and net8.0/net10.0 build matrix.

# 1.3.0

## Features
- feat(storetypes): `K8SCert` supports inventory of all signed K8S cluster CSRs.
- feat(crypto): Replace `X509Certificate2` with BouncyCastle for all cryptographic operations, improving cross-platform compatibility.
- feat(crypto): Add `CertificateUtilities` class with comprehensive certificate parsing, key extraction, and format detection.
- feat(crypto): Support for all key types: `RSA (1024-8192 bit), ECDSA (P-256, P-384, P-521), DSA (1024, 2048 bit), Ed25519, Ed448`.

## Bug Fixes
- fix(client): Fix null reference issues in kubeconfig parsing when optional fields are missing.
- fix(inventory): Initialize logger before all other operations to ensure proper error reporting.
- fix(management): Fix alias parsing for `K8SNS` and `K8SCluster` store-types when alias contains multiple path segments.
- fix(management): Add `IncludeCertChain` at base job level, and include in management jobs.
- fix(management): `K8SPKCS12` and `K8SJKS` respect `IncludeCertChain` flag.
- fix(management): "Create if missing" jobs (`CertStoreOperationType.Create`) no longer fail with "Unknown operation type: Create". `Create` is now routed identically to `Add`.
- fix(management): `K8SJKS` and `K8SPKCS12` `CreateEmptyStore` now uses the buddy-secret password when one is configured, instead of always using an empty password.
- fix(management): `K8SJKS` and `K8SPKCS12` alias routing now correctly interprets the `<fieldName>/<certAlias>` format. Previously, `HandleAdd` and `HandleRemove` always wrote to the first existing field in the secret and passed the full alias string (e.g. `mystore.jks/default`) to the keystore serializer; now the field name selects the target K8S secret field and only the short cert alias is used inside the JKS/PKCS12 file.

## Chores:
- chore(tests): Add comprehensive unit test suite covering all store types and cryptographic operations.
- chore(tests): Add integration test suite validating end-to-end operations against live Kubernetes clusters.
- chore(tests): Add alias routing regression tests (`AliasRoutingRegressionTests`) with 8 unit tests covering JKS and PKCS12 field-selection and certAlias correctness.
- chore(tests): Add 4 integration tests each to `K8SJKSStoreIntegrationTests` and `K8SPKCS12StoreIntegrationTests` validating end-to-end `<fieldName>/<certAlias>` alias routing (field written to, cert alias inside keystore, inventory alias format, and remove from named field).
- chore(tests): Add unit tests for all three constructors of `JkSisPkcs12Exception`, `InvalidK8SSecretException`, and `StoreNotFoundException` (previously at 0% line coverage).
- chore(tests): Add 10 unit tests for `CertificateChainExtractor` covering null/empty inputs, DER fallback, invalid data, and `ca.crt` chain handling (coverage: 75% → 98.9%).
- chore(tests): Add 26 no-network unit tests for `CertificateSecretHandler`, `ClusterSecretHandler`, and `NamespaceSecretHandler` covering property assertions, `NotSupportedException` throws, and alias-parsing `ArgumentException` paths (coverage: ~69–78% → ~82–89%).
- chore(ci): Add GitHub Actions workflows for unit tests, integration tests, code quality, and security scanning.
- chore(ci): Add CodeQL, dependency review, SBOM generation, and license compliance workflows.
- chore(ci): Add PR quality gate with semantic versioning validation and auto-labeling.
- chore(docs): Document supported key types for all store types.
- chore(util): Add verbose logging to PAM credential resolver.
- chore(refactor): Remove dead code from `JobBase` — unused static arrays, dead properties, unused `WarningJob()`, `HasPrivateKey()`, and `CertChainSeparator`.
- chore(refactor): Remove unreachable branches from `KubeClient.GetKubeClient()` — the `else if (k8SConfiguration == null)` and file-path fallback branches were provably dead because `KubeconfigParser.Parse()` always throws on failure rather than returning null. Cyclomatic complexity reduced from 14 to 6, CRAP score from 137 to 26.8.
- chore(refactor): Simplify JKS serializer `CreateOrUpdateJks` — extract `LoadExistingJksStore()`, `LoadNewCertificate()`, `SaveJksStore()`, `PasswordToChars()` helpers. CRAP score reduced from 60 to 16.
- chore(refactor): Simplify PKCS12 serializer `CreateOrUpdatePkcs12` — same helper extraction pattern. CRAP score reduced from 36 to 16.
- chore(refactor): Simplify `GetStorePath()` in `JobBase` — extract `DeriveSecretType()` and `NormalizeSecretTypeForPath()` helpers, make method private.

# 1.2.2

## Bug Fixes
- fix(storetypes): `K8SJKS` and `K8SPKCS12` storetypes using a separate `k8s` secret for store password does not crash
on missing or invalid secret field name. 
- fix(storetypes): `K8SJKS` where JKS files created using Keytool v20+ will be recognized as JKS files.
- fix(storetypes): `K8SJKS` and `K8SPKCS12` store/buddy passwords ending with a `\n` character will be trimmed to not include the newline.
- fix(storetypes): All store-types now support `IncludeCertChain` parameter. This defaults to `true`.
- fix(storetypes): `K8STLSSECR` and `K8SSecret` support `SeparateChain` property. This defaults to `false`.

## Chores:
- chore(docs): Update documentation format
- chore(deps): Bump `BouncyCastle.Cryptography` to `v2.6.2`. 

# 1.2.1

## Bug Fixes
- fix(management): `K8SNS` management jobs handle `storepath` parsed length is less than expected.

# 1.2.0

## Features
- feat(client): Retry interrupted connections to k8s cluster. 

# 1.1.3

## Bug Fixes
- fix(client): Provide useful error message when credentials are empty and/or invalid format.
- fix(base): Prevent uninitialized client reference in `JobBase`.

## Chores:
- chore(deps): Bump `Keyfactor.Logging` to `v1.1.2`.
- chore(deps): Bump `Keyfactor.PKI` to `v5.5.0`.

# 1.1.2

## Bug Fixes
- fix(management): Management jobs for `K8STLSSecret` and `K8SSecret` types handle ECC keys.
- fix(manifest): Update store-type definitions to include params `IncludeCertChain` and `SeparateChain`
- fix(docs): Update screenshots for `K8SCluster` and `K8SNS` store types custom fields.
- fix(client): Handle skip TLS flag when passed to a job.

# 1.1.1

## Features
- feat(storetypes): `K8SPKCS12` store type added to support PKCS12, .P12, PFX, files in K8S `opaque` secrets.
- feat(storetypes): `K8SJKS` store type added to support JKS files in K8S `opaque` secrets.
- feat(storetypes): `K8SCLUSTER` store type added to support PEM files in K8S `opaque` and `tls` secrets for an entire cluster as a single store.
- feat(storetypes): `K8SNS` store type added to support PEM files in K8S `opaque` and `tls` secrets for a single namespace as a single store.
- feat(discovery): Support added for: `K8SNS`, `K8SPKCS12`, `K8SJKS` store types.
- feat(management): Support added for:,`K8SCLUSTER`, `K8SNS`, `K8SPKCS12`, `K8SJKS` store types.
- feat(inventory): Support added for: `K8SCLUSTER`, `K8SNS`, `K8SPKCS12`, `K8SJKS` store types.

# 1.0.6

## Bug Fixes
- fix(base): If unable to convert to x509Certificate2 object then just use raw bytes from job.
- fix(client): Replace remaining "private_keys" refs to "tls.key"
- fix(management): Private keys coming from Keyfactor command are not stored unencrypted in secrets.
- fix(management): Remove check for cert bytes in HandleTlsSecret
- fix(management): Condition for handling "create_store" includes check of PEM and alias.

## Other Changes
- chore(scripts): Add script to stand up Hashicorp Vault CA and create some certs then push them into K8S secrets.

# 1.0.4

## Bug Fixes
- fix(management): Opaque secrets now manage tls.crt and tls.key rather than `certificates` and `private_keys`. 
Only a single cert and key are supported.

# 1.0.3

## Bug Fixes
- fix(base): Add additional logic extracting private keys
- fix(base): Verbose logging.
- fix(client): Discovery locations now include cluster name.
- fix(discovery): StorePath now includes cluster name from kubeconfig credentials.
- fix(management): When creating `X509Certificate2` include flag to allow export.
- fix(scripts): Fixed k8s service account scripts to default to index 0 and added notes about assumption.

## Other Changes
- chore(docs): Added docs about `StorePath`

# 1.0.2

## Bug Fixes
- fix(base): Add support for empty or null `ServerUsername` and default to `kubeconfig`
- fix(base): Throw configuration exception if `ServerPassword` is null or empty.
- fix(client): Init kf logger properly.
- fix(client): Remove will search all secret keys to check for cert rather than just managed keys.
- fix(discovery): Remove duplicate locations from results and print out discovered locations in the message.
- fix(discovery): Lists all namespaces and then checks if namespace is in the "Directories to search" parameter rather than filter by API call.
- fix(discovery): Now checks the storetype passed to determine what K8S secret type to import when checking secret keys.
- fix(inventory): Added more logging
- fix(inventory): When secret is not found on K8S inventory is assumed empty.
- fix(management): Add support for `createStore`
- fix(management): Enable use of "create store" tick box, which triggers an empty management job.
- fix(manifest): Capability names match docs
- fix(store-types): Update store types to require server and remove `KubeSvcCreds` field.


## Other Changes
- chore(docs): Removed KubeSvcCreds reference from PAM stub.

# 1.0.1

## Bug Fixes
- fix(base): Parse `KubeNamespace` and `KubeSecretName` from storepath if contains `/`
- fix(inventory): Allowing for secret key tls.crt and tls.key for `Opaque` secret types.
- fix(inventory): Returned certs list now returns list of certs.

## Other Changes
- chore(docs): Remove references to `KubeSvcCreds` field, and instead force `Needs Server` which implicitly adds fields 
for `ServerUsername` and `ServerPassword`

# 1.0.0
- Initial release


