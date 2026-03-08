# 2.0.0

## Breaking Changes
- The monolithic job classes have been replaced with a store-type-specific handler pattern. Each store type (`K8SCert`, `K8SCluster`, `K8SJKS`, `K8SNS`, `K8SPKCS12`, `K8SSecret`, `K8STLSSecr`) now has dedicated `Inventory`, `Management`, `Discovery`, and `Reenrollment` job classes in `Jobs/StoreTypes/<StoreType>/`. The `manifest.json` has been updated accordingly.
- `JobBase` dead properties removed: `KubeHost`, `KubeCluster`, `SkipTlsValidation`, `OperationType`, `Overwrite`, `KeyEntry`, `ManagementConfig`, `DiscoveryConfig`, `InventoryConfig`. Any code referencing these properties must be updated.
- `KeystoreManager` class removed. JKS and PKCS12 operations are now handled by `JksSecretHandler` and `Pkcs12SecretHandler` respectively.

## Features
- feat(terraform): Add reusable Terraform modules for all 7 store types to support dev/test cluster provisioning.

## Bug Fixes
- fix(management): Fix alias routing for `K8SJKS` and `K8SPKCS12` — `HandleAdd` and `HandleRemove` now correctly extract the field name and cert alias from `<fieldName>/<certAlias>` format instead of passing the full alias string to the keystore serializer.
- fix(management): Route `CertStoreOperationType.Create` to `HandleAdd` so "create if missing" jobs work correctly. Fix `CreateEmptyStore` to use the buddy-secret password when configured.
- fix(management): Correct buddy password path parsing in `K8SJKS` and `K8SPKCS12` handlers — `<namespace>/<secretName>` is now parsed correctly.
- fix(store-type/k8scert): Properly include certificate chain when inventorying CSRs.
- fix(client): Handle null return from `SecretOperations.GetSecret()` — throw `StoreNotFoundException` instead of null reference exception.
- fix(security): Remove password length from redacted log output to avoid leaking information.
- fix(handlers): Remove unused exception variable in `OpaqueSecretHandler` and `TlsSecretHandler` catch blocks.

## Refactoring
- refactor: Extract handler pattern — secret operations for each store type are now delegated to dedicated handler classes (`OpaqueSecretHandler`, `TlsSecretHandler`, `JksSecretHandler`, `Pkcs12SecretHandler`, `ClusterSecretHandler`, `NamespaceSecretHandler`, `CertificateSecretHandler`) via `SecretHandlerFactory`.
- refactor: Extract `CertificateChainExtractor`, `StoreConfigurationParser`, `PasswordResolver`, `JobCertificateParser`, and `StorePathResolver` services from `JobBase` and `KubeClient`, reducing `JobBase` by ~1000 lines.
- refactor: Extract `SecretOperations` and `CertificateOperations` from `KubeClient` — Kubernetes CRUD operations are now separated into dedicated classes.
- refactor: Extract `ParseKeystoreAlias` helper to `SecretHandlerBase`, removing ~1200 lines of duplicated alias-parsing logic.
- refactor: Lift `ValidateCertOnlyUpdate` to `SecretHandlerBase` — cert-only update validation is now shared across TLS and Opaque handlers.
- refactor: Simplify `JksSecretHandler` and `Pkcs12SecretHandler` `CreateOrUpdate` methods by extracting `LoadExistingStore`, `LoadNewCertificate`, `SaveStore`, and `PasswordToChars` helpers.
- refactor: Convert all log string concatenation to structured logging throughout `JobBase` and `KubeClient`.
- refactor: Replace hardcoded polling delays in `K8SCert` integration tests with proper condition polling.
- refactor: Remove dead `X509Certificate2Collection` methods and `GetKeyBytes(X509Certificate2)`.

## Tests
- test: Add comprehensive unit test suite — `StoreConfigurationParser`, `LoggingUtilities`, `StoreNotFoundException`, `CertificateUtilities`, `KubeconfigParser`, `K8SJobCertificate`, `K8SCertificateContext`, `DiscoveryBase`, `PAMUtilities`, `ParseKeystoreAliasCore`, and alias routing regression tests for `K8SJKS`/`K8SPKCS12`.
- test: Add integration tests for `KubeCertificateManagerClient`, multi-alias and buddy password scenarios for `K8SJKS` and `K8SPKCS12`.
- test: Add `CachedCertificateProvider` to eliminate redundant certificate generation across test runs, significantly reducing test suite execution time.

## Chores
- chore(ci): Migrate to Keyfactor Actions v6.
- chore(ci): Configure signoff notifications via starter workflow.

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
- fix(management): `K8SJKS` and `K8SPKCS12` alias routing now correctly interprets the `<fieldName>/<certAlias>` alias format. Previously, `HandleAdd` and `HandleRemove` always wrote to the first existing field in the secret and passed the full alias string (e.g. `mystore.jks/default`) to the keystore serializer; now the field name selects the target K8S secret field and only the short cert alias is used inside the JKS/PKCS12 file.

## Chores:
- chore(tests): Add comprehensive unit test suite covering all store types and cryptographic operations.
- chore(tests): Add integration test suite validating end-to-end operations against live Kubernetes clusters.
- chore(tests): Add alias routing regression tests (`AliasRoutingRegressionTests`) with 8 unit tests covering JKS and PKCS12 field-selection and certAlias correctness.
- chore(tests): Add 4 integration tests each to `K8SJKSStoreIntegrationTests` and `K8SPKCS12StoreIntegrationTests` validating end-to-end `<fieldName>/<certAlias>` alias routing (field written to, cert alias inside keystore, inventory alias format, and remove from named field).
- chore(ci): Add GitHub Actions workflows for unit tests, integration tests, code quality, and security scanning.
- chore(ci): Add CodeQL, dependency review, SBOM generation, and license compliance workflows.
- chore(ci): Add PR quality gate with semantic versioning validation and auto-labeling.
- chore(docs): Document supported key types for all store types.
- chore(util): Add verbose logging to PAM credential resolver.
- chore(refactor): Remove dead code from `JobBase` — unused static arrays, dead properties (`KubeHost`, `KubeCluster`, `SkipTlsValidation`, `OperationType`, `Overwrite`, `KeyEntry`, `ManagementConfig`, `DiscoveryConfig`, `InventoryConfig`), unused `WarningJob()`, `HasPrivateKey()`, and `CertChainSeparator`.
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


