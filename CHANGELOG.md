# 1.1.0

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

