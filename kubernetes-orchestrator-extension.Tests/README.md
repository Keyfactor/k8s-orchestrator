# Kubernetes Orchestrator Extension Tests

This document provides an overview of all test cases for the Keyfactor Kubernetes Universal Orchestrator Extension, organized by store type.

## Test Categories

The test suite is divided into two main categories:

- **Unit Tests** - Tests that run without external dependencies, validating serialization, data structures, and certificate handling logic
- **Integration Tests** - Tests that require a real Kubernetes cluster, validating end-to-end orchestrator operations

## Running Tests

### Unit Tests Only
```bash
make test-unit
# or
dotnet test --filter "Category!=Integration"
```

### Integration Tests
Integration tests require:
- `RUN_INTEGRATION_TESTS=true` environment variable
- Access to a Kubernetes cluster via `~/.kube/config` (or `INTEGRATION_TEST_KUBECONFIG`)
- Cluster permissions to create/delete namespaces and secrets

```bash
make test-integration
# or store-type specific:
make test-store-jks
make test-store-pkcs12
make test-store-secret
make test-store-tls
make test-store-cluster
make test-store-ns
make test-store-cert
make test-kubeclient
```

### All Tests
```bash
make testall
```

---

## K8SJKS - Java Keystore Store Type

Manages JKS (Java KeyStore) files stored as base64 in Kubernetes Opaque secrets.

### Unit Tests (`K8SJKSStoreTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Basic Deserialization** | |
| `DeserializeRemoteCertificateStore_ValidJksWithPassword_ReturnsStore` | Valid JKS with correct password loads successfully |
| `DeserializeRemoteCertificateStore_EmptyPassword_ThrowsArgumentException` | Empty password throws ArgumentException |
| `DeserializeRemoteCertificateStore_NullPassword_ThrowsArgumentException` | Null password throws ArgumentException |
| `DeserializeRemoteCertificateStore_WrongPassword_ThrowsException` | Wrong password throws IOException |
| `DeserializeRemoteCertificateStore_CorruptedData_ThrowsException` | Corrupted data throws exception |
| `DeserializeRemoteCertificateStore_NullData_ThrowsException` | Null data throws exception |
| `DeserializeRemoteCertificateStore_EmptyData_ThrowsException` | Empty data throws exception |
| **Key Type Coverage** | |
| `DeserializeRemoteCertificateStore_RsaKeys_SuccessfullyLoadsStore` | RSA keys (1024, 2048, 4096, 8192) load correctly |
| `DeserializeRemoteCertificateStore_EcKeys_SuccessfullyLoadsStore` | EC keys (P-256, P-384, P-521) load correctly |
| `DeserializeRemoteCertificateStore_DsaKeys_SuccessfullyLoadsStore` | DSA keys (1024, 2048) load correctly |
| `DeserializeRemoteCertificateStore_EdwardsKeys_SuccessfullyLoadsStore` | Edwards curve keys (Ed25519, Ed448) load correctly |
| **Password Scenarios** | |
| `DeserializeRemoteCertificateStore_VariousPasswords_SuccessfullyLoadsStore` | Various passwords (special chars, Unicode, emoji, spaces) work |
| `DeserializeRemoteCertificateStore_PasswordWithNewline_HandlesCorrectly` | Passwords with trailing newlines are handled |
| `DeserializeRemoteCertificateStore_VeryLongPassword_SuccessfullyLoadsStore` | Very long passwords (1000+ chars) work |
| **Certificate Chain** | |
| `DeserializeRemoteCertificateStore_CertificateWithChain_LoadsAllCertificates` | Certificate chains (leaf + intermediate + root) load correctly |
| `DeserializeRemoteCertificateStore_SingleCertificate_LoadsWithoutChain` | Single certificates load without chain |
| **Multiple Aliases** | |
| `DeserializeRemoteCertificateStore_MultipleAliases_LoadsAllCertificates` | Multiple certificate entries load with correct aliases |
| **Serialization** | |
| `SerializeRemoteCertificateStore_ValidStore_ReturnsSerializedData` | Valid store serializes correctly |
| `SerializeRemoteCertificateStore_RoundTrip_PreservesData` | Serialize/deserialize round-trip preserves data |
| `SerializeRemoteCertificateStore_EmptyStore_ReturnsValidOutput` | Empty store serializes without error |
| `SerializeRemoteCertificateStore_DifferentPassword_SuccessfullySerializes` | Re-serializing with different password works |
| **Edge Cases** | |
| `GetPrivateKeyPath_ReturnsNull` | Private key path returns null (inline keys) |
| `DeserializeRemoteCertificateStore_PartiallyCorruptedData_ThrowsException` | Partially corrupted data throws exception |

### Integration Tests (`K8SJKSStoreIntegrationTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Inventory** | |
| `Inventory_EmptyJksSecret_ReturnsEmptyList` | Inventory on JKS secret returns success |
| `Inventory_JksSecretWithMultipleCerts_ReturnsAllCertificates` | Inventory returns all certificates in JKS |
| `Inventory_NonExistentSecret_ReturnsFailure` | Non-existent secret returns failure |
| **Management Add** | |
| `Management_AddCertificateToNewSecret_CreatesSecretWithCertificate` | Add creates new secret with certificate |
| `Management_AddCertificateToExistingSecret_UpdatesSecret` | Add to existing secret appends certificate |
| **Management Remove** | |
| `Management_RemoveCertificateFromSecret_RemovesCertificate` | Remove deletes certificate by alias |
| **Discovery** | |
| `Discovery_FindsJksSecretsInNamespace` | Discovery finds JKS secrets |
| **Error Handling** | |
| `Management_AddWithWrongPassword_ReturnsFailure` | Wrong password returns failure |

---

## K8SPKCS12 - PKCS12/PFX Store Type

Manages PKCS12 (.p12, .pfx) files stored as base64 in Kubernetes Opaque secrets.

### Unit Tests (`K8SPKCS12StoreTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Basic Deserialization** | |
| `DeserializeRemoteCertificateStore_ValidPkcs12WithPassword_ReturnsStore` | Valid PKCS12 with password loads successfully |
| `DeserializeRemoteCertificateStore_EmptyPassword_SuccessfullyLoadsStore` | PKCS12 with empty password loads (differs from JKS) |
| `DeserializeRemoteCertificateStore_NullPassword_SuccessfullyLoadsStore` | PKCS12 with null password loads |
| `DeserializeRemoteCertificateStore_WrongPassword_ThrowsException` | Wrong password throws IOException |
| `DeserializeRemoteCertificateStore_CorruptedData_ThrowsException` | Corrupted data throws exception |
| `DeserializeRemoteCertificateStore_NullData_ThrowsException` | Null data throws exception |
| `DeserializeRemoteCertificateStore_EmptyData_ThrowsException` | Empty data throws exception |
| **Key Type Coverage** | |
| `DeserializeRemoteCertificateStore_RsaKeys_SuccessfullyLoadsStore` | RSA keys (1024, 2048, 4096, 8192) load correctly |
| `DeserializeRemoteCertificateStore_EcKeys_SuccessfullyLoadsStore` | EC keys (P-256, P-384, P-521) load correctly |
| `DeserializeRemoteCertificateStore_DsaKeys_SuccessfullyLoadsStore` | DSA keys (1024, 2048) load correctly |
| `DeserializeRemoteCertificateStore_EdwardsKeys_SuccessfullyLoadsStore` | Edwards curve keys (Ed25519, Ed448) load correctly |
| **Password Scenarios** | |
| `DeserializeRemoteCertificateStore_VariousPasswords_SuccessfullyLoadsStore` | Various passwords (special chars, Unicode, emoji, spaces) work |
| `DeserializeRemoteCertificateStore_VeryLongPassword_SuccessfullyLoadsStore` | Very long passwords work |
| **Certificate Chain** | |
| `DeserializeRemoteCertificateStore_CertificateWithChain_LoadsAllCertificates` | Certificate chains load correctly |
| `DeserializeRemoteCertificateStore_SingleCertificate_LoadsWithoutChain` | Single certificates load without chain |
| **Multiple Aliases** | |
| `DeserializeRemoteCertificateStore_MultipleAliases_LoadsAllCertificates` | Multiple certificate entries load correctly |
| **Serialization** | |
| `SerializeRemoteCertificateStore_ValidStore_ReturnsSerializedData` | Valid store serializes correctly |
| `SerializeRemoteCertificateStore_RoundTrip_PreservesData` | Round-trip preserves data |
| `SerializeRemoteCertificateStore_EmptyStore_ReturnsValidOutput` | Empty store serializes |
| `SerializeRemoteCertificateStore_DifferentPassword_SuccessfullySerializes` | Re-serializing with different password works |
| **Edge Cases** | |
| `GetPrivateKeyPath_ReturnsNull` | Private key path returns null (inline keys) |
| `DeserializeRemoteCertificateStore_PartiallyCorruptedData_ThrowsException` | Partially corrupted data throws exception |
| `DeserializeRemoteCertificateStore_CertificateOnlyEntry_SuccessfullyLoadsStore` | Certificate-only entries (no private key) load |

### Integration Tests (`K8SPKCS12StoreIntegrationTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Inventory** | |
| `Inventory_EmptyPkcs12Secret_ReturnsEmptyList` | Inventory on PKCS12 secret returns success |
| `Inventory_Pkcs12SecretWithMultipleCerts_ReturnsAllCertificates` | Inventory returns all certificates |
| `Inventory_NonExistentSecret_ReturnsFailure` | Non-existent secret returns failure |
| **Management Add** | |
| `Management_AddCertificateToNewSecret_CreatesSecretWithCertificate` | Add creates new secret |
| `Management_AddCertificateToExistingSecret_UpdatesSecret` | Add to existing secret appends |
| **Management Remove** | |
| `Management_RemoveCertificateFromSecret_RemovesCertificate` | Remove deletes certificate by alias |
| **Discovery** | |
| `Discovery_FindsPkcs12SecretsInNamespace` | Discovery finds PKCS12 secrets |
| **Error Handling** | |
| `Management_AddWithWrongPassword_ReturnsFailure` | Wrong password returns failure |

---

## K8SSecret - Opaque Secret Store Type

Manages Kubernetes Opaque secrets with PEM-formatted certificates and keys.

### Unit Tests (`K8SSecretStoreTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **PEM Certificate Parsing** | |
| `PemCertificate_ValidFormat_CanBeParsed` | Valid PEM certificate can be parsed |
| `PemPrivateKey_ValidFormat_CanBeParsed` | Valid PEM private key can be parsed |
| `PemCertificate_VariousKeyTypes_ValidFormat` | All key types (RSA, EC, DSA, Ed25519, Ed448) produce valid PEM |
| **K8S Secret Structure** | |
| `OpaqueSecret_WithPemCertAndKey_HasCorrectStructure` | Opaque secret has correct structure |
| `OpaqueSecret_WithCertificateChain_CanStoreSeparateCaField` | Certificate chain can use separate ca.crt field |
| `OpaqueSecret_FlexibleFieldNames_SupportedVariations` | Flexible field names (tls.crt, cert, certificate, crt) supported |
| **Certificate Chain** | |
| `CertificateChain_ConcatenatedInSingleField_ValidFormat` | Concatenated chain in single field is valid |
| `CertificateChain_SingleCertificate_NoChainField` | Single certificate has no ca.crt field |
| `OpaqueSecret_WithBundledChain_AllCertsInTlsCrt` | Bundled chain puts all certs in tls.crt |
| `OpaqueSecret_SeparateChainVsBundled_DifferentStructures` | Separate vs bundled chain produces different structures |
| **DER to PEM Conversion** | |
| `DerCertificate_ConvertedToPem_ValidFormat` | DER to PEM conversion works |
| **Encoding** | |
| `PemCertificate_Utf8Encoding_RoundTripSuccessful` | UTF-8 encoding round-trip works |
| `PemData_StoredAsBytes_CorrectlyDecoded` | PEM stored as bytes decodes correctly |
| **Edge Cases** | |
| `OpaqueSecret_EmptyData_ValidStructure` | Empty data is valid structure |
| `OpaqueSecret_OnlyCertificateNoKey_ValidStructure` | Certificate without key is valid |
| `PemCertificate_WithWhitespace_StillValid` | PEM with extra whitespace is valid |
| **Metadata** | |
| `OpaqueSecret_WithLabels_PreservesMetadata` | Labels and metadata are preserved |

### Integration Tests (`K8SSecretStoreIntegrationTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Inventory** | |
| `Inventory_OpaqueSecretWithCertificate_ReturnsSuccess` | Inventory on Opaque secret succeeds |
| `Inventory_OpaqueSecretWithChain_ReturnsSuccess` | Inventory with chain succeeds |
| `Inventory_CertificateOnlySecret_ReturnsSuccess` | Certificate-only secret succeeds |
| `Inventory_NonExistentSecret_ReturnsFailure` | Non-existent secret handled gracefully |
| **Management** | |
| `Management_AddCertificateToNewSecret_ReturnsSuccess` | Add creates new Opaque secret |
| `Management_RemoveCertificateFromSecret_ReturnsSuccess` | Remove certificate succeeds |
| `Management_AddCertificateWithChainBundled_CreatesBundledSecret` | Add with SeparateChain=false bundles chain |
| `Management_AddCertificateWithChainSeparate_CreatesSeparateChainSecret` | Add with SeparateChain=true creates ca.crt |
| **Discovery** | |
| `Discovery_FindsOpaqueSecrets_ReturnsSuccess` | Discovery finds Opaque secrets |
| **Certificate Without Private Key** | |
| `Management_AddCertificateWithoutPrivateKey_DerFormat_ReturnsSuccess` | DER cert-only to new secret succeeds |
| `Management_AddCertificateWithoutPrivateKey_PemFormat_ReturnsSuccess` | PEM cert-only to new secret succeeds |
| `Inventory_OpaqueSecretWithCertificateOnly_ReturnsSuccess` | Inventory cert-only secret succeeds |
| `Management_UpdateExistingSecretWithCertificateOnly_FailsWhenExistingKeyPresent` | Cert-only update to secret with key fails (prevents mismatched key) |
| **Key Type Coverage** | |
| `Management_Rsa2048Certificate_AddAndInventory_Success` | RSA 2048 add and inventory |
| `Management_Rsa4096Certificate_AddAndInventory_Success` | RSA 4096 add and inventory |
| `Management_EcP256Certificate_AddAndInventory_Success` | EC P-256 add and inventory |
| `Management_EcP384Certificate_AddAndInventory_Success` | EC P-384 add and inventory |
| `Management_EcP521Certificate_AddAndInventory_Success` | EC P-521 add and inventory |
| `Management_Ed25519Certificate_AddAndInventory_Success` | Ed25519 add and inventory |

---

## K8STLSSecr - TLS Secret Store Type

Manages Kubernetes `kubernetes.io/tls` secrets with strict field names (tls.crt, tls.key, ca.crt).

### Unit Tests (`K8STLSSecrStoreTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **PEM Certificate Parsing** | |
| `PemCertificate_ValidFormat_CanBeParsed` | Valid PEM certificate can be parsed |
| `PemPrivateKey_ValidFormat_CanBeParsed` | Valid PEM private key can be parsed |
| `PemCertificate_VariousKeyTypes_ValidFormat` | All key types produce valid PEM |
| **K8S TLS Secret Structure** | |
| `TlsSecret_WithCertAndKey_HasCorrectStructure` | TLS secret has correct structure |
| `TlsSecret_WithCertificateChain_CanStoreSeparateCaField` | Certificate chain uses ca.crt |
| `TlsSecret_StrictFieldNames_OnlyTlsCrtAndTlsKey` | Only tls.crt and tls.key allowed (strict) |
| `TlsSecret_Type_MustBeKubernetesIoTls` | Type must be kubernetes.io/tls |
| **Certificate Chain** | |
| `CertificateChain_ConcatenatedInSingleField_ValidFormat` | Concatenated chain is valid |
| `CertificateChain_SingleCertificate_NoChainField` | Single cert has no ca.crt |
| `TlsSecret_WithBundledChain_AllCertsInTlsCrt` | Bundled chain puts all in tls.crt |
| `TlsSecret_SeparateChainVsBundled_DifferentStructures` | Separate vs bundled produces different structures |
| **Field Validation** | |
| `TlsSecret_MissingTlsCrt_Invalid` | Missing tls.crt is invalid |
| `TlsSecret_MissingTlsKey_Invalid` | Missing tls.key is invalid |
| `TlsSecret_OptionalCaCrt_Allowed` | ca.crt is optional |
| **Edge Cases** | |
| `TlsSecret_EmptyData_ValidStructure` | Empty data is valid structure |
| `PemCertificate_WithWhitespace_StillValid` | PEM with whitespace is valid |
| **Metadata** | |
| `TlsSecret_WithLabels_PreservesMetadata` | Labels are preserved |
| `TlsSecret_NativeKubernetesFormat_Compatible` | Compatible with native K8S TLS secrets |

### Integration Tests (`K8STLSSecrStoreIntegrationTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Inventory** | |
| `Inventory_TlsSecretWithCertificate_ReturnsSuccess` | Inventory on TLS secret succeeds |
| `Inventory_TlsSecretWithChain_ReturnsSuccess` | Inventory with chain succeeds |
| `Inventory_EcCertificate_ReturnsSuccess` | EC certificate inventory succeeds |
| `Inventory_NonExistentTlsSecret_ReturnsFailure` | Non-existent secret handled gracefully |
| **Management** | |
| `Management_AddCertificateToNewTlsSecret_ReturnsSuccess` | Add creates new TLS secret |
| `Management_RemoveCertificateFromTlsSecret_ReturnsSuccess` | Remove certificate succeeds |
| `Management_AddCertificateWithChainBundled_CreatesBundledTlsCrt` | SeparateChain=false bundles chain |
| `Management_AddCertificateWithChainSeparate_CreatesSeparateCaCrt` | SeparateChain=true creates ca.crt |
| **Discovery** | |
| `Discovery_FindsTlsSecrets_ReturnsSuccess` | Discovery finds TLS secrets |
| **Native Kubernetes Compatibility** | |
| `TlsSecret_CompatibleWithK8sIngress_CorrectFormat` | TLS secrets are Ingress-compatible |
| **Certificate Without Private Key** | |
| `Management_AddCertificateWithoutPrivateKey_DerFormat_ReturnsSuccess` | DER cert-only to new TLS secret succeeds |
| `Management_AddCertificateWithoutPrivateKey_PemFormat_ReturnsSuccess` | PEM cert-only to new TLS secret succeeds |
| `Management_UpdateExistingTlsSecretWithCertificateOnly_FailsWhenExistingKeyPresent` | Cert-only update to TLS secret with key fails (prevents mismatched key) |
| **Key Type Coverage** | |
| `Management_Rsa2048Certificate_AddAndInventory_Success` | RSA 2048 add and inventory |
| `Management_Rsa4096Certificate_AddAndInventory_Success` | RSA 4096 add and inventory |
| `Management_EcP256Certificate_AddAndInventory_Success` | EC P-256 add and inventory |
| `Management_EcP384Certificate_AddAndInventory_Success` | EC P-384 add and inventory |
| `Management_EcP521Certificate_AddAndInventory_Success` | EC P-521 add and inventory |
| `Management_Ed25519Certificate_AddAndInventory_Success` | Ed25519 add and inventory |

---

## K8SCluster - Cluster-Wide Store Type

Manages ALL secrets across ALL namespaces in a Kubernetes cluster.

### Unit Tests (`K8SClusterStoreTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Cluster Scope** | |
| `ClusterStore_RepresentsAllNamespaces_NotSingleNamespace` | Store path is cluster-wide |
| `ClusterStore_CanContainMultipleSecretTypes_InDifferentNamespaces` | Multiple secret types across namespaces |
| **Secret Collection** | |
| `SecretList_MultipleNamespaces_CanBeGrouped` | Secrets grouped by namespace |
| `SecretList_FilterByType_ReturnsOnlyMatchingSecrets` | Filtering by type works |
| **Discovery** | |
| `Discovery_EmptyCluster_ReturnsEmptyList` | Empty cluster returns empty |
| `Discovery_MultipleSecrets_ReturnsAllSecrets` | Multiple secrets are discovered |
| **Namespace Filtering** | |
| `NamespaceFilter_ExcludeSystemNamespaces_FilterCorrectly` | System namespaces can be excluded |
| `NamespaceFilter_IncludeOnlySpecificNamespaces_FilterCorrectly` | Namespace inclusion filter works |
| **Certificate Data** | |
| `ClusterSecret_WithPemCertificate_CanBeRead` | PEM certificates can be read |
| `ClusterSecret_MultipleSecretsWithCertificates_CanBeEnumerated` | Multiple certificates enumerated |
| **Permissions (Conceptual)** | |
| `ClusterStore_RequiresClusterWidePermissions_NotNamespaceScoped` | Documents cluster-wide RBAC needs |
| **Edge Cases** | |
| `ClusterStore_NamespaceWithNoSecrets_ReturnsEmpty` | Empty namespace returns empty |
| `ClusterStore_LargeNumberOfSecrets_CanBeHandled` | 100+ secrets handled |
| **TLS Secret Operations via Cluster Store** | |
| `ClusterTlsSecret_WithCertAndKey_HasCorrectStructure` | TLS secret structure via cluster |
| `ClusterTlsSecret_WithCertificateChain_CanStoreSeparateCaField` | Chain with separate ca.crt field |
| `ClusterTlsSecret_StrictFieldNames_OnlyTlsCrtAndTlsKey` | TLS secrets enforce strict field names |
| `ClusterTlsSecret_Type_MustBeKubernetesIoTls` | Type validation for TLS secrets |
| `ClusterTlsSecret_WithBundledChain_AllCertsInTlsCrt` | Bundled chain in tls.crt |
| `ClusterTlsSecret_SeparateChainVsBundled_DifferentStructures` | Compare chain storage strategies |
| `ClusterTlsSecret_NativeKubernetesFormat_Compatible` | Ingress compatibility |
| `ClusterTlsSecret_MissingRequiredFields_Invalid` | Field validation |
| **Opaque Secret Operations via Cluster Store** | |
| `ClusterOpaqueSecret_WithPemCertAndKey_HasCorrectStructure` | Opaque secret structure via cluster |
| `ClusterOpaqueSecret_WithCertificateChain_CanStoreSeparateCaField` | Chain with separate ca.crt field |
| `ClusterOpaqueSecret_FlexibleFieldNames_SupportedVariations` | Flexible field names (cert, crt, certificate) |
| `ClusterOpaqueSecret_WithBundledChain_AllCertsInTlsCrt` | Bundled chain in tls.crt |
| `ClusterOpaqueSecret_SeparateChainVsBundled_DifferentStructures` | Compare chain storage strategies |
| `ClusterOpaqueSecret_OnlyCertificateNoKey_ValidStructure` | Certificate-only secrets |
| **Key Type Coverage via Cluster Store** | |
| `ClusterSecret_RsaKeyTypes_ValidPemFormat` | RSA 1024/2048/4096/8192 via cluster |
| `ClusterSecret_EcKeyTypes_ValidPemFormat` | EC P-256/P-384/P-521 via cluster |
| `ClusterSecret_EdwardsKeyTypes_ValidPemFormat` | Ed25519/Ed448 via cluster |
| **Cross-Type Cluster Operations** | |
| `ClusterStore_MixedSecretTypes_SameNamespace_CanCoexist` | TLS + Opaque in same namespace |
| `ClusterStore_SameSecretName_DifferentNamespaces_AreIndependent` | Same name, different namespaces |
| `ClusterStore_FilterTlsSecrets_ReturnsOnlyTlsType` | Filter for kubernetes.io/tls only |
| `ClusterStore_FilterOpaqueSecrets_ReturnsOnlyOpaqueType` | Filter for Opaque only |
| **Encoding and Conversion** | |
| `ClusterSecret_Utf8Encoding_RoundTripSuccessful` | UTF-8 encoding round-trip |
| `ClusterSecret_DerToPemConversion_ValidFormat` | DER to PEM conversion |
| `ClusterSecret_PemWithWhitespace_StillValid` | Whitespace handling |
| **Metadata** | |
| `ClusterSecret_WithLabels_PreservesMetadata` | Labels are preserved |
| `ClusterSecret_WithAnnotations_PreservesMetadata` | Annotations are preserved |

### Integration Tests (`K8SClusterStoreIntegrationTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Discovery** | |
| `Discovery_MultipleNamespaces_FindsAllSecrets` | Discovery across namespaces |
| `Discovery_MixedSecretTypes_FindsAllTypes` | Discovers Opaque and TLS |
| **Inventory** | |
| `Inventory_ClusterWide_ReturnsAllCertificates` | Cluster-wide inventory |
| **Management** | |
| `Management_AddCertificateToSpecificNamespace_ReturnsSuccess` | Add to specific namespace |
| `Management_RemoveCertificateFromNamespace_ReturnsSuccess` | Remove from namespace |
| **Cross-Namespace** | |
| `CrossNamespace_SecretsInDifferentNamespaces_AreIndependent` | Same-name secrets in different namespaces are independent |
| **Error Handling** | |
| `Inventory_InvalidClusterCredentials_ReturnsFailure` | Invalid credentials fail |
| **TLS Secret Operations via Cluster** | |
| `Inventory_TlsSecretInCluster_ReturnsSuccess` | Inventory TLS secret via cluster |
| `Inventory_TlsSecretWithChain_ReturnsSuccess` | Inventory TLS secret with chain |
| `Inventory_TlsSecretWithEcCert_ReturnsSuccess` | Inventory EC TLS secret |
| `Management_AddTlsSecretToCluster_ReturnsSuccess` | Add TLS secret via cluster |
| `Management_RemoveTlsSecretFromCluster_ReturnsSuccess` | Remove TLS secret via cluster |
| `Management_AddTlsSecretWithBundledChain_CreatesBundledTlsCrt` | IncludeCertChain=true, SeparateChain=false |
| `Management_AddTlsSecretWithSeparateChain_CreatesSeparateCaCrt` | IncludeCertChain=true, SeparateChain=true |
| `Management_AddTlsSecretWithoutChain_NoChainIncluded` | IncludeCertChain=false |
| `Management_OverwriteTlsSecret_UpdatesCorrectly` | Overwrite existing TLS secret |
| `TlsSecret_CreatedViaCluster_CompatibleWithIngress` | Native K8S Ingress compatibility |
| `Inventory_MultipleTlsSecretsAcrossNamespaces_ReturnsAll` | Multiple TLS secrets cluster-wide |
| **Opaque Secret Operations via Cluster** | |
| `Inventory_OpaqueSecretInCluster_ReturnsSuccess` | Inventory Opaque secret via cluster |
| `Inventory_OpaqueSecretWithChain_ReturnsSuccess` | Inventory Opaque secret with chain |
| `Inventory_OpaqueSecretCertOnly_ReturnsSuccess` | Inventory certificate-only Opaque secret |
| `Management_AddOpaqueSecretToCluster_ReturnsSuccess` | Add Opaque secret via cluster |
| `Management_RemoveOpaqueSecretFromCluster_ReturnsSuccess` | Remove Opaque secret via cluster |
| `Management_AddOpaqueSecretWithBundledChain_CreatesBundledSecret` | IncludeCertChain=true, SeparateChain=false |
| `Management_AddOpaqueSecretWithSeparateChain_CreatesSeparateCaCrt` | IncludeCertChain=true, SeparateChain=true |
| `Management_AddOpaqueSecretWithoutChain_NoChainIncluded` | IncludeCertChain=false |
| `Management_OverwriteOpaqueSecret_UpdatesCorrectly` | Overwrite existing Opaque secret |
| `Inventory_MultipleOpaqueSecretsAcrossNamespaces_ReturnsAll` | Multiple Opaque secrets cluster-wide |
| **Key Type Coverage via Cluster** | |
| `Management_AddRsaCertificateViaCluster_AllKeySizes` | RSA 2048 via cluster |
| `Management_AddEcCertificateViaCluster_AllCurves` | EC P-256 via cluster |
| `Management_AddEd25519CertificateViaCluster_Success` | Ed25519 via cluster |
| `Management_AddRsa4096CertificateViaCluster_Success` | RSA 4096 add and inventory |
| `Management_AddEcP384CertificateViaCluster_Success` | EC P-384 add and inventory |
| `Management_AddEcP521CertificateViaCluster_Success` | EC P-521 add and inventory |
| `Management_AddRsa2048OpaqueSecretViaCluster_Success` | RSA 2048 Opaque via cluster |
| `Management_AddEcP256OpaqueSecretViaCluster_Success` | EC P-256 Opaque via cluster |
| **Cross-Type and Cross-Namespace Operations** | |
| `Inventory_MixedSecretTypes_ReturnsAllTypes` | TLS + Opaque in single inventory |
| `Discovery_MixedSecretTypes_ReturnsCorrectMetadata` | Discovery identifies secret types |
| `Management_AddTlsAndOpaqueToSameNamespace_BothSucceed` | Multiple types in same namespace |
| `CrossNamespace_TlsSecretsSameNameDifferentNs_AreIndependent` | TLS secrets same name different ns |
| `CrossNamespace_OpaqueSecretsSameNameDifferentNs_AreIndependent` | Opaque secrets same name different ns |
| `Management_TargetSpecificSecretType_UsesCorrectAlias` | Alias format targets correct type |
| **Additional Error Handling** | |
| `Inventory_NonExistentTlsSecretInCluster_ReturnsGracefully` | Non-existent TLS secret handling |
| `Inventory_NonExistentOpaqueSecretInCluster_ReturnsGracefully` | Non-existent Opaque secret handling |
| `Management_AddToNonExistentNamespace_ReturnsFailure` | Invalid namespace handling |

---

## K8SNS - Namespace-Level Store Type

Manages ALL secrets within a SINGLE namespace.

### Unit Tests (`K8SNSStoreTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Namespace Scope** | |
| `NamespaceStore_RepresentsSingleNamespace_NotClusterWide` | Store path is namespace name |
| `NamespaceStore_CanContainMultipleSecretTypes_InSameNamespace` | Multiple secret types in namespace |
| `NamespaceStore_EnforcesNamespaceBoundary_NoOtherNamespaces` | Only sees secrets in target namespace |
| **Secret Collection** | |
| `SecretList_SingleNamespace_CanBeEnumerated` | Secrets enumerated correctly |
| `SecretList_FilterByType_ReturnsOnlyMatchingSecrets` | Filtering by type works |
| `SecretList_GroupByName_CanIdentifyDuplicates` | Duplicate names detected |
| **Discovery** | |
| `Discovery_EmptyNamespace_ReturnsEmptyList` | Empty namespace returns empty |
| `Discovery_NamespaceWithSecrets_ReturnsAllSecrets` | All secrets discovered |
| **Certificate Data** | |
| `NamespaceSecret_WithPemCertificate_CanBeRead` | PEM certificates can be read |
| `NamespaceSecret_MultipleSecretsWithCertificates_CanBeEnumerated` | Multiple certificates enumerated |
| **Permissions (Conceptual)** | |
| `NamespaceStore_RequiresNamespaceScopedPermissions_NotClusterWide` | Documents namespace-scoped RBAC |
| **Edge Cases** | |
| `NamespaceStore_LargeNumberOfSecrets_CanBeHandled` | 100+ secrets handled |
| `NamespaceStore_SpecialCharactersInSecretNames_Handled` | Special characters in names work |
| **Namespace Validation** | |
| `NamespaceStore_ValidNamespace_AcceptsValidNames` | Valid namespace names accepted |
| `NamespaceStore_DefaultNamespace_HandledCorrectly` | Default namespace works |

### Integration Tests (`K8SNSStoreIntegrationTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Discovery** | |
| `Discovery_SingleNamespace_FindsAllSecrets` | Discovery in single namespace |
| `Discovery_MixedSecretTypes_FindsAllTypes` | Discovers all secret types |
| **Inventory** | |
| `Inventory_NamespaceScope_ReturnsAllCertificates` | Namespace-scoped inventory |
| **Management** | |
| `Management_AddCertificateToNamespace_ReturnsSuccess` | Add to namespace |
| `Management_RemoveCertificateFromNamespace_ReturnsSuccess` | Remove from namespace |
| **Boundary Tests** | |
| `NamespaceScope_OnlySeesSecretsInNamespace_NotOtherNamespaces` | Only sees own namespace |
| **Error Handling** | |
| `Inventory_NonExistentNamespace_ReturnsFailure` | Non-existent namespace handled |
| `Inventory_EmptyNamespace_ReturnsSuccess` | Empty namespace returns success |
| **Multiple Secret Types** | |
| `Namespace_WithMultipleSecretTypes_HandlesAllTypes` | Handles Opaque, TLS, EC in same namespace |
| **Key Type Coverage** | |
| `Management_Rsa2048Certificate_AddAndInventory_Success` | RSA 2048 add and inventory |
| `Management_Rsa4096Certificate_AddAndInventory_Success` | RSA 4096 add and inventory |
| `Management_EcP256Certificate_AddAndInventory_Success` | EC P-256 add and inventory |
| `Management_EcP384Certificate_AddAndInventory_Success` | EC P-384 add and inventory |
| `Management_EcP521Certificate_AddAndInventory_Success` | EC P-521 add and inventory |
| `Management_Ed25519Certificate_AddAndInventory_Success` | Ed25519 add and inventory |

---

## K8SCert - Certificate Signing Request Store Type

Manages Kubernetes Certificate Signing Requests (CSRs). **READ-ONLY** - only Inventory and Discovery operations are supported.

### Unit Tests (`K8SCertStoreTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **CSR Status** | |
| `CertificateSigningRequest_ApprovedWithCertificate_HasValidStatus` | Approved CSR with certificate |
| `CertificateSigningRequest_Pending_HasNoConditions` | Pending CSR has no conditions |
| `CertificateSigningRequest_Denied_HasDeniedCondition` | Denied CSR has denied condition |
| `CertificateSigningRequest_ApprovedWithoutCertificate_IsIncomplete` | Approved but no cert is incomplete |
| **CSR Certificate Parsing** | |
| `CertificateSigningRequest_WithValidCertificate_CanBeParsed` | Certificate from CSR can be parsed |
| `CertificateSigningRequest_VariousKeyTypes_CanBeCreated` | All key types create valid CSRs |
| **CSR Collection** | |
| `CertificateSigningRequests_MultipleCSRs_CanBeEnumerated` | Multiple CSRs enumerated with correct counts |
| **Edge Cases** | |
| `CertificateSigningRequest_NullStatus_HandledGracefully` | Null status handled |
| `CertificateSigningRequest_EmptyConditions_TreatedAsPending` | Empty conditions = pending |
| `CertificateSigningRequest_MultipleConditions_LatestTakesPrecedence` | Latest condition takes precedence |
| **Metadata** | |
| `CertificateSigningRequest_Metadata_ContainsRequiredFields` | Required metadata fields present |

### Integration Tests (`K8SCertStoreIntegrationTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Inventory** | |
| `Inventory_SingleApprovedCSR_ReturnsSuccess` | Approved CSR inventory |
| `Inventory_PendingCSR_ReturnsSuccess` | Pending CSR inventory |
| `Inventory_NonExistentCSR_ReturnsFailure` | Non-existent CSR handled gracefully |
| **Discovery** | |
| `Discovery_FindsMultipleCSRs_ReturnsSuccess` | Discovery finds multiple CSRs |

---

## KubeCertificateManagerClient - Direct Client Tests

Direct integration tests for the `KubeCertificateManagerClient` class, testing Kubernetes API operations without going through the job/handler layers.

### Integration Tests (`KubeClientIntegrationTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Constructor & Connection** | |
| `Constructor_ValidKubeconfig_CreatesClient` | Valid kubeconfig creates client |
| `GetHost_ReturnsClusterUrl` | Returns cluster API server URL |
| `GetClusterName_ReturnsClusterName` | Returns cluster name from config |
| **Secret CRUD** | |
| `GetCertificateStoreSecret_ExistingSecret_ReturnsSecret` | Read existing secret |
| `GetCertificateStoreSecret_NonExistent_ThrowsStoreNotFoundException` | Non-existent secret throws |
| `CreateOrUpdateCertificateStoreSecret_PEM_CreatesNewSecret` | Create new Opaque secret with PEM |
| `CreateOrUpdateCertificateStoreSecret_PEM_UpdatesExistingSecret` | Update existing Opaque secret |
| `CreateOrUpdateCertificateStoreSecret_TLS_CreatesNewSecret` | Create new TLS secret |
| `CreateOrUpdateCertificateStoreSecret_WithChain_StoresChainSeparately` | Chain stored in ca.crt |
| `DeleteCertificateStoreSecret_ExistingSecret_DeletesSuccessfully` | Delete secret |
| **PKCS12 Secrets** | |
| `GetPkcs12Secret_ExistingSecret_ReturnsSecretWithInventory` | Read PKCS12 secret with inventory |
| `GetPkcs12Secret_NonExistent_ThrowsStoreNotFoundException` | Non-existent PKCS12 throws |
| `GetPkcs12Secret_CustomAllowedKeys_FiltersCorrectly` | Filters by allowed extensions |
| `CreateOrUpdatePkcs12Secret_CreatesNewSecret` | Create new PKCS12 secret |
| **JKS Secrets** | |
| `GetJksSecret_ExistingSecret_ReturnsSecretWithInventory` | Read JKS secret with inventory |
| `GetJksSecret_NonExistent_ThrowsStoreNotFoundException` | Non-existent JKS throws |
| `GetJksSecret_EmptyData_ThrowsInvalidK8SSecretException` | Empty JKS data throws |
| `CreateOrUpdateJksSecret_CreatesNewSecret` | Create new JKS secret |
| **Buddy Passwords** | |
| `CreateOrUpdateBuddyPass_CreatesPasswordSecret` | Create buddy password secret |
| `CreateOrUpdateBuddyPass_UpdatesExistingPasswordSecret` | Update existing buddy password |
| `ReadBuddyPass_ExistingSecret_ReturnsSecret` | Read buddy password |
| `ReadBuddyPass_NonExistent_ThrowsStoreNotFoundException` | Non-existent buddy throws |
| **Discovery** | |
| `DiscoverSecrets_OpaqueType_FindsSecretsInNamespace` | Discover Opaque secrets |
| `DiscoverSecrets_TlsType_FindsTlsSecrets` | Discover TLS secrets |
| `DiscoverSecrets_ClusterType_ReturnsClusterName` | Cluster-type returns cluster name |
| `DiscoverSecrets_NamespaceType_ReturnsNamespaceLocations` | Namespace-type returns namespace locations |
| **PKCS12 Store Management** | |
| `CreateOrUpdateCertificateStoreSecret_PKCS12_CreatesNewStore` | Create PKCS12 store secret |
| `UpdatePKCS12SecretStore_AddsNewCertToExistingStore` | Add cert to existing PKCS12 store |
| `RemoveFromPKCS12SecretStore_RemovesCertificateFromStore` | Remove cert from PKCS12 store |
| `CreatePKCS12Collection_ValidPkcs12_ReturnsStore` | Create PKCS12 collection |
| **Certificate Operations** | |
| `ReadPemCertificate_ValidPem_ReturnsCertificate` | Read PEM certificate |
| `ReadDerCertificate_ValidDer_ReturnsCertificate` | Read DER certificate |
| `ConvertToPem_ValidCertificate_ReturnsPemString` | Convert to PEM |
| `ExtractPrivateKeyAsPem_ValidPkcs12_ReturnsKey` | Extract private key as PEM |
| `LoadCertificateChain_ValidPem_ReturnsChain` | Load certificate chain |
| **CSR Operations** | |
| `GenerateCertificateRequest_ValidParams_ReturnsCsrObject` | Generate CSR with key pair |
| `ListAllCertificateSigningRequests_ReturnsResults` | List all CSRs |
| `DiscoverCertificates_ReturnsLocations` | Discover CSR certificates |
| **Placeholder Methods** | |
| `GetOpaqueSecretCertificateInventory_ReturnsEmptyList` | Opaque inventory placeholder |
| `GetTlsSecretCertificateInventory_ReturnsEmptyList` | TLS inventory placeholder |

---

## Certificate Format Detection Tests

Tests for DER and PEM certificate format detection and parsing. These tests validate the ability to handle certificates without private keys from Command.

### Unit Tests (`CertificateFormatTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **DER Format Detection** | |
| `IsDerFormat_ValidDerCertificate_ReturnsTrue` | Valid DER certificate is detected |
| `IsDerFormat_VariousKeyTypes_ReturnsTrue` | DER detection works for RSA, EC, Ed25519 keys |
| `IsDerFormat_Pkcs12Data_ReturnsFalse` | PKCS12 data is not detected as DER |
| `IsDerFormat_RandomBytes_ReturnsFalse` | Random bytes are not detected as DER |
| `IsDerFormat_EmptyBytes_ReturnsFalse` | Empty bytes return false |
| `IsDerFormat_NullBytes_ReturnsFalse` | Null bytes return false |
| **Certificate Generation Without Private Key** | |
| `GenerateDerCertificate_ReturnsValidDerBytes` | DER certificate generation works |
| `GeneratePemCertificateOnly_ReturnsPemWithoutPrivateKey` | PEM without private key is generated |
| `GenerateBase64DerCertificate_ReturnsValidBase64` | Base64 DER certificate is valid |
| **Certificate Thumbprint** | |
| `GetThumbprint_DerCertificate_ReturnsValidThumbprint` | DER certificate thumbprint extraction |
| **PEM/DER Round-Trip** | |
| `DerToPem_RoundTrip_PreservesData` | Round-trip conversion preserves data |
| **Certificate Chain Parsing** | |
| `CertificateChain_MultiplePemCertificates_ParsesAllCerts` | Multiple PEM certs parsed correctly |
| `CertificateChain_FullChainInSingleField_ParsesAllThreeCerts` | Full chain (leaf+intermediate+root) parsed |
| `CertificateChain_SingleCertificate_ParsesOneCert` | Single certificate parsed |
| `CertificateChain_EmptyString_ReturnsEmptyList` | Empty string returns empty list |

---

## Certificate Utilities

Utility functions for certificate parsing, conversion, and property extraction.

### Unit Tests (`CertificateUtilitiesTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Certificate Parsing** | |
| `ParseCertificateFromPem_ValidPem_ReturnsValidCertificate` | PEM parsing works |
| `ParseCertificateFromPem_NullString_ThrowsArgumentException` | Null PEM throws |
| `ParseCertificateFromPem_EmptyString_ThrowsArgumentException` | Empty PEM throws |
| `ParseCertificateFromDer_ValidDer_ReturnsValidCertificate` | DER parsing works |
| `ParseCertificateFromDer_NullBytes_ThrowsArgumentException` | Null DER throws |
| `ParseCertificateFromDer_EmptyBytes_ThrowsArgumentException` | Empty DER throws |
| `ParseCertificateFromPkcs12_ValidPkcs12_ReturnsValidCertificate` | PKCS12 parsing works |
| `ParseCertificateFromPkcs12_WithAlias_ReturnsCorrectCertificate` | PKCS12 with alias works |
| **Certificate Properties** | |
| `GetThumbprint_ValidCertificate_ReturnsUppercaseHex` | Thumbprint is uppercase hex |
| `GetThumbprint_MatchesX509Certificate2_ForValidation` | Thumbprint matches .NET X509Certificate2 |
| `GetSubjectCN_ValidCertificate_ExtractsCorrectCN` | Subject CN extraction |
| `GetSubjectDN_ValidCertificate_ReturnsFullDN` | Full subject DN |
| `GetIssuerCN_ValidCertificate_ExtractsCorrectCN` | Issuer CN extraction |
| `GetNotBefore_ValidCertificate_ReturnsValidDate` | Not before date |
| `GetNotAfter_ValidCertificate_ReturnsValidDate` | Not after date |
| `GetSerialNumber_ValidCertificate_ReturnsHexString` | Serial number as hex |
| `GetKeyAlgorithm_RsaCertificate_ReturnsRSA` | RSA algorithm detection |
| `GetKeyAlgorithm_EcCertificate_ReturnsECDSA` | ECDSA algorithm detection |
| `GetPublicKey_ValidCertificate_ReturnsNonEmptyBytes` | Public key bytes |
| **Private Key Operations** | |
| `ExtractPrivateKey_ValidStore_ReturnsPrivateKey` | Private key extraction |
| `ExtractPrivateKey_WithAlias_ReturnsCorrectKey` | Extraction with alias |
| `ExtractPrivateKeyAsPem_RsaKey_ReturnsValidPem` | RSA key to PEM |
| `ExtractPrivateKeyAsPem_EcKey_ReturnsValidPem` | EC key to PEM |
| `ExportPrivateKeyPkcs8_RsaKey_ReturnsValidBytes` | RSA key to PKCS8 |
| `ExportPrivateKeyPkcs8_EcKey_ReturnsValidBytes` | EC key to PKCS8 |
| `GetPrivateKeyType_RsaKey_ReturnsRSA` | RSA key type detection |
| `GetPrivateKeyType_EcKey_ReturnsEC` | EC key type detection |
| **Chain Operations** | |
| `LoadCertificateChain_SingleCertPem_ReturnsOneCertificate` | Single cert chain |
| `LoadCertificateChain_MultipleCertsPem_ReturnsMultipleCertificates` | Multi cert chain |
| `LoadCertificateChain_EmptyString_ReturnsEmptyList` | Empty string = empty list |
| `ExtractChainFromPkcs12_WithChain_ReturnsFullChain` | PKCS12 chain extraction |
| **Format Detection** | |
| `DetectFormat_PemData_ReturnsPem` | PEM format detection |
| `DetectFormat_DerData_ReturnsDer` | DER format detection |
| `DetectFormat_Pkcs12Data_ReturnsPkcs12` | PKCS12 format detection |
| `DetectFormat_NullData_ReturnsUnknown` | Null = unknown |
| `DetectFormat_EmptyData_ReturnsUnknown` | Empty = unknown |
| **Format Conversion** | |
| `ConvertToPem_ValidCertificate_ReturnsValidPem` | Certificate to PEM |
| `ConvertToDer_ValidCertificate_ReturnsValidDer` | Certificate to DER |
| `ConvertToPem_RoundTrip_PreservesData` | PEM round-trip |
| **Helper Methods** | |
| `LoadPkcs12Store_ValidData_ReturnsStore` | PKCS12 store loading |
| `LoadPkcs12Store_InvalidPassword_ThrowsException` | Invalid password throws |
| `IsDerFormat_ValidDer_ReturnsTrue` | DER detection |
| `IsDerFormat_InvalidData_ReturnsFalse` | Invalid data detection |
| **Null Argument Tests** | |
| `GetThumbprint_NullCertificate_ThrowsArgumentNullException` | Null cert throws |
| `GetSubjectCN_NullCertificate_ThrowsArgumentNullException` | Null cert throws |
| `ConvertToPem_NullCertificate_ThrowsArgumentNullException` | Null cert throws |
| `ConvertToDer_NullCertificate_ThrowsArgumentNullException` | Null cert throws |
| `ExtractPrivateKeyAsPem_NullKey_ThrowsArgumentNullException` | Null key throws |
| `ExportPrivateKeyPkcs8_NullKey_ThrowsArgumentNullException` | Null key throws |

---

## Management Job Routing

Regression tests for `ManagementBase.RouteOperation`, verifying that `CertStoreOperationType.Create` ("create if missing") is correctly routed to `HandleAdd`.

### Unit Tests (`Unit/Jobs/ManagementBaseTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Create operation type regression** | |
| `RouteOperation_CreateType_CallsHandleAdd` | `OperationType=Create` routes to `HandleAdd` (regression: previously returned "Unknown operation type: Create") |
| `RouteOperation_CreateType_DoesNotFail` | `OperationType=Create` does not return Failure |
| **Add operation** | |
| `RouteOperation_AddType_CallsHandleAdd` | `OperationType=Add` routes to `HandleAdd` |
| **Remove operation** | |
| `RouteOperation_RemoveType_CallsHandleRemove` | `OperationType=Remove` routes to `HandleRemove` |
| **Unsupported operation types** | |
| `RouteOperation_UnsupportedTypes_ReturnsFailure` | `Unknown`, `Inventory`, `Discovery` return Failure without calling Add or Remove |

---

## Logging Safety Tests

Tests to ensure sensitive data is never logged.

### Unit Tests (`LoggingSafetyTests.cs`)

| Test Name | Description |
|-----------|-------------|
| **Source Code Analysis** | |
| `SourceCode_ShouldNotContain_DirectPasswordLogging` | No direct password logging in source |
| `SourceCode_ShouldNotContain_DirectPrivateKeyLogging` | No direct private key logging |
| `SourceCode_ShouldNotContain_DirectTokenLogging` | No direct token logging |
| `NoTodoInsecureCommentsRemain` | No TODO insecure comments remain |
| **LoggingUtilities** | |
| `LoggingUtilities_RedactPassword_ShouldNotRevealPassword` | Password redaction works |
| `LoggingUtilities_GetPasswordCorrelationId_ShouldBeConsistent` | Consistent correlation IDs |
| `LoggingUtilities_GetPasswordCorrelationId_ShouldBeDifferentForDifferentPasswords` | Different passwords = different IDs |
| `LoggingUtilities_RedactPrivateKeyPem_ShouldNotRevealKeyMaterial` | Private key PEM redaction |
| `LoggingUtilities_RedactPrivateKey_ShouldShowKeyTypeOnly` | Private key redaction shows type only |
| `LoggingUtilities_RedactPkcs12Bytes_ShouldNotRevealContents` | PKCS12 bytes redaction |
| `LoggingUtilities_RedactToken_ShouldShowOnlyPrefixSuffixAndLength` | Token redaction |
| `LoggingUtilities_GetFieldPresence_ShouldIndicatePresenceNotValue` | Field presence indicator |

---

## Test Infrastructure

### Helpers

- **`CertificateTestHelper.cs`** - Generates test certificates with various key types (RSA, EC, DSA, Ed25519, Ed448) and chain configurations
- **`SkipUnlessAttribute.cs`** - Custom xUnit attribute to skip tests unless specific environment variables are set

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUN_INTEGRATION_TESTS` | Set to `true` to enable integration tests | (not set) |
| `INTEGRATION_TEST_KUBECONFIG` | Path to kubeconfig file | `~/.kube/config` |
| `INTEGRATION_TEST_CONTEXT` | Kubernetes context to use | `kf-integrations` |
| `SKIP_INTEGRATION_TEST_CLEANUP` | Set to `true` to skip cleanup after tests | (not set) |

### Test Namespaces

Integration tests create dedicated namespaces for isolation:
- `keyfactor-k8sjks-integration-tests`
- `keyfactor-k8spkcs12-integration-tests`
- `keyfactor-k8ssecret-integration-tests`
- `keyfactor-k8stlssecr-integration-tests`
- `keyfactor-k8scluster-test-ns1`, `keyfactor-k8scluster-test-ns2`
- `keyfactor-k8sns-integration-tests`
- `keyfactor-k8scert-integration-tests`
