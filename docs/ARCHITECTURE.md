# Kubernetes Orchestrator Extension - Architecture

This document describes the architecture of the Keyfactor Kubernetes Universal Orchestrator Extension.

## Overview

The extension enables remote management of certificate stores in Kubernetes clusters. It integrates with Keyfactor Command to provide discovery, inventory, management, and reenrollment operations for certificates stored in various Kubernetes resources.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Keyfactor Command                               │
│  (Certificate Authority & Management Platform)                      │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  │ Orchestrator Protocol
                                  │
┌─────────────────────────────────▼───────────────────────────────────┐
│                 Universal Orchestrator                              │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │           Kubernetes Orchestrator Extension                   │  │
│  │                                                               │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │  │
│  │  │    Jobs     │  │  Handlers   │  │      Services       │   │  │
│  │  │  (per type) │─▶│  (per type) │─▶│  (shared business)  │   │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘   │  │
│  │         │                                     │               │  │
│  │         │              ┌──────────────────────┘               │  │
│  │         ▼              ▼                                      │  │
│  │  ┌─────────────────────────────┐                              │  │
│  │  │   KubeCertificateManager    │                              │  │
│  │  │        Client               │                              │  │
│  │  └──────────────┬──────────────┘                              │  │
│  │                 │                                             │  │
│  └─────────────────┼─────────────────────────────────────────────┘  │
│                    │                                                │
└────────────────────┼────────────────────────────────────────────────┘
                     │
                     │ Kubernetes API (REST)
                     │
┌────────────────────▼────────────────────────────────────────────────┐
│                    Kubernetes Cluster                               │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐    │
│  │   Secrets    │  │   Secrets    │  │  CertificateSigningReqs │    │
│  │   (Opaque)   │  │   (TLS)      │  │     (certificates.k8s)  │    │
│  └──────────────┘  └──────────────┘  └────────────────────────┘    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Supported Store Types

The extension supports 7 certificate store types:

| Store Type | Kubernetes Resource | Certificate Format | Operations |
|------------|--------------------|--------------------|------------|
| **K8SCert** | CertificateSigningRequest | PEM | Inventory, Discovery |
| **K8SSecret** | Secret (Opaque) | PEM | All |
| **K8STLSSecr** | Secret (kubernetes.io/tls) | PEM | All |
| **K8SJKS** | Secret (Opaque) | JKS (Java Keystore) | All + Reenrollment |
| **K8SPKCS12** | Secret (Opaque) | PKCS12/PFX | All + Reenrollment |
| **K8SCluster** | Multiple Secrets | PEM | All |
| **K8SNS** | Multiple Secrets | PEM | All |

## Layer Architecture

### 1. Jobs Layer (`Jobs/`)

Entry points for orchestrator operations. Each job type inherits from a base class.

```
Jobs/
├── Base/
│   ├── K8SJobBase.cs       # Shared infrastructure (client, credentials, results)
│   ├── InventoryBase.cs    # Common inventory logic
│   ├── ManagementBase.cs   # Common management logic
│   ├── DiscoveryBase.cs    # Common discovery logic
│   └── ReenrollmentBase.cs # Common reenrollment logic
└── StoreTypes/
    ├── K8SCert/            # CSR operations
    ├── K8SCluster/         # Cluster-wide operations
    ├── K8SNS/              # Namespace operations
    ├── K8SJKS/             # JKS keystore operations
    ├── K8SPKCS12/          # PKCS12 keystore operations
    ├── K8SSecret/          # Opaque secret operations
    └── K8STLSSecr/         # TLS secret operations
```

**Base Classes:**

- **K8SJobBase**: Initializes Kubernetes client, parses credentials, provides common result builders
- **InventoryBase**: Coordinates inventory collection, delegates to handlers
- **ManagementBase**: Handles add/remove operations, delegates to handlers
- **DiscoveryBase**: Discovers certificate stores across namespaces

### 2. Handlers Layer (`Handlers/`)

Implements secret-type-specific operations using the Strategy pattern.

```
Handlers/
├── ISecretHandler.cs           # Interface
├── SecretHandlerFactory.cs     # Factory for creating handlers
├── TlsSecretHandler.cs         # kubernetes.io/tls secrets
├── OpaqueSecretHandler.cs      # Opaque secrets with PEM data
├── JksSecretHandler.cs         # JKS keystores in Opaque secrets
├── Pkcs12SecretHandler.cs      # PKCS12 files in Opaque secrets
├── ClusterSecretHandler.cs     # Cluster-wide multi-secret operations
├── NamespaceSecretHandler.cs   # Namespace-level multi-secret operations
└── CertificateSecretHandler.cs # CSR operations (read-only)
```

**Key Interface:**

```csharp
public interface ISecretHandler
{
    string[] AllowedKeys { get; }
    string SecretTypeName { get; }
    bool SupportsManagement { get; }
    List<InventoryEntry> GetInventoryEntries(long jobId);
    V1Secret HandleAdd(K8SJobCertificate certObj, string alias, bool overwrite);
    V1Secret HandleRemove(string alias);
    V1Secret CreateEmptyStore();
    List<string> DiscoverStores(string[] allowedKeys, string namespacesCsv);
}
```

**Base Class (`SecretHandlerBase`):**

Provides shared logic used by multiple handlers:
- `IsSecretEmpty(V1Secret)` — Detects empty-store secrets (created via "create if missing")
- `ValidateCertOnlyUpdate(V1Secret)` — Prevents cert/key mismatch on cert-only overwrites (virtual `PrivateKeyFieldNames` property allows TLS vs Opaque customization)
- `ParseKeystoreAliasCore(alias, inventory, defaultFieldName)` — Shared alias parsing for JKS/PKCS12 handlers (`<fieldName>/<certAlias>` format)
- `ResolvePassword(V1Secret)` — Buddy-secret password resolution
- `HandleCreateIfMissing()` — Create-if-not-exists logic

### 3. Services Layer (`Services/`)

Reusable business logic services.

```
Services/
├── CertificateChainExtractor.cs   # Extracts certs from secret data fields
├── JobCertificateParser.cs        # Certificate format detection and extraction from job configs
├── KeystoreOperations.cs          # JKS/PKCS12 keystore manipulation
├── PasswordResolver.cs            # PAM-aware password resolution
├── StoreConfigurationParser.cs    # Parses store property JSON
└── StorePathResolver.cs           # Parses store paths (namespace/secret)
```

### 4. Clients Layer (`Clients/`)

Kubernetes API client wrappers and certificate operations.

```
Clients/
├── KubeClient.cs                  # Main client wrapper (alias: KubeCertificateManagerClient)
├── KubeconfigParser.cs            # Kubeconfig JSON parsing and validation
├── SecretOperations.cs            # Secret CRUD operations
└── CertificateOperations.cs       # Certificate parsing/conversion (thin wrapper over CertificateUtilities)
```

**KubeClient Responsibilities:**

- Kubeconfig parsing and validation (via `KubeconfigParser`)
- Connection retry logic
- TLS verification (optional skip)
- Secret CRUD operations (via `SecretOperations`)

**CertificateOperations** is a thin logging wrapper that delegates all certificate parsing, conversion, and private key export to `CertificateUtilities` and `PrivateKeyFormatUtilities`.

### 5. Serializers Layer (`Serializers/`)

Format-specific serialization for non-PEM stores. Only JKS and PKCS12 need serializers — PEM-based store types (K8SSecret, K8STLSSecr, K8SCert, K8SCluster, K8SNS) work with raw PEM strings directly in their handlers and don't require a separate serialization layer.

```
Serializers/
├── ICertificateStoreSerializer.cs  # Interface (Deserialize, Serialize, GetPrivateKeyPath)
├── K8SJKS/
│   └── Store.cs                    # JKS keystore handling (BouncyCastle)
└── K8SPKCS12/
    └── Store.cs                    # PKCS12 handling (BouncyCastle)
```

## Data Flow

### Inventory Operation

```
InventoryJobConfiguration
         │
         ▼
┌─────────────────────┐
│  Inventory Job      │ (e.g., K8SJKS/Inventory.cs)
│  (Store Type)       │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  InventoryBase      │
│  - Initialize       │
│  - Route to handler │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  ISecretHandler     │ (e.g., JksSecretHandler)
│  - GetInventory()   │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│  KubeClient         │ ────▶│  Kubernetes API     │
│  - GetSecret()      │      │  - GET /secrets     │
└─────────────────────┘      └─────────────────────┘
          │
          ▼
┌─────────────────────┐
│  KeystoreOperations │ (for JKS/PKCS12 only)
│  - Parse keystore   │
│  - Extract certs    │
└─────────────────────┘
          │
          ▼
    InventoryItems
          │
          ▼
┌─────────────────────┐
│  InventorySubmitter │
│  - Build items      │
│  - Submit to Command│
└─────────────────────┘
```

### Management Operation (Add)

```
ManagementJobConfiguration
         │
         ▼
┌─────────────────────┐
│  Management Job     │
│  (Store Type)       │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  ManagementBase     │
│  - Initialize       │
│  - Route to handler │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  ISecretHandler     │
│  - AddCertificate() │
└─────────┬───────────┘
          │
          ├─────────────────────────┐
          │                         │
          ▼                         ▼
┌─────────────────────┐   ┌─────────────────────┐
│  SecretOperations   │   │  KeystoreOperations │
│  - BuildNewSecret() │   │  - UpdateKeystore() │
│  - UpdateSecret()   │   └─────────────────────┘
└─────────────────────┘
          │
          ▼
    Kubernetes API
    - PUT /secrets
```

## Key Design Patterns

### Strategy Pattern (Handlers)

Each secret type implements `ISecretHandler`, allowing the base classes to work with any secret type through a common interface.

```csharp
// SecretHandlerFactory creates the appropriate handler
var handler = SecretHandlerFactory.Create(context.SecretType, kubeClient, logger);
handler.AddCertificate(context);
```

### Template Method Pattern (Base Classes)

Base classes define the algorithm skeleton; subclasses override specific steps.

```csharp
// InventoryBase defines the template
public JobResult ProcessJob(InventoryJobConfiguration config, ...)
{
    InitializeStore(config);          // Base implementation
    var handler = GetHandler();       // Subclass overrides
    var items = handler.GetInventory();
    SubmitInventory(items);           // Base implementation
}
```

### Lazy Initialization

Services are lazily initialized to avoid unnecessary object creation.

```csharp
private StorePathResolver _pathResolver;
protected StorePathResolver PathResolver =>
    _pathResolver ??= new StorePathResolver(Logger);
```

## Authentication

The extension authenticates to Kubernetes using a **kubeconfig** JSON object provided as the server password. The kubeconfig contains:

```json
{
  "apiVersion": "v1",
  "kind": "Config",
  "clusters": [{
    "name": "cluster",
    "cluster": {
      "server": "https://kubernetes.default.svc",
      "certificate-authority-data": "<base64-ca>"
    }
  }],
  "users": [{
    "name": "service-account",
    "user": {
      "token": "<service-account-token>"
    }
  }],
  "contexts": [{
    "name": "context",
    "context": {
      "cluster": "cluster",
      "user": "service-account",
      "namespace": "default"
    }
  }],
  "current-context": "context"
}
```

## Error Handling

The extension uses custom exceptions:

- **StoreNotFoundException**: Secret/CSR not found in Kubernetes
- **InvalidOperationException**: Invalid operation for store state
- **HttpOperationException**: Kubernetes API errors

Jobs return `JobResult` with appropriate status:

```csharp
public JobResult SuccessJob(long jobId) => new JobResult
{
    Result = OrchestratorJobStatusJobResult.Success,
    JobHistoryId = jobId
};

public JobResult FailJob(string message, long jobId) => new JobResult
{
    Result = OrchestratorJobStatusJobResult.Failure,
    JobHistoryId = jobId,
    FailureMessage = message
};
```

## Certificate Libraries

The extension uses multiple certificate libraries:

| Library | Purpose |
|---------|---------|
| **BouncyCastle** (v2.6.2) | X.509 parsing, JKS/PKCS12 handling, PEM encoding, private key operations |
| **Keyfactor.PKI** (v8.2.2) | Thumbprints, CommonName, SerialNumber, PEM/DER conversion, `PrivateKeyConverter` |
| **System.Security.Cryptography** | K8s client TLS only (not used for certificate store operations) |

**Note:** `CertificateUtilities` and `PrivateKeyFormatUtilities` in `Utilities/` wrap these libraries with consistent logging. Some operations (unencrypted private key PEM export, certificate chain parsing from mixed PEM) use raw BouncyCastle due to gaps in the PKI library — see `docs/KEYFACTOR_PKI_ENHANCEMENTS.md` for details.

## Configuration

### Store Configuration

Store-specific configuration is passed as JSON in `StoreProperties`:

```json
{
  "KubeNamespace": "production",
  "KubeSecretName": "my-tls-secret",
  "KubeSecretType": "tls_secret",
  "PasswordSecretPath": "production/my-password-secret",
  "PasswordFieldName": "password"
}
```

### PAM Integration

The extension supports Privileged Access Management (PAM) for credential retrieval:

```csharp
// PAMUtilities resolves fields with PAM fallback
var password = PAMUtilities.ResolveFieldWithPam(
    resolver,
    config.StorePassword,
    "StorePassword",
    defaultValue);
```

## Manifest

The `manifest.json` file registers the extension with the Universal Orchestrator:

```json
{
  "extensions": {
    "Keyfactor.Extensions.Orchestrator.K8S": {
      "assemblyPath": "Keyfactor.Orchestrators.K8S.dll",
      "TypeFullName": "Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SJKS.Inventory"
    }
  }
}
```

Each store type + operation combination has a corresponding entry mapping to its job class.

## Directory Structure

```
kubernetes-orchestrator-extension/
├── Clients/                    # Kubernetes API clients
├── Enums/                      # SecretType, StoreType enums
├── Exceptions/                 # Custom exceptions
├── Handlers/                   # Secret operation handlers
├── Jobs/
│   ├── Base/                   # Base job classes
│   └── StoreTypes/             # Store-specific jobs
├── Models/                     # Data models
├── Serializers/                # Store-specific serializers (JKS, PKCS12)
├── Services/                   # Business logic services
├── Utilities/                  # Helper utilities
└── manifest.json               # Extension registration
```

## Future Considerations

1. **Keyfactor.PKI Library Enhancements**: Several local utility methods could be replaced once PKI gaps are addressed — see `docs/KEYFACTOR_PKI_ENHANCEMENTS.md`
2. **Handler Registry**: The current factory pattern could evolve into a registry for easier extension
3. **Async Operations**: Consider async/await for Kubernetes API calls
4. **Connection Pooling**: Reuse Kubernetes client connections across operations
5. **Metrics**: Add telemetry for operation timing and success rates
