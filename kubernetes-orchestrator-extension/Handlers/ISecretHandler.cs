// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Extensions;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Represents a single inventory entry with certificate chain and private key status.
/// Used for multi-secret inventory (K8SNS, K8SCluster) where each secret may have different private key status.
/// </summary>
public class InventoryEntry
{
    /// <summary>The alias/identifier for this inventory item.</summary>
    public string Alias { get; set; } = string.Empty;

    /// <summary>The certificate chain as PEM strings (leaf cert first, then intermediates, then root).</summary>
    public List<string> Certificates { get; set; } = new();

    /// <summary>Whether this entry has a private key in the store.</summary>
    public bool HasPrivateKey { get; set; }
}

/// <summary>
/// Interface for secret handlers that provide store-type-specific operations.
/// Each store type (TLS, Opaque, JKS, PKCS12, etc.) implements this interface.
/// </summary>
public interface ISecretHandler
{
    #region Inventory Operations

    /// <summary>
    /// Gets certificates from the secret as a simple list of PEM strings.
    /// Used by simple secret types (Opaque, TLS) where there's a single certificate chain.
    /// </summary>
    /// <param name="jobId">Job history ID for logging.</param>
    /// <returns>List of PEM-encoded certificates.</returns>
    List<string> GetCertificates(long jobId);

    /// <summary>
    /// Gets certificates from the secret with alias information.
    /// Used by keystore types (JKS, PKCS12) where each entry has an alias.
    /// </summary>
    /// <param name="jobId">Job history ID for logging.</param>
    /// <returns>Dictionary mapping alias to certificate chain (list of PEM strings).</returns>
    Dictionary<string, List<string>> GetCertificatesWithAliases(long jobId);

    /// <summary>
    /// Gets inventory entries with full metadata including private key status.
    /// Used by multi-secret types (K8SCluster, K8SNS) for per-item inventory.
    /// </summary>
    /// <param name="jobId">Job history ID for logging.</param>
    /// <returns>List of inventory entries with certificates and private key status.</returns>
    List<InventoryEntry> GetInventoryEntries(long jobId);

    /// <summary>
    /// Checks if this secret has a private key.
    /// </summary>
    /// <returns>True if the secret contains a private key.</returns>
    bool HasPrivateKey();

    #endregion

    #region Management Operations

    /// <summary>
    /// Adds or updates a certificate in the secret.
    /// </summary>
    /// <param name="certObj">Certificate object containing cert data and private key.</param>
    /// <param name="alias">Alias/name for the certificate entry.</param>
    /// <param name="overwrite">Whether to overwrite existing entries.</param>
    /// <returns>Updated V1Secret object.</returns>
    V1Secret HandleAdd(K8SJobCertificate certObj, string alias, bool overwrite);

    /// <summary>
    /// Removes a certificate from the secret.
    /// </summary>
    /// <param name="alias">Alias of the certificate to remove.</param>
    /// <returns>Updated V1Secret object, or null if secret was deleted.</returns>
    V1Secret HandleRemove(string alias);

    /// <summary>
    /// Creates an empty store (used for "create if missing" scenarios).
    /// </summary>
    /// <returns>New V1Secret object.</returns>
    V1Secret CreateEmptyStore();

    #endregion

    #region Discovery Operations

    /// <summary>
    /// Discovers stores of this type in the cluster or namespace.
    /// </summary>
    /// <param name="allowedKeys">Data keys to look for in secrets.</param>
    /// <param name="namespacesCsv">Comma-separated namespaces to search, or "all" for cluster-wide.</param>
    /// <returns>List of store paths in format "namespace/secretname".</returns>
    List<string> DiscoverStores(string[] allowedKeys, string namespacesCsv);

    #endregion

    #region Properties

    /// <summary>
    /// Gets the default allowed data keys for this secret type.
    /// </summary>
    string[] AllowedKeys { get; }

    /// <summary>
    /// Gets the secret type name (e.g., "tls", "opaque", "jks").
    /// </summary>
    string SecretTypeName { get; }

    /// <summary>
    /// Gets whether this handler supports management operations.
    /// Some handlers (like K8SCert) are read-only.
    /// </summary>
    bool SupportsManagement { get; }

    #endregion
}

/// <summary>
/// Context object containing configuration and dependencies for secret handlers.
/// Passed to handler constructors to provide access to KubeClient, Logger, and job configuration.
/// </summary>
public interface ISecretOperationContext
{
    /// <summary>Kubernetes namespace for the secret.</summary>
    string KubeNamespace { get; }

    /// <summary>Secret name.</summary>
    string KubeSecretName { get; }

    /// <summary>Store path from job configuration.</summary>
    string StorePath { get; }

    /// <summary>Store password (for keystores).</summary>
    string StorePassword { get; }

    /// <summary>Password secret path (for buddy password pattern).</summary>
    string PasswordSecretPath { get; }

    /// <summary>Password field name in buddy secret.</summary>
    string PasswordFieldName { get; }

    /// <summary>Whether to store certificate chain separately.</summary>
    bool SeparateChain { get; }

    /// <summary>Whether to include certificate chain in inventory.</summary>
    bool IncludeCertChain { get; }

    /// <summary>Custom certificate data field name(s).</summary>
    string CertificateDataFieldName { get; }
}
