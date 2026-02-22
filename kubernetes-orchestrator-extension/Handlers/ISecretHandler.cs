// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Result of an inventory operation containing discovered certificates.
/// </summary>
public class InventoryResult
{
    /// <summary>
    /// Whether the inventory operation succeeded.
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Error message if the operation failed.
    /// </summary>
    public string ErrorMessage { get; set; } = string.Empty;

    /// <summary>
    /// Warning message (operation succeeded but with warnings).
    /// </summary>
    public string WarningMessage { get; set; } = string.Empty;

    /// <summary>
    /// List of PEM-formatted certificates discovered.
    /// </summary>
    public List<string> Certificates { get; set; } = new();

    /// <summary>
    /// Dictionary mapping aliases to certificate chains (for JKS/PKCS12).
    /// Key is the alias, value is a list of PEM certificates in the chain.
    /// </summary>
    public Dictionary<string, List<string>> CertificateChains { get; set; } = new();

    /// <summary>
    /// Dictionary mapping store paths to certificates (for cluster/namespace inventory).
    /// </summary>
    public Dictionary<string, string> CertificatesByPath { get; set; } = new();

    /// <summary>
    /// Whether the certificates have associated private keys.
    /// </summary>
    public bool HasPrivateKey { get; set; }

    /// <summary>
    /// The type of inventory result data available.
    /// </summary>
    public InventoryResultType ResultType { get; set; } = InventoryResultType.CertificateList;

    /// <summary>
    /// Creates a successful result with a list of certificates.
    /// </summary>
    public static InventoryResult SuccessWithCertificates(List<string> certificates, bool hasPrivateKey = false)
    {
        return new InventoryResult
        {
            Success = true,
            Certificates = certificates,
            HasPrivateKey = hasPrivateKey,
            ResultType = InventoryResultType.CertificateList
        };
    }

    /// <summary>
    /// Creates a successful result with certificate chains (JKS/PKCS12).
    /// </summary>
    public static InventoryResult SuccessWithChains(Dictionary<string, List<string>> chains, bool hasPrivateKey = false)
    {
        return new InventoryResult
        {
            Success = true,
            CertificateChains = chains,
            HasPrivateKey = hasPrivateKey,
            ResultType = InventoryResultType.CertificateChains
        };
    }

    /// <summary>
    /// Creates a successful result with certificates indexed by path (cluster/namespace).
    /// </summary>
    public static InventoryResult SuccessWithPaths(Dictionary<string, string> certsByPath, bool hasPrivateKey = false)
    {
        return new InventoryResult
        {
            Success = true,
            CertificatesByPath = certsByPath,
            HasPrivateKey = hasPrivateKey,
            ResultType = InventoryResultType.CertificatesByPath
        };
    }

    /// <summary>
    /// Creates a failed result.
    /// </summary>
    public static InventoryResult Failure(string errorMessage)
    {
        return new InventoryResult
        {
            Success = false,
            ErrorMessage = errorMessage
        };
    }

    /// <summary>
    /// Creates a warning result (succeeded but with issues).
    /// </summary>
    public static InventoryResult Warning(string warningMessage, List<string> certificates = null)
    {
        return new InventoryResult
        {
            Success = true,
            WarningMessage = warningMessage,
            Certificates = certificates ?? new List<string>()
        };
    }
}

/// <summary>
/// Type of data in an inventory result.
/// </summary>
public enum InventoryResultType
{
    /// <summary>
    /// Simple list of PEM certificates.
    /// </summary>
    CertificateList,

    /// <summary>
    /// Dictionary of aliases to certificate chains.
    /// </summary>
    CertificateChains,

    /// <summary>
    /// Dictionary of paths to certificates (cluster/namespace).
    /// </summary>
    CertificatesByPath
}

/// <summary>
/// Interface for secret type handlers.
/// Each handler implements the logic for a specific type of Kubernetes secret
/// (TLS, Opaque, JKS, PKCS12, etc.).
/// </summary>
public interface ISecretHandler
{
    /// <summary>
    /// The primary secret type this handler supports.
    /// </summary>
    SecretType SupportedSecretType { get; }

    /// <summary>
    /// Checks if this handler can process the given secret type.
    /// </summary>
    /// <param name="secretType">The secret type to check.</param>
    /// <returns>True if this handler can process the secret type.</returns>
    bool CanHandle(SecretType secretType);

    /// <summary>
    /// Processes an inventory operation to discover certificates in the store.
    /// </summary>
    /// <param name="context">The operation context containing store details.</param>
    /// <param name="client">The Kubernetes client for API operations.</param>
    /// <returns>The inventory result containing discovered certificates.</returns>
    InventoryResult ProcessInventory(SecretOperationContext context, KubeCertificateManagerClient client);

    /// <summary>
    /// Processes an add operation to add a certificate to the store.
    /// </summary>
    /// <param name="context">The operation context containing store details.</param>
    /// <param name="certificate">The certificate to add.</param>
    /// <param name="client">The Kubernetes client for API operations.</param>
    /// <returns>JobResult indicating success or failure.</returns>
    JobResult ProcessAdd(SecretOperationContext context, K8SJobCertificate certificate, KubeCertificateManagerClient client);

    /// <summary>
    /// Processes a remove operation to remove a certificate from the store.
    /// </summary>
    /// <param name="context">The operation context containing store details.</param>
    /// <param name="alias">The alias of the certificate to remove.</param>
    /// <param name="client">The Kubernetes client for API operations.</param>
    /// <returns>JobResult indicating success or failure.</returns>
    JobResult ProcessRemove(SecretOperationContext context, string alias, KubeCertificateManagerClient client);

    /// <summary>
    /// Asynchronously processes an inventory operation.
    /// </summary>
    Task<InventoryResult> ProcessInventoryAsync(
        SecretOperationContext context,
        KubeCertificateManagerClient client,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously processes an add operation.
    /// </summary>
    Task<JobResult> ProcessAddAsync(
        SecretOperationContext context,
        K8SJobCertificate certificate,
        KubeCertificateManagerClient client,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously processes a remove operation.
    /// </summary>
    Task<JobResult> ProcessRemoveAsync(
        SecretOperationContext context,
        string alias,
        KubeCertificateManagerClient client,
        CancellationToken cancellationToken = default);
}
