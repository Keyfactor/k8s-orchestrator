// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Services;

/// <summary>
/// Service for building and submitting certificate inventory to Keyfactor Command.
/// Consolidates duplicate PushInventory logic from Inventory.cs.
/// </summary>
public class InventorySubmitter
{
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new InventorySubmitter.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    public InventorySubmitter(ILogger logger = null)
    {
        _logger = logger ?? LogHandler.GetClassLogger(typeof(InventorySubmitter));
    }

    /// <summary>
    /// Submits a certificate inventory to Keyfactor Command.
    /// </summary>
    /// <param name="inventoryItems">The inventory items to submit.</param>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <param name="submitInventory">Callback delegate to submit certificates.</param>
    /// <param name="jobMessage">Optional message to include in the job result.</param>
    /// <returns>JobResult indicating success or failure.</returns>
    public JobResult SubmitInventory(
        List<CurrentInventoryItem> inventoryItems,
        long jobId,
        SubmitInventoryUpdate submitInventory,
        string jobMessage = null)
    {
        try
        {
            _logger.LogDebug("Submitting {Count} inventory items to Keyfactor Command for job {JobId}",
                inventoryItems.Count, jobId);
            submitInventory.Invoke(inventoryItems);
            _logger.LogInformation("Inventory completed successfully for job id {JobId}", jobId);
            return CreateSuccessResult(jobId, jobMessage);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unable to submit inventory to Keyfactor Command for job id {JobId}", jobId);
            return CreateFailureResult(jobId, ex.Message);
        }
    }

    /// <summary>
    /// Builds inventory items from a list of PEM certificate strings.
    /// </summary>
    /// <param name="certsList">Collection of PEM-formatted certificate strings.</param>
    /// <param name="hasPrivateKey">Whether the certificates have associated private keys.</param>
    /// <param name="storeName">Store name for logging (optional).</param>
    /// <param name="namespaceName">Namespace for logging (optional).</param>
    /// <returns>List of inventory items, or null if parsing fails.</returns>
    public (List<CurrentInventoryItem> Items, string Error) BuildInventoryFromPemList(
        IEnumerable<string> certsList,
        bool hasPrivateKey,
        string storeName = null,
        string namespaceName = null)
    {
        var inventoryItems = new List<CurrentInventoryItem>();

        foreach (var cert in certsList)
        {
            if (string.IsNullOrEmpty(cert))
            {
                _logger.LogWarning("Empty certificate found in inventory for {Store}/{Namespace}",
                    storeName ?? "unknown", namespaceName ?? "unknown");
                continue;
            }

            try
            {
                var bcCert = cert.Contains("BEGIN CERTIFICATE")
                    ? CertificateUtilities.ParseCertificateFromPem(cert)
                    : CertificateUtilities.ParseCertificateFromDer(Convert.FromBase64String(cert));

                var alias = CertificateUtilities.GetThumbprint(bcCert);
                _logger.LogDebug("Parsed certificate with thumbprint: {Alias}", alias);

                inventoryItems.Add(CreateInventoryItem(alias, new[] { cert }, hasPrivateKey));
                break; // Original behavior: only process first valid cert
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Failed to parse certificate");
                return (null, e.Message);
            }
        }

        return (inventoryItems, null);
    }

    /// <summary>
    /// Builds inventory items from a dictionary mapping aliases to single certificates.
    /// </summary>
    /// <param name="certsList">Dictionary mapping aliases to PEM certificate strings.</param>
    /// <param name="hasPrivateKey">Whether the certificates have associated private keys.</param>
    /// <param name="storeName">Store name for logging (optional).</param>
    /// <param name="namespaceName">Namespace for logging (optional).</param>
    /// <returns>List of inventory items.</returns>
    public List<CurrentInventoryItem> BuildInventoryFromDictionary(
        Dictionary<string, string> certsList,
        bool hasPrivateKey,
        string storeName = null,
        string namespaceName = null)
    {
        var inventoryItems = new List<CurrentInventoryItem>();

        foreach (var certObj in certsList)
        {
            var cert = certObj.Value;
            var alias = certObj.Key;

            if (string.IsNullOrEmpty(cert))
            {
                _logger.LogWarning("Empty certificate for alias {Alias} in {Store}/{Namespace}",
                    alias, storeName ?? "unknown", namespaceName ?? "unknown");
                continue;
            }

            try
            {
                var bcCert = cert.Contains("BEGIN CERTIFICATE")
                    ? CertificateUtilities.ParseCertificateFromPem(cert)
                    : CertificateUtilities.ParseCertificateFromDer(Convert.FromBase64String(cert));
                _logger.LogTrace("Certificate parsed successfully: {Subject}", bcCert.SubjectDN);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Failed to parse certificate for alias {Alias}", alias);
                // Continue processing other certificates (original behavior)
            }

            inventoryItems.Add(CreateInventoryItem(alias, new[] { cert }, hasPrivateKey));
        }

        return inventoryItems;
    }

    /// <summary>
    /// Builds inventory items from a dictionary mapping aliases to certificate chains.
    /// </summary>
    /// <param name="certsList">Dictionary mapping aliases to lists of PEM certificates (chains).</param>
    /// <param name="hasPrivateKey">Whether the certificates have associated private keys.</param>
    /// <param name="storeName">Store name for logging (optional).</param>
    /// <param name="namespaceName">Namespace for logging (optional).</param>
    /// <returns>List of inventory items.</returns>
    public List<CurrentInventoryItem> BuildInventoryFromChainDictionary(
        Dictionary<string, List<string>> certsList,
        bool hasPrivateKey,
        string storeName = null,
        string namespaceName = null)
    {
        var inventoryItems = new List<CurrentInventoryItem>();

        foreach (var certObj in certsList)
        {
            var certs = certObj.Value;
            var alias = certObj.Key;

            if (certs == null || certs.Count == 0)
            {
                _logger.LogWarning("Empty certificate chain for alias {Alias} in {Store}/{Namespace}",
                    alias, storeName ?? "unknown", namespaceName ?? "unknown");
                continue;
            }

            inventoryItems.Add(CreateInventoryItem(alias, certs, hasPrivateKey));
        }

        return inventoryItems;
    }

    /// <summary>
    /// Creates a single inventory item.
    /// </summary>
    private static CurrentInventoryItem CreateInventoryItem(string alias, IEnumerable<string> certificates, bool hasPrivateKey)
    {
        return new CurrentInventoryItem
        {
            ItemStatus = OrchestratorInventoryItemStatus.Unknown,
            Alias = alias,
            PrivateKeyEntry = hasPrivateKey,
            UseChainLevel = true,
            Certificates = certificates
        };
    }

    /// <summary>
    /// Creates a success job result.
    /// </summary>
    private static JobResult CreateSuccessResult(long jobId, string message = null)
    {
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Success,
            JobHistoryId = jobId,
            FailureMessage = message
        };
    }

    /// <summary>
    /// Creates a failure job result.
    /// </summary>
    private static JobResult CreateFailureResult(long jobId, string errorMessage)
    {
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Failure,
            JobHistoryId = jobId,
            FailureMessage = errorMessage
        };
    }
}
