// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Handler for Kubernetes Certificate Signing Requests (CSRs).
/// This handler is READ-ONLY - CSRs cannot be created/modified through the orchestrator.
/// </summary>
public class CertificateSecretHandler : SecretHandlerBase
{
    /// <summary>
    /// Default allowed keys (not applicable to CSRs).
    /// </summary>
    private static readonly string[] DefaultAllowedKeys = Array.Empty<string>();

    /// <inheritdoc />
    public override string[] AllowedKeys => DefaultAllowedKeys;

    /// <inheritdoc />
    public override string SecretTypeName => "certificate";

    /// <inheritdoc />
    public override bool SupportsManagement => false;

    /// <summary>
    /// Initializes a new instance of the CertificateSecretHandler.
    /// </summary>
    public CertificateSecretHandler(
        KubeCertificateManagerClient kubeClient,
        ILogger logger,
        ISecretOperationContext context)
        : base(kubeClient, logger, context)
    {
    }

    #region Inventory Operations

    /// <inheritdoc />
    public override List<string> GetCertificates(long jobId)
    {
        LogMethodEntry(nameof(GetCertificates));

        try
        {
            // Check if this is single CSR mode or cluster-wide mode
            if (IsSingleCsrMode())
            {
                return GetSingleCsrCertificates(jobId);
            }
            else
            {
                return GetClusterWideCsrCertificates(jobId);
            }
        }
        finally
        {
            LogMethodExit(nameof(GetCertificates));
        }
    }

    /// <inheritdoc />
    public override Dictionary<string, List<string>> GetCertificatesWithAliases(long jobId)
    {
        LogMethodEntry(nameof(GetCertificatesWithAliases));

        try
        {
            var result = new Dictionary<string, List<string>>();

            if (IsSingleCsrMode())
            {
                var certs = GetSingleCsrCertificates(jobId);
                if (certs.Count > 0)
                {
                    result[Context.KubeSecretName] = certs;
                }
            }
            else
            {
                // Cluster-wide: list all CSRs
                // ListAllCertificateSigningRequests returns Dictionary<string, string> (name -> certPem)
                var allCsrs = KubeClient.ListAllCertificateSigningRequests();
                foreach (var kvp in allCsrs)
                {
                    if (!string.IsNullOrEmpty(kvp.Value))
                    {
                        // Parse PEM chain and convert back to individual PEM strings
                        var certList = SplitPemChainToStrings(kvp.Value);
                        if (certList.Count > 0)
                        {
                            result[kvp.Key] = certList;
                        }
                    }
                }
            }

            return result;
        }
        finally
        {
            LogMethodExit(nameof(GetCertificatesWithAliases));
        }
    }

    /// <inheritdoc />
    public override List<InventoryEntry> GetInventoryEntries(long jobId)
    {
        var aliasedCerts = GetCertificatesWithAliases(jobId);
        var entries = new List<InventoryEntry>();

        foreach (var kvp in aliasedCerts)
        {
            entries.Add(new InventoryEntry
            {
                Alias = kvp.Key,
                Certificates = kvp.Value,
                HasPrivateKey = false // CSRs never have private keys in the orchestrator
            });
        }

        return entries;
    }

    /// <inheritdoc />
    public override bool HasPrivateKey()
    {
        // CSRs never have private keys accessible through the orchestrator
        return false;
    }

    #endregion

    #region Management Operations (Not Supported)

    /// <inheritdoc />
    public override V1Secret HandleAdd(K8SJobCertificate certObj, string alias, bool overwrite)
    {
        throw new NotSupportedException(
            "Management operations are not supported for Certificate Signing Requests. " +
            "CSRs must be created and approved through Kubernetes directly.");
    }

    /// <inheritdoc />
    public override V1Secret HandleRemove(string alias)
    {
        throw new NotSupportedException(
            "Management operations are not supported for Certificate Signing Requests. " +
            "CSRs must be deleted through Kubernetes directly.");
    }

    /// <inheritdoc />
    public override V1Secret CreateEmptyStore()
    {
        throw new NotSupportedException(
            "Certificate Signing Requests cannot be created as empty stores.");
    }

    #endregion

    #region Discovery Operations

    /// <inheritdoc />
    public override List<string> DiscoverStores(string[] allowedKeys, string namespacesCsv)
    {
        LogMethodEntry(nameof(DiscoverStores));

        try
        {
            // ListAllCertificateSigningRequests returns Dictionary<string, string> (name -> certPem)
            var allCsrs = KubeClient.ListAllCertificateSigningRequests();
            return allCsrs.Keys.ToList();
        }
        finally
        {
            LogMethodExit(nameof(DiscoverStores));
        }
    }

    #endregion

    #region Private Helpers

    private bool IsSingleCsrMode()
    {
        // Single CSR mode when a specific CSR name is provided
        return !string.IsNullOrEmpty(Context.KubeSecretName) &&
               Context.KubeSecretName != "*";
    }

    private List<string> GetSingleCsrCertificates(long jobId)
    {
        try
        {
            // GetCertificateSigningRequestStatus returns string[] (each element may contain a chain)
            var csrCerts = KubeClient.GetCertificateSigningRequestStatus(Context.KubeSecretName);
            if (csrCerts != null && csrCerts.Length > 0)
            {
                // Split each PEM chain into individual certificates
                var allCerts = new List<string>();
                foreach (var certPem in csrCerts)
                {
                    var split = SplitPemChainToStrings(certPem);
                    allCerts.AddRange(split);
                }
                return allCerts;
            }

            Logger.LogDebug("CSR '{Name}' has no issued certificate yet", Context.KubeSecretName);
            return new List<string>();
        }
        catch (k8s.Autorest.HttpOperationException ex)
            when (ex.Response?.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            throw new StoreNotFoundException(
                $"Certificate Signing Request '{Context.KubeSecretName}' was not found.");
        }
    }

    /// <summary>
    /// Splits a PEM chain into individual certificate PEM strings using the existing
    /// KubeClient.LoadCertificateChain method (powered by BouncyCastle's PemReader).
    /// </summary>
    private List<string> SplitPemChainToStrings(string pemChain)
    {
        if (string.IsNullOrWhiteSpace(pemChain))
        {
            return new List<string>();
        }

        var certs = KubeClient.LoadCertificateChain(pemChain);
        var result = new List<string>();

        foreach (var cert in certs)
        {
            var certPem = KubeClient.ConvertToPem(cert);
            result.Add(certPem);
        }

        Logger.LogDebug("Split PEM chain into {Count} individual certificates", result.Count);
        return result;
    }

    private List<string> GetClusterWideCsrCertificates(long jobId)
    {
        // ListAllCertificateSigningRequests returns Dictionary<string, string> (name -> certPem)
        var allCsrs = KubeClient.ListAllCertificateSigningRequests();

        // Split each PEM chain into individual certificates
        var allCerts = new List<string>();
        foreach (var certPem in allCsrs.Values.Where(v => !string.IsNullOrEmpty(v)))
        {
            var split = SplitPemChainToStrings(certPem);
            allCerts.AddRange(split);
        }
        return allCerts;
    }

    #endregion
}
