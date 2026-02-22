// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Constants;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers.Serializers;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using StoreNotFoundException = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreNotFoundException;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Handler for PKCS12/PFX keystores stored in Kubernetes Opaque secrets.
/// Supports multiple aliases, certificate chains, and password-protected keystores.
/// </summary>
public class Pkcs12SecretHandler : BaseSecretHandler
{
    private readonly string _jobProperties;

    /// <summary>
    /// Creates a new Pkcs12SecretHandler.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    /// <param name="jobProperties">Optional job properties JSON for serializer configuration.</param>
    public Pkcs12SecretHandler(ILogger logger = null, string jobProperties = null) : base(logger)
    {
        _jobProperties = jobProperties;
    }

    /// <inheritdoc />
    public override SecretType SupportedSecretType => SecretType.Pkcs12;

    /// <inheritdoc />
    public override InventoryResult ProcessInventory(SecretOperationContext context, KubeCertificateManagerClient client)
    {
        LogOperationStart("Inventory", context);

        try
        {
            var allowedKeys = GetAllowedKeys(context);
            Logger.LogDebug("Fetching PKCS12 secret {Namespace}/{SecretName}", context.Namespace, context.SecretName);

            var k8sData = client.GetPkcs12Secret(context.SecretName, context.Namespace, "", "", allowedKeys.ToList());

            var pkcs12InventoryDict = new Dictionary<string, List<string>>();
            var pkcs12Store = new Pkcs12CertificateStoreSerializer(_jobProperties);

            foreach (var (keyName, keyBytes) in k8sData.Inventory)
            {
                Logger.LogDebug("Processing PKCS12 data field '{Key}'", keyName);
                var keyPassword = ResolveStorePassword(context, client, k8sData.Secret);

                var pStoreDs = pkcs12Store.DeserializeRemoteCertificateStore(keyBytes, keyName, keyPassword);

                foreach (var certAlias in pStoreDs.Aliases)
                {
                    var certChainList = new List<string>();
                    var certChain = pStoreDs.GetCertificateChain(certAlias);

                    var fullAlias = $"{keyName}/{certAlias}";

                    if (certChain != null)
                    {
                        certChainList = BuildCertificateChainPems(certChain);
                    }

                    if (certChainList.Count > 0)
                    {
                        pkcs12InventoryDict[fullAlias] = certChainList;
                        continue;
                    }

                    // Try to get just the leaf certificate
                    var leaf = pStoreDs.GetCertificate(certAlias);
                    if (leaf != null)
                    {
                        certChainList.Add(ConvertToPem(leaf.Certificate));
                    }

                    pkcs12InventoryDict[fullAlias] = certChainList;
                }
            }

            Logger.LogDebug("PKCS12 inventory complete with {Count} entries", pkcs12InventoryDict.Count);
            LogOperationComplete("Inventory", context, true);
            return InventoryResult.SuccessWithChains(pkcs12InventoryDict, true);
        }
        catch (StoreNotFoundException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error during PKCS12 secret inventory: {Message}", ex.Message);
            return InventoryResult.Failure($"Error processing PKCS12 secret: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public override JobResult ProcessAdd(SecretOperationContext context, K8SJobCertificate certificate, KubeCertificateManagerClient client)
    {
        LogOperationStart("Add", context);

        try
        {
            var pkcs12Store = new Pkcs12CertificateStoreSerializer(_jobProperties);
            var k8sData = new KubeCertificateManagerClient.Pkcs12Secret();

            // Try to get existing secret
            try
            {
                k8sData = client.GetPkcs12Secret(context.SecretName, context.Namespace);
            }
            catch (StoreNotFoundException)
            {
                Logger.LogDebug("PKCS12 secret not found, will create new");
            }

            var newCertBytes = string.IsNullOrEmpty(certificate.CertB64)
                ? Array.Empty<byte>()
                : Convert.FromBase64String(certificate.CertB64);

            if (certificate.Pkcs12 != null && certificate.Pkcs12.Length > 0)
            {
                newCertBytes = certificate.Pkcs12;
            }

            var alias = certificate.Alias;
            if (string.IsNullOrEmpty(alias))
            {
                alias = certificate.CertThumbprint ?? "default";
            }

            var existingDataFieldName = SecretFieldNames.DefaultPkcs12;

            // Parse alias for field name
            if (alias.Contains('/'))
            {
                var aliasParts = alias.Split('/');
                existingDataFieldName = aliasParts[0];
                alias = aliasParts[1];
            }

            byte[] existingData = null;
            if (k8sData.Secret?.Data != null &&
                k8sData.Secret.Data.TryGetValue(existingDataFieldName, out var existingValue))
            {
                existingData = existingValue;
            }

            var storePassword = ResolveStorePassword(context, client, k8sData.Secret);

            var newPkcs12Store = pkcs12Store.CreateOrUpdatePkcs12(
                newCertBytes,
                certificate.Password,
                alias,
                existingData,
                storePassword,
                false);

            if (k8sData.Inventory == null || k8sData.Inventory.Count == 0)
            {
                k8sData.Inventory = new Dictionary<string, byte[]>();
            }
            k8sData.Inventory[existingDataFieldName] = newPkcs12Store;

            client.CreateOrUpdatePkcs12Secret(k8sData, context.SecretName, context.Namespace);

            LogOperationComplete("Add", context, true);
            return SuccessJob(context.JobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error adding certificate to PKCS12 secret: {Message}", ex.Message);
            return FailJob(ex.Message, context.JobHistoryId);
        }
    }

    /// <inheritdoc />
    public override JobResult ProcessRemove(SecretOperationContext context, string alias, KubeCertificateManagerClient client)
    {
        LogOperationStart("Remove", context);

        try
        {
            var pkcs12Store = new Pkcs12CertificateStoreSerializer(_jobProperties);
            KubeCertificateManagerClient.Pkcs12Secret k8sData;

            try
            {
                k8sData = client.GetPkcs12Secret(context.SecretName, context.Namespace);
            }
            catch (StoreNotFoundException)
            {
                Logger.LogWarning("PKCS12 secret not found, nothing to remove");
                return SuccessJob(context.JobHistoryId, "Secret not found, nothing to remove");
            }

            var existingDataFieldName = SecretFieldNames.DefaultPkcs12;
            var entryAlias = alias;

            if (alias.Contains('/'))
            {
                var aliasParts = alias.Split('/');
                existingDataFieldName = aliasParts[0];
                entryAlias = aliasParts[1];
            }

            byte[] existingData = null;
            if (k8sData.Secret?.Data != null &&
                k8sData.Secret.Data.TryGetValue(existingDataFieldName, out var existingValue))
            {
                existingData = existingValue;
            }

            if (existingData == null)
            {
                Logger.LogWarning("PKCS12 field '{Field}' not found in secret", existingDataFieldName);
                return SuccessJob(context.JobHistoryId, $"Field '{existingDataFieldName}' not found, nothing to remove");
            }

            var storePassword = ResolveStorePassword(context, client, k8sData.Secret);

            var newPkcs12Store = pkcs12Store.CreateOrUpdatePkcs12(
                Array.Empty<byte>(),
                null,
                entryAlias,
                existingData,
                storePassword,
                true);  // remove = true

            k8sData.Inventory[existingDataFieldName] = newPkcs12Store;
            client.CreateOrUpdatePkcs12Secret(k8sData, context.SecretName, context.Namespace);

            LogOperationComplete("Remove", context, true);
            return SuccessJob(context.JobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error removing certificate from PKCS12 secret: {Message}", ex.Message);
            return FailJob(ex.Message, context.JobHistoryId);
        }
    }

    private string[] GetAllowedKeys(SecretOperationContext context)
    {
        if (!string.IsNullOrEmpty(context.CertDataFieldName))
        {
            return context.CertDataFieldName.Split(',')
                .Concat(AllowedKeys.Pkcs12Keys)
                .Distinct()
                .ToArray();
        }
        return AllowedKeys.Pkcs12Keys;
    }
}
