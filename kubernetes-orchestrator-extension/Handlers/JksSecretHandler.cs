// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using k8s.Autorest;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Constants;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers.Serializers;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using StoreNotFoundException = Keyfactor.Extensions.Orchestrator.K8S.Exceptions.StoreNotFoundException;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Handler for Java KeyStore (JKS) files stored in Kubernetes Opaque secrets.
/// Supports multiple aliases, certificate chains, and password-protected keystores.
/// </summary>
public class JksSecretHandler : BaseSecretHandler
{
    private readonly string _jobProperties;

    /// <summary>
    /// Creates a new JksSecretHandler.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    /// <param name="jobProperties">Optional job properties JSON for serializer configuration.</param>
    public JksSecretHandler(ILogger logger = null, string jobProperties = null) : base(logger)
    {
        _jobProperties = jobProperties;
    }

    /// <inheritdoc />
    public override SecretType SupportedSecretType => SecretType.Jks;

    /// <inheritdoc />
    public override InventoryResult ProcessInventory(SecretOperationContext context, KubeCertificateManagerClient client)
    {
        LogOperationStart("Inventory", context);

        try
        {
            var allowedKeys = GetAllowedKeys(context);
            Logger.LogDebug("Fetching JKS secret {Namespace}/{SecretName}", context.Namespace, context.SecretName);

            var k8sData = client.GetJksSecret(context.SecretName, context.Namespace, "", "", allowedKeys.ToList());

            var jksInventoryDict = new Dictionary<string, List<string>>();
            var jksStore = new JksCertificateStoreSerializer(_jobProperties);

            foreach (var (keyName, keyBytes) in k8sData.Inventory)
            {
                Logger.LogDebug("Processing JKS data field '{Key}'", keyName);
                var keyPassword = ResolveStorePassword(context, client, k8sData.Secret);

                Pkcs12Store jStoreDs;
                var sourceIsPkcs12 = false;

                try
                {
                    jStoreDs = jksStore.DeserializeRemoteCertificateStore(keyBytes, keyName, keyPassword);
                }
                catch (JkSisPkcs12Exception)
                {
                    Logger.LogDebug("JKS data is actually PKCS12, using PKCS12 deserializer");
                    sourceIsPkcs12 = true;
                    var pkcs12Store = new Pkcs12CertificateStoreSerializer(_jobProperties);
                    jStoreDs = pkcs12Store.DeserializeRemoteCertificateStore(keyBytes, keyName, keyPassword);
                }

                var certAliasLookup = new Dictionary<string, string>();

                foreach (var certAlias in jStoreDs.Aliases)
                {
                    if (certAliasLookup.TryGetValue(certAlias, out var existingSubject) && existingSubject == "skip")
                    {
                        continue;
                    }

                    var certChainList = new List<string>();
                    var certChain = jStoreDs.GetCertificateChain(certAlias);

                    if (certChain != null)
                    {
                        certAliasLookup[certAlias] = certChain[0].Certificate.SubjectDN.ToString();

                        if (sourceIsPkcs12 && certChain.Length > 0)
                        {
                            var certChainSubjects = certChain.Skip(1)
                                .Select(cert => cert.Certificate.SubjectDN.ToString())
                                .ToList();

                            foreach (var alias in jStoreDs.Aliases)
                            {
                                if (alias != certAlias && certChainSubjects.Contains(alias))
                                {
                                    certAliasLookup[alias] = "skip";
                                }
                            }
                        }

                        certChainList = BuildCertificateChainPems(certChain);
                    }
                    else
                    {
                        certAliasLookup[certAlias] = "skip";
                    }

                    var fullAlias = $"{keyName}/{certAlias}";

                    if (certChainList.Count > 0)
                    {
                        jksInventoryDict[fullAlias] = certChainList;
                        continue;
                    }

                    // Try to get just the leaf certificate
                    var leaf = jStoreDs.GetCertificate(certAlias);
                    if (leaf != null)
                    {
                        certChainList.Add(ConvertToPem(leaf.Certificate));
                    }

                    if (certAliasLookup[certAlias] != "skip")
                    {
                        jksInventoryDict[fullAlias] = certChainList;
                    }
                }
            }

            Logger.LogDebug("JKS inventory complete with {Count} entries", jksInventoryDict.Count);
            LogOperationComplete("Inventory", context, true);
            return InventoryResult.SuccessWithChains(jksInventoryDict, true);
        }
        catch (StoreNotFoundException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error during JKS secret inventory: {Message}", ex.Message);
            return InventoryResult.Failure($"Error processing JKS secret: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public override JobResult ProcessAdd(SecretOperationContext context, K8SJobCertificate certificate, KubeCertificateManagerClient client)
    {
        LogOperationStart("Add", context);

        try
        {
            var jksStore = new JksCertificateStoreSerializer(_jobProperties);
            var k8sData = new KubeCertificateManagerClient.JksSecret();

            // Try to get existing secret
            try
            {
                k8sData = client.GetJksSecret(context.SecretName, context.Namespace);
            }
            catch (StoreNotFoundException)
            {
                Logger.LogDebug("JKS secret not found, will create new");
            }

            var newCertBytes = string.IsNullOrEmpty(certificate.CertB64)
                ? Array.Empty<byte>()
                : Convert.FromBase64String(certificate.CertB64);

            if (certificate.Pkcs12 != null && certificate.Pkcs12.Length > 0)
            {
                newCertBytes = certificate.Pkcs12;
            }

            var alias = string.IsNullOrEmpty(certificate.Alias) ? "default" : certificate.Alias;
            var existingDataFieldName = !string.IsNullOrEmpty(context.CertDataFieldName)
                ? context.CertDataFieldName
                : SecretFieldNames.DefaultJks;

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

            try
            {
                var newJksStore = jksStore.CreateOrUpdateJks(
                    newCertBytes,
                    certificate.Password,
                    alias,
                    existingData,
                    storePassword,
                    false,
                    context.IncludeCertChain);

                if (k8sData.Inventory == null || k8sData.Inventory.Count == 0)
                {
                    k8sData.Inventory = new Dictionary<string, byte[]>();
                }
                k8sData.Inventory[existingDataFieldName] = newJksStore;

                client.CreateOrUpdateJksSecret(k8sData, context.SecretName, context.Namespace);

                LogOperationComplete("Add", context, true);
                return SuccessJob(context.JobHistoryId);
            }
            catch (JkSisPkcs12Exception)
            {
                Logger.LogDebug("JKS data is actually PKCS12, delegating to PKCS12 handler");
                var pkcs12Handler = new Pkcs12SecretHandler(Logger, _jobProperties);
                return pkcs12Handler.ProcessAdd(context, certificate, client);
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error adding certificate to JKS secret: {Message}", ex.Message);
            return FailJob(ex.Message, context.JobHistoryId);
        }
    }

    /// <inheritdoc />
    public override JobResult ProcessRemove(SecretOperationContext context, string alias, KubeCertificateManagerClient client)
    {
        LogOperationStart("Remove", context);

        try
        {
            var jksStore = new JksCertificateStoreSerializer(_jobProperties);
            KubeCertificateManagerClient.JksSecret k8sData;

            try
            {
                k8sData = client.GetJksSecret(context.SecretName, context.Namespace);
            }
            catch (StoreNotFoundException)
            {
                Logger.LogWarning("JKS secret not found, nothing to remove");
                return SuccessJob(context.JobHistoryId, "Secret not found, nothing to remove");
            }

            var existingDataFieldName = !string.IsNullOrEmpty(context.CertDataFieldName)
                ? context.CertDataFieldName
                : SecretFieldNames.DefaultJks;
            var entryAlias = alias;

            if (alias != null && alias.Contains('/'))
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
                Logger.LogWarning("JKS field '{Field}' not found in secret", existingDataFieldName);
                return SuccessJob(context.JobHistoryId, $"Field '{existingDataFieldName}' not found, nothing to remove");
            }

            var storePassword = ResolveStorePassword(context, client, k8sData.Secret);

            try
            {
                var newJksStore = jksStore.CreateOrUpdateJks(
                    Array.Empty<byte>(),
                    null,
                    entryAlias,
                    existingData,
                    storePassword,
                    true,  // remove = true
                    false);

                k8sData.Inventory[existingDataFieldName] = newJksStore;
                client.CreateOrUpdateJksSecret(k8sData, context.SecretName, context.Namespace);

                LogOperationComplete("Remove", context, true);
                return SuccessJob(context.JobHistoryId);
            }
            catch (JkSisPkcs12Exception)
            {
                Logger.LogDebug("JKS data is actually PKCS12, delegating to PKCS12 handler");
                var pkcs12Handler = new Pkcs12SecretHandler(Logger, _jobProperties);
                return pkcs12Handler.ProcessRemove(context, alias, client);
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error removing certificate from JKS secret: {Message}", ex.Message);
            return FailJob(ex.Message, context.JobHistoryId);
        }
    }

    private string[] GetAllowedKeys(SecretOperationContext context)
    {
        if (!string.IsNullOrEmpty(context.CertDataFieldName))
        {
            return context.CertDataFieldName.Split(',')
                .Concat(AllowedKeys.JksKeys)
                .Distinct()
                .ToArray();
        }
        return AllowedKeys.JksKeys;
    }
}
