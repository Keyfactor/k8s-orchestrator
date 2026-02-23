// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using k8s.Autorest;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Constants;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using StoreNotFoundException = Keyfactor.Extensions.Orchestrator.K8S.Exceptions.StoreNotFoundException;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Handler for Kubernetes Opaque secrets containing PEM certificates.
/// Supports multiple certificate field names and chain separation.
/// </summary>
public class OpaqueSecretHandler : BaseSecretHandler
{
    /// <summary>
    /// Creates a new OpaqueSecretHandler.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    public OpaqueSecretHandler(ILogger logger = null) : base(logger)
    {
    }

    /// <inheritdoc />
    public override SecretType SupportedSecretType => SecretType.Opaque;

    /// <inheritdoc />
    public override InventoryResult ProcessInventory(SecretOperationContext context, KubeCertificateManagerClient client)
    {
        LogOperationStart("Inventory", context);

        try
        {
            var ns = context.Namespace;
            var secretName = context.SecretName;

            if (string.IsNullOrEmpty(ns))
            {
                ns = "default";
                Logger.LogWarning("Namespace not specified, using 'default'");
            }

            Logger.LogDebug("Fetching Opaque secret {Namespace}/{SecretName}", ns, secretName);
            var secret = client.GetCertificateStoreSecret(secretName, ns);

            if (secret?.Data == null)
            {
                throw new StoreNotFoundException($"Opaque secret '{secretName}' not found or has no data in namespace '{ns}'");
            }

            var certsList = new List<string>();
            var hasPrivateKey = true; // Assume true for opaque secrets

            // Get allowed keys to search for certificate data
            var allowedKeys = GetAllowedKeys(context);

            foreach (var key in allowedKeys)
            {
                if (!secret.Data.ContainsKey(key))
                    continue;

                Logger.LogDebug("Found certificate data in field '{Key}'", key);
                var certBytes = secret.Data[key];
                var certData = Encoding.UTF8.GetString(certBytes);

                // Split certificates if comma-separated
                var splitCerts = certData.Split(',');
                foreach (var cert in splitCerts)
                {
                    if (!string.IsNullOrWhiteSpace(cert))
                    {
                        certsList.Add(cert.Trim());
                    }
                }
            }

            LogOperationComplete("Inventory", context, true);
            return InventoryResult.SuccessWithCertificates(certsList, hasPrivateKey);
        }
        catch (HttpOperationException ex) when (ex.Response?.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            Logger.LogWarning("Opaque secret not found: {Namespace}/{SecretName}", context.Namespace, context.SecretName);
            throw new StoreNotFoundException(
                $"Opaque secret '{context.SecretName}' not found in namespace '{context.Namespace}'");
        }
        catch (StoreNotFoundException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error during Opaque secret inventory: {Message}", ex.Message);
            return InventoryResult.Failure($"Error querying Kubernetes secret API: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public override JobResult ProcessAdd(SecretOperationContext context, K8SJobCertificate certificate, KubeCertificateManagerClient client)
    {
        LogOperationStart("Add", context);

        try
        {
            var certAlias = certificate.Alias;
            if (string.IsNullOrEmpty(certAlias))
            {
                certAlias = certificate.CertThumbprint;
            }

            // Handle empty certificate case (create empty secret)
            if (string.IsNullOrEmpty(certAlias) && string.IsNullOrEmpty(certificate.CertPem))
            {
                Logger.LogWarning("No certificate data provided, creating empty Opaque secret");
                client.CreateOrUpdateCertificateStoreSecret(
                    "", "", new List<string>(),
                    context.SecretName, context.Namespace,
                    "secret", false, true);

                return SuccessJob(context.JobHistoryId);
            }

            Logger.LogDebug("Adding certificate {Alias} to Opaque secret {Namespace}/{SecretName}",
                certAlias, context.Namespace, context.SecretName);

            Logger.LogDebug("Certificate metadata - SeparateChain: {SeparateChain}, IncludeCertChain: {IncludeCertChain}",
                context.SeparateChain, context.IncludeCertChain);

            var response = client.CreateOrUpdateCertificateStoreSecret(
                certificate.PrivateKeyPem,
                certificate.CertPem,
                certificate.ChainPem,
                context.SecretName,
                context.Namespace,
                "secret",
                context.Append,
                context.Overwrite,
                false,
                context.SeparateChain,
                context.IncludeCertChain);

            if (response == null)
            {
                return FailJob($"Failed to create or update Opaque secret '{context.SecretName}'", context.JobHistoryId);
            }

            Logger.LogInformation("Successfully created or updated secret '{SecretName}' in namespace '{Namespace}'",
                context.SecretName, context.Namespace);

            LogOperationComplete("Add", context, true);
            return SuccessJob(context.JobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error adding certificate to Opaque secret: {Message}", ex.Message);
            return FailJob(ex.Message, context.JobHistoryId);
        }
    }

    /// <inheritdoc />
    public override JobResult ProcessRemove(SecretOperationContext context, string alias, KubeCertificateManagerClient client)
    {
        LogOperationStart("Remove", context);

        try
        {
            Logger.LogDebug("Removing Opaque secret {Namespace}/{SecretName}", context.Namespace, context.SecretName);

            client.DeleteCertificateStoreSecret(
                context.SecretName,
                context.Namespace,
                "secret",
                alias);

            LogOperationComplete("Remove", context, true);
            return SuccessJob(context.JobHistoryId);
        }
        catch (HttpOperationException ex) when (ex.Message.Contains("NotFound"))
        {
            Logger.LogWarning("Opaque secret not found, nothing to remove: {Namespace}/{SecretName}",
                context.Namespace, context.SecretName);
            return SuccessJob(context.JobHistoryId,
                $"Secret '{context.SecretName}' was not found in namespace '{context.Namespace}'. Delete not necessary.");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error removing Opaque secret: {Message}", ex.Message);
            return FailJob(ex.Message, context.JobHistoryId);
        }
    }

    /// <summary>
    /// Gets the list of allowed keys to search for certificate data.
    /// </summary>
    private string[] GetAllowedKeys(SecretOperationContext context)
    {
        if (!string.IsNullOrEmpty(context.CertDataFieldName))
        {
            return context.CertDataFieldName.Split(',');
        }

        return AllowedKeys.OpaqueKeys;
    }
}
