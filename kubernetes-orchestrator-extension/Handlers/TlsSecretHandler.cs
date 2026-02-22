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
using StoreNotFoundException = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreNotFoundException;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Handler for kubernetes.io/tls type secrets.
/// Manages TLS certificates with standard tls.crt and tls.key fields.
/// </summary>
public class TlsSecretHandler : BaseSecretHandler
{
    /// <summary>
    /// Creates a new TlsSecretHandler.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    public TlsSecretHandler(ILogger logger = null) : base(logger)
    {
    }

    /// <inheritdoc />
    public override SecretType SupportedSecretType => SecretType.Tls;

    /// <inheritdoc />
    public override InventoryResult ProcessInventory(SecretOperationContext context, KubeCertificateManagerClient client)
    {
        LogOperationStart("Inventory", context);

        try
        {
            // Ensure namespace and secret name are set
            var ns = context.Namespace;
            var secretName = context.SecretName;

            if (string.IsNullOrEmpty(ns))
            {
                ns = "default";
                Logger.LogWarning("Namespace not specified, using 'default'");
            }

            Logger.LogDebug("Fetching TLS secret {Namespace}/{SecretName}", ns, secretName);
            var secret = client.GetCertificateStoreSecret(secretName, ns);

            if (secret?.Data == null)
            {
                throw new StoreNotFoundException($"TLS secret '{secretName}' not found or has no data in namespace '{ns}'");
            }

            var certsList = new List<string>();
            var hasPrivateKey = false;

            // Extract certificate from tls.crt
            if (secret.Data.TryGetValue(SecretFieldNames.TlsCrt, out var certBytes))
            {
                var certPem = Encoding.UTF8.GetString(certBytes);
                var certObj = client.ReadPemCertificate(certPem);

                if (certObj == null)
                {
                    Logger.LogDebug("Failed to parse as PEM, trying DER format");
                    certObj = client.ReadDerCertificate(certPem);
                }

                if (certObj != null)
                {
                    certPem = client.ConvertToPem(certObj);
                    if (!string.IsNullOrEmpty(certPem))
                    {
                        certsList.Add(certPem);
                    }
                }
            }

            // Check for CA certificate
            if (secret.Data.TryGetValue(SecretFieldNames.CaCrt, out var caBytes))
            {
                var caPem = Encoding.UTF8.GetString(caBytes);
                var caObj = client.ReadPemCertificate(caPem);

                if (caObj == null)
                {
                    caObj = client.ReadDerCertificate(caPem);
                }

                if (caObj != null)
                {
                    var caPemConverted = client.ConvertToPem(caObj);
                    if (!string.IsNullOrEmpty(caPemConverted))
                    {
                        certsList.Add(caPemConverted);
                    }
                }
            }
            else
            {
                // Check if certificate chain is embedded in tls.crt
                if (secret.Data.TryGetValue(SecretFieldNames.TlsCrt, out var chainBytes))
                {
                    var certChain = client.LoadCertificateChain(Encoding.UTF8.GetString(chainBytes));
                    if (certChain != null && certChain.Count > 1)
                    {
                        certsList.Clear();
                        foreach (var cert in certChain)
                        {
                            certsList.Add(client.ConvertToPem(cert));
                        }
                    }
                }
            }

            // Check for private key
            hasPrivateKey = secret.Data.ContainsKey(SecretFieldNames.TlsKey) &&
                            secret.Data[SecretFieldNames.TlsKey]?.Length > 0;

            LogOperationComplete("Inventory", context, true);
            return InventoryResult.SuccessWithCertificates(certsList, hasPrivateKey);
        }
        catch (HttpOperationException ex) when (ex.Response?.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            Logger.LogWarning("TLS secret not found: {Namespace}/{SecretName}", context.Namespace, context.SecretName);
            throw new StoreNotFoundException(
                $"TLS secret '{context.SecretName}' not found in namespace '{context.Namespace}'");
        }
        catch (StoreNotFoundException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error during TLS secret inventory: {Message}", ex.Message);
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
                Logger.LogWarning("No certificate data provided, creating empty TLS secret");
                client.CreateOrUpdateCertificateStoreSecret(
                    "", "", new List<string>(),
                    context.SecretName, context.Namespace,
                    "tls_secret", false, true);

                return SuccessJob(context.JobHistoryId);
            }

            Logger.LogDebug("Adding certificate {Alias} to TLS secret {Namespace}/{SecretName}",
                certAlias, context.Namespace, context.SecretName);

            var response = client.CreateOrUpdateCertificateStoreSecret(
                certificate.PrivateKeyPem,
                certificate.CertPem,
                certificate.ChainPem,
                context.SecretName,
                context.Namespace,
                "tls_secret",
                context.Append,
                context.Overwrite,
                false,
                context.SeparateChain,
                context.IncludeCertChain);

            if (response == null)
            {
                return FailJob($"Failed to create or update TLS secret '{context.SecretName}'", context.JobHistoryId);
            }

            LogOperationComplete("Add", context, true);
            return SuccessJob(context.JobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error adding certificate to TLS secret: {Message}", ex.Message);
            return FailJob(ex.Message, context.JobHistoryId);
        }
    }

    /// <inheritdoc />
    public override JobResult ProcessRemove(SecretOperationContext context, string alias, KubeCertificateManagerClient client)
    {
        LogOperationStart("Remove", context);

        try
        {
            Logger.LogDebug("Removing TLS secret {Namespace}/{SecretName}", context.Namespace, context.SecretName);

            var response = client.DeleteCertificateStoreSecret(
                context.SecretName,
                context.Namespace,
                "tls_secret",
                alias);

            LogOperationComplete("Remove", context, true);
            return SuccessJob(context.JobHistoryId);
        }
        catch (HttpOperationException ex) when (ex.Message.Contains("NotFound"))
        {
            Logger.LogWarning("TLS secret not found, nothing to remove: {Namespace}/{SecretName}",
                context.Namespace, context.SecretName);
            return SuccessJob(context.JobHistoryId,
                $"Secret '{context.SecretName}' was not found in namespace '{context.Namespace}'. Delete not necessary.");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error removing TLS secret: {Message}", ex.Message);
            return FailJob(ex.Message, context.JobHistoryId);
        }
    }
}
