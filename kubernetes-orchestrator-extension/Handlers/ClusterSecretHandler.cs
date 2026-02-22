// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Constants;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Exceptions;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Handler for cluster-wide secret operations (K8SCluster store type).
/// Manages all Opaque and TLS secrets across all namespaces in a cluster.
/// </summary>
public class ClusterSecretHandler : BaseSecretHandler
{
    private readonly TlsSecretHandler _tlsHandler;
    private readonly OpaqueSecretHandler _opaqueHandler;

    /// <summary>
    /// Creates a new ClusterSecretHandler.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    public ClusterSecretHandler(ILogger logger = null) : base(logger)
    {
        _tlsHandler = new TlsSecretHandler(logger);
        _opaqueHandler = new OpaqueSecretHandler(logger);
    }

    /// <inheritdoc />
    public override SecretType SupportedSecretType => SecretType.Cluster;

    /// <inheritdoc />
    public override InventoryResult ProcessInventory(SecretOperationContext context, KubeCertificateManagerClient client)
    {
        LogOperationStart("Inventory", context);

        try
        {
            var clusterInventoryDict = new Dictionary<string, List<string>>();
            var errors = new List<string>();

            // Discover and process all Opaque secrets
            var opaqueSecrets = client.DiscoverSecrets(AllowedKeys.OpaqueKeys, "Opaque", "all");
            foreach (var secretPath in opaqueSecrets)
            {
                try
                {
                    var secretContext = ParseSecretPath(secretPath, context, SecretType.Opaque);
                    var result = _opaqueHandler.ProcessInventory(secretContext, client);

                    if (result.Success && result.Certificates.Count > 0)
                    {
                        var storePath = BuildStorePath(secretContext, "opaque");
                        clusterInventoryDict[storePath] = result.Certificates;
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogError("Error processing Opaque secret {Path}: {Error}", secretPath, ex.Message);
                    errors.Add(ex.Message);
                }
            }

            // Discover and process all TLS secrets
            var tlsSecrets = client.DiscoverSecrets(AllowedKeys.TlsKeys, "tls", "all");
            foreach (var secretPath in tlsSecrets)
            {
                try
                {
                    var secretContext = ParseSecretPath(secretPath, context, SecretType.Tls);
                    var result = _tlsHandler.ProcessInventory(secretContext, client);

                    if (result.Success && result.Certificates.Count > 0)
                    {
                        var storePath = BuildStorePath(secretContext, "tls");
                        clusterInventoryDict[storePath] = result.Certificates;
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogError("Error processing TLS secret {Path}: {Error}", secretPath, ex.Message);
                    errors.Add(ex.Message);
                }
            }

            LogOperationComplete("Inventory", context, true);
            return InventoryResult.SuccessWithChains(clusterInventoryDict, true);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error during cluster inventory: {Message}", ex.Message);
            return InventoryResult.Failure($"Error during cluster inventory: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public override JobResult ProcessAdd(SecretOperationContext context, K8SJobCertificate certificate, KubeCertificateManagerClient client)
    {
        LogOperationStart("Add", context);

        try
        {
            var alias = certificate.Alias;
            if (string.IsNullOrEmpty(alias))
            {
                return FailJob("Certificate alias is required for K8SCluster store type. Expected format: '<namespace>/secrets/<tls|opaque>/<secret_name>'", context.JobHistoryId);
            }

            // Parse alias: namespace/secrets/type/secret_name
            var aliasParts = alias.Split('/');
            if (aliasParts.Length < 4)
            {
                return FailJob($"Invalid alias format for K8SCluster store type. Expected pattern: '<namespace>/secrets/<tls|opaque>/<secret_name>' but got '{alias}'", context.JobHistoryId);
            }

            var secretContext = context.Clone();
            secretContext.Namespace = aliasParts[0];
            secretContext.SecretName = aliasParts[^1];
            var secretTypeStr = aliasParts[^2];

            ISecretHandler handler = secretTypeStr.ToLowerInvariant() switch
            {
                "tls" => _tlsHandler,
                "opaque" => _opaqueHandler,
                _ => throw new UnsupportedStoreTypeException(secretTypeStr, "Add")
            };

            return handler.ProcessAdd(secretContext, certificate, client);
        }
        catch (UnsupportedStoreTypeException ex)
        {
            return FailJob(ex.Message, context.JobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error adding certificate to cluster: {Message}", ex.Message);
            return FailJob(ex.Message, context.JobHistoryId);
        }
    }

    /// <inheritdoc />
    public override JobResult ProcessRemove(SecretOperationContext context, string alias, KubeCertificateManagerClient client)
    {
        LogOperationStart("Remove", context);

        try
        {
            if (string.IsNullOrEmpty(alias))
            {
                return FailJob("Certificate alias is required for K8SCluster store type", context.JobHistoryId);
            }

            // Parse alias: namespace/secrets/type/secret_name
            var aliasParts = alias.Split('/');
            if (aliasParts.Length < 4)
            {
                return FailJob($"Invalid alias format for K8SCluster store type. Expected pattern: '<namespace>/secrets/<tls|opaque>/<secret_name>' but got '{alias}'", context.JobHistoryId);
            }

            var secretContext = context.Clone();
            secretContext.Namespace = aliasParts[0];
            secretContext.SecretName = aliasParts[^1];
            var secretTypeStr = aliasParts[^2];

            ISecretHandler handler = secretTypeStr.ToLowerInvariant() switch
            {
                "tls" => _tlsHandler,
                "opaque" => _opaqueHandler,
                _ => throw new UnsupportedStoreTypeException(secretTypeStr, "Remove")
            };

            return handler.ProcessRemove(secretContext, alias, client);
        }
        catch (UnsupportedStoreTypeException ex)
        {
            return FailJob(ex.Message, context.JobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error removing certificate from cluster: {Message}", ex.Message);
            return FailJob(ex.Message, context.JobHistoryId);
        }
    }

    private SecretOperationContext ParseSecretPath(string path, SecretOperationContext baseContext, SecretType secretType)
    {
        var parts = path.Split('/');
        var context = baseContext.Clone();
        context.SecretType = secretType;

        if (parts.Length >= 2)
        {
            context.Namespace = parts[0];
            context.SecretName = parts[^1];
        }
        else
        {
            context.SecretName = path;
        }

        return context;
    }

    private string BuildStorePath(SecretOperationContext context, string secretType)
    {
        return $"{context.Namespace}/secrets/{secretType}/{context.SecretName}";
    }
}
