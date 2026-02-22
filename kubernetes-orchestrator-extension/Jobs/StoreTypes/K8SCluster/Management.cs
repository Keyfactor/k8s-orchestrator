// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SCluster;

/// <summary>
/// Management job for cluster-wide certificate operations.
/// Handles Add and Remove operations across namespaces using alias-based routing.
/// </summary>
/// <remarks>
/// Alias format: namespace/secrets/[tls|opaque]/secret_name
/// Example: default/secrets/tls/my-cert
/// </remarks>
public class Management : ManagementBase
{
    /// <summary>
    /// Creates a new cluster management job with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    public Management(IPAMSecretResolver resolver) : base(resolver)
    {
    }

    /// <inheritdoc />
    protected override SecretType GetSecretType() => SecretType.Cluster;

    /// <inheritdoc />
    protected override StoreType GetStoreType() => StoreType.K8SCluster;

    /// <inheritdoc />
    protected override JobResult ProcessAdd(
        ManagementJobConfiguration config,
        SecretOperationContext context,
        ISecretHandler handler)
    {
        // Parse alias to extract namespace, secret type, and secret name
        // Format: namespace/secrets/[tls|opaque]/secret_name
        var alias = config.JobCertificate?.Alias;
        if (string.IsNullOrEmpty(alias))
        {
            return FailJob("Alias is required for K8SCluster management operations", config.JobHistoryId);
        }

        var parts = alias.Split('/');
        if (parts.Length < 4)
        {
            return FailJob(
                $"Invalid alias format for K8SCluster. Expected: '<namespace>/secrets/<tls|opaque>/<secret_name>' but got '{alias}'",
                config.JobHistoryId);
        }

        // Update context with parsed values
        context.Namespace = parts[0];
        context.SecretName = parts[^1];
        var secretTypeStr = parts[^2];

        // Determine actual secret type from alias
        var actualSecretType = secretTypeStr.ToLower() switch
        {
            "tls" => SecretType.Tls,
            "opaque" => SecretType.Opaque,
            _ => SecretType.Unknown
        };

        if (actualSecretType == SecretType.Unknown)
        {
            return FailJob($"Unsupported secret type '{secretTypeStr}' in alias", config.JobHistoryId);
        }

        Logger.LogDebug("Cluster Add: Namespace={Namespace}, SecretType={SecretType}, SecretName={SecretName}",
            context.Namespace, actualSecretType, context.SecretName);

        // Get the appropriate handler and process
        var actualHandler = GetHandler(actualSecretType);
        var certificate = ParseJobCertificate(config);
        if (certificate == null && !string.IsNullOrEmpty(config.JobCertificate?.Contents))
        {
            return FailJob("Failed to parse certificate from job configuration", config.JobHistoryId);
        }

        certificate ??= new K8SJobCertificate { Alias = config.JobCertificate?.Alias };

        return actualHandler.ProcessAdd(context, certificate, KubeClient);
    }

    /// <inheritdoc />
    protected override JobResult ProcessRemove(
        ManagementJobConfiguration config,
        SecretOperationContext context,
        ISecretHandler handler)
    {
        // Parse alias to extract namespace, secret type, and secret name
        var alias = config.JobCertificate?.Alias;
        if (string.IsNullOrEmpty(alias))
        {
            return FailJob("Alias is required for K8SCluster remove operations", config.JobHistoryId);
        }

        var parts = alias.Split('/');
        if (parts.Length < 4)
        {
            return FailJob(
                $"Invalid alias format for K8SCluster. Expected: '<namespace>/secrets/<tls|opaque>/<secret_name>' but got '{alias}'",
                config.JobHistoryId);
        }

        // Update context with parsed values
        context.Namespace = parts[0];
        context.SecretName = parts[^1];
        var secretTypeStr = parts[^2];

        // Determine actual secret type from alias
        var actualSecretType = secretTypeStr.ToLower() switch
        {
            "tls" => SecretType.Tls,
            "opaque" => SecretType.Opaque,
            _ => SecretType.Unknown
        };

        if (actualSecretType == SecretType.Unknown)
        {
            return FailJob($"Unsupported secret type '{secretTypeStr}' in alias", config.JobHistoryId);
        }

        Logger.LogDebug("Cluster Remove: Namespace={Namespace}, SecretType={SecretType}, SecretName={SecretName}",
            context.Namespace, actualSecretType, context.SecretName);

        // Get the appropriate handler and process
        var actualHandler = GetHandler(actualSecretType);
        return actualHandler.ProcessRemove(context, alias, KubeClient);
    }
}
