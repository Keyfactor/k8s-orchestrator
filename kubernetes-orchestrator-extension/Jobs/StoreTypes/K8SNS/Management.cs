// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SNS;

/// <summary>
/// Management job for namespace-level certificate operations.
/// Handles Add and Remove operations within a single namespace using alias-based routing.
/// </summary>
/// <remarks>
/// Alias format: secrets/[tls|opaque]/secret_name
/// Example: secrets/tls/my-cert
/// </remarks>
public class Management : ManagementBase
{
    /// <summary>
    /// Creates a new namespace management job with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    public Management(IPAMSecretResolver resolver) : base(resolver)
    {
    }

    /// <inheritdoc />
    protected override SecretType GetSecretType() => SecretType.Namespace;

    /// <inheritdoc />
    protected override StoreType GetStoreType() => StoreType.K8SNS;

    /// <inheritdoc />
    protected override JobResult ProcessAdd(
        ManagementJobConfiguration config,
        SecretOperationContext context,
        ISecretHandler handler)
    {
        // Parse alias to extract secret type and secret name
        // Format: secrets/[tls|opaque]/secret_name
        var alias = config.JobCertificate?.Alias;
        if (string.IsNullOrEmpty(alias))
        {
            return FailJob("Alias is required for K8SNS management operations", config.JobHistoryId);
        }

        var parts = alias.Split('/');
        if (parts.Length < 3)
        {
            return FailJob(
                $"Invalid alias format for K8SNS. Expected: 'secrets/<tls|opaque>/<secret_name>' but got '{alias}'",
                config.JobHistoryId);
        }

        // Namespace comes from the store path
        if (string.IsNullOrEmpty(context.Namespace))
        {
            context.Namespace = context.StorePath;
        }

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
            return FailJob($"Unsupported secret type '{secretTypeStr}' in alias. Expected 'tls' or 'opaque'.", config.JobHistoryId);
        }

        Logger.LogDebug("Namespace Add: Namespace={Namespace}, SecretType={SecretType}, SecretName={SecretName}",
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
        // Parse alias to extract secret type and secret name
        var alias = config.JobCertificate?.Alias;
        if (string.IsNullOrEmpty(alias))
        {
            return FailJob("Alias is required for K8SNS remove operations", config.JobHistoryId);
        }

        var parts = alias.Split('/');
        if (parts.Length < 3)
        {
            return FailJob(
                $"Invalid alias format for K8SNS. Expected: 'secrets/<tls|opaque>/<secret_name>' but got '{alias}'",
                config.JobHistoryId);
        }

        // Namespace comes from the store path
        if (string.IsNullOrEmpty(context.Namespace))
        {
            context.Namespace = context.StorePath;
        }

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

        Logger.LogDebug("Namespace Remove: Namespace={Namespace}, SecretType={SecretType}, SecretName={SecretName}",
            context.Namespace, actualSecretType, context.SecretName);

        // Get the appropriate handler and process
        var actualHandler = GetHandler(actualSecretType);
        return actualHandler.ProcessRemove(context, alias, KubeClient);
    }
}
