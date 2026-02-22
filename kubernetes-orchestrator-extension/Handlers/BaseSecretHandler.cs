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
using System.Threading;
using System.Threading.Tasks;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Constants;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Exceptions;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Abstract base class for secret handlers providing common functionality
/// for password retrieval, certificate chain extraction, and error handling.
/// </summary>
public abstract class BaseSecretHandler : ISecretHandler
{
    /// <summary>
    /// Logger for this handler.
    /// </summary>
    protected readonly ILogger Logger;

    /// <summary>
    /// Creates a new BaseSecretHandler.
    /// </summary>
    /// <param name="logger">Logger for this handler. If null, creates a default logger.</param>
    protected BaseSecretHandler(ILogger logger = null)
    {
        Logger = logger ?? LogHandler.GetClassLogger(GetType());
    }

    /// <inheritdoc />
    public abstract SecretType SupportedSecretType { get; }

    /// <inheritdoc />
    public virtual bool CanHandle(SecretType secretType)
    {
        return secretType == SupportedSecretType;
    }

    /// <inheritdoc />
    public abstract InventoryResult ProcessInventory(SecretOperationContext context, KubeCertificateManagerClient client);

    /// <inheritdoc />
    public abstract JobResult ProcessAdd(SecretOperationContext context, K8SJobCertificate certificate, KubeCertificateManagerClient client);

    /// <inheritdoc />
    public abstract JobResult ProcessRemove(SecretOperationContext context, string alias, KubeCertificateManagerClient client);

    /// <inheritdoc />
    public virtual Task<InventoryResult> ProcessInventoryAsync(
        SecretOperationContext context,
        KubeCertificateManagerClient client,
        CancellationToken cancellationToken = default)
    {
        // Default implementation wraps sync method
        // Derived classes can override for true async
        return Task.FromResult(ProcessInventory(context, client));
    }

    /// <inheritdoc />
    public virtual Task<JobResult> ProcessAddAsync(
        SecretOperationContext context,
        K8SJobCertificate certificate,
        KubeCertificateManagerClient client,
        CancellationToken cancellationToken = default)
    {
        // Default implementation wraps sync method
        return Task.FromResult(ProcessAdd(context, certificate, client));
    }

    /// <inheritdoc />
    public virtual Task<JobResult> ProcessRemoveAsync(
        SecretOperationContext context,
        string alias,
        KubeCertificateManagerClient client,
        CancellationToken cancellationToken = default)
    {
        // Default implementation wraps sync method
        return Task.FromResult(ProcessRemove(context, alias, client));
    }

    /// <summary>
    /// Retrieves the store password from the context or from a Kubernetes secret.
    /// </summary>
    /// <param name="context">The operation context.</param>
    /// <param name="client">The Kubernetes client.</param>
    /// <param name="existingSecret">Optional existing secret to extract password from.</param>
    /// <returns>The resolved password, or empty string if not found.</returns>
    protected string ResolveStorePassword(SecretOperationContext context, KubeCertificateManagerClient client, V1Secret existingSecret = null)
    {
        Logger.LogDebug("Resolving store password for {Namespace}/{SecretName}", context.Namespace, context.SecretName);

        // If password is directly provided and not a K8S secret reference
        if (!context.PasswordIsK8SSecret && !string.IsNullOrEmpty(context.StorePassword))
        {
            Logger.LogTrace("Using directly provided store password");
            return context.StorePassword.TrimEnd('\n', '\r');
        }

        // If password should be retrieved from a K8S secret
        if (context.PasswordIsK8SSecret && !string.IsNullOrEmpty(context.PasswordSecretPath))
        {
            return ResolvePasswordFromSecret(context, client);
        }

        // Try to get password from existing secret if provided
        if (existingSecret?.Data != null)
        {
            var passwordFieldName = string.IsNullOrEmpty(context.PasswordFieldName)
                ? SecretFieldNames.DefaultPassword
                : context.PasswordFieldName;

            if (existingSecret.Data.TryGetValue(passwordFieldName, out var passwordBytes))
            {
                var password = Encoding.UTF8.GetString(passwordBytes).TrimEnd('\n', '\r');
                Logger.LogTrace("Retrieved password from existing secret field '{FieldName}'", passwordFieldName);
                return password;
            }
        }

        // Fallback to context store password
        return context.StorePassword?.TrimEnd('\n', '\r') ?? string.Empty;
    }

    /// <summary>
    /// Retrieves a password from a separate Kubernetes secret.
    /// </summary>
    /// <param name="context">The operation context.</param>
    /// <param name="client">The Kubernetes client.</param>
    /// <returns>The password from the secret.</returns>
    /// <exception cref="PasswordRetrievalException">Thrown if the password cannot be retrieved.</exception>
    protected string ResolvePasswordFromSecret(SecretOperationContext context, KubeCertificateManagerClient client)
    {
        Logger.LogDebug("Retrieving password from K8S secret: {Path}", context.PasswordSecretPath);

        try
        {
            var pathParts = context.PasswordSecretPath.Split('/');
            string passwordNamespace;
            string passwordSecretName;

            if (pathParts.Length >= 2)
            {
                passwordNamespace = pathParts[0];
                passwordSecretName = pathParts[1];
            }
            else
            {
                passwordNamespace = context.Namespace;
                passwordSecretName = context.PasswordSecretPath;
            }

            var passwordSecret = client.GetCertificateStoreSecret(passwordSecretName, passwordNamespace);
            if (passwordSecret?.Data == null)
            {
                throw new PasswordRetrievalException(
                    $"Password secret '{passwordSecretName}' in namespace '{passwordNamespace}' is empty or not found.",
                    context.PasswordSecretPath);
            }

            var fieldName = string.IsNullOrEmpty(context.PasswordFieldName)
                ? SecretFieldNames.DefaultPassword
                : context.PasswordFieldName;

            if (!passwordSecret.Data.TryGetValue(fieldName, out var passwordBytes))
            {
                throw new PasswordRetrievalException(
                    $"Password field '{fieldName}' not found in secret '{passwordSecretName}'.",
                    context.PasswordSecretPath);
            }

            return Encoding.UTF8.GetString(passwordBytes).TrimEnd('\n', '\r');
        }
        catch (PasswordRetrievalException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new PasswordRetrievalException(
                $"Failed to retrieve password from secret: {ex.Message}",
                context.PasswordSecretPath,
                ex);
        }
    }

    /// <summary>
    /// Creates a successful JobResult.
    /// </summary>
    /// <param name="jobHistoryId">The job history ID.</param>
    /// <param name="message">Optional success message.</param>
    /// <returns>A success JobResult.</returns>
    protected JobResult SuccessJob(long jobHistoryId, string message = null)
    {
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Success,
            JobHistoryId = jobHistoryId,
            FailureMessage = message
        };
    }

    /// <summary>
    /// Creates a failed JobResult.
    /// </summary>
    /// <param name="errorMessage">The error message.</param>
    /// <param name="jobHistoryId">The job history ID.</param>
    /// <returns>A failure JobResult.</returns>
    protected JobResult FailJob(string errorMessage, long jobHistoryId)
    {
        Logger.LogError("Job failed: {ErrorMessage}", errorMessage);
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Failure,
            JobHistoryId = jobHistoryId,
            FailureMessage = errorMessage
        };
    }

    /// <summary>
    /// Creates a warning JobResult.
    /// </summary>
    /// <param name="warningMessage">The warning message.</param>
    /// <param name="jobHistoryId">The job history ID.</param>
    /// <returns>A warning JobResult.</returns>
    protected JobResult WarningJob(string warningMessage, long jobHistoryId)
    {
        Logger.LogWarning("Job completed with warning: {WarningMessage}", warningMessage);
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Warning,
            JobHistoryId = jobHistoryId,
            FailureMessage = warningMessage
        };
    }

    /// <summary>
    /// Converts a BouncyCastle certificate to PEM format.
    /// </summary>
    /// <param name="certificate">The certificate to convert.</param>
    /// <returns>PEM-formatted certificate string.</returns>
    protected string ConvertToPem(Org.BouncyCastle.X509.X509Certificate certificate)
    {
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN CERTIFICATE-----");
        sb.AppendLine(Convert.ToBase64String(certificate.GetEncoded()));
        sb.AppendLine("-----END CERTIFICATE-----");
        return sb.ToString();
    }

    /// <summary>
    /// Builds a list of PEM certificates from a certificate chain.
    /// </summary>
    /// <param name="chain">Array of certificate entries.</param>
    /// <returns>List of PEM-formatted certificates.</returns>
    protected List<string> BuildCertificateChainPems(Org.BouncyCastle.Pkcs.X509CertificateEntry[] chain)
    {
        if (chain == null || chain.Length == 0)
            return new List<string>();

        return chain.Select(entry => ConvertToPem(entry.Certificate)).ToList();
    }

    /// <summary>
    /// Logs the start of an operation.
    /// </summary>
    protected void LogOperationStart(string operation, SecretOperationContext context)
    {
        Logger.LogInformation("Starting {Operation} for {SecretType} secret {Namespace}/{SecretName}",
            operation, SupportedSecretType, context.Namespace, context.SecretName);
    }

    /// <summary>
    /// Logs the completion of an operation.
    /// </summary>
    protected void LogOperationComplete(string operation, SecretOperationContext context, bool success)
    {
        if (success)
        {
            Logger.LogInformation("Completed {Operation} for {SecretType} secret {Namespace}/{SecretName}",
                operation, SupportedSecretType, context.Namespace, context.SecretName);
        }
        else
        {
            Logger.LogWarning("Failed {Operation} for {SecretType} secret {Namespace}/{SecretName}",
                operation, SupportedSecretType, context.Namespace, context.SecretName);
        }
    }
}
