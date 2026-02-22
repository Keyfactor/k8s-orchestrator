// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Text;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Constants;
using Keyfactor.Extensions.Orchestrator.K8S.Exceptions;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Services;

/// <summary>
/// Service for resolving and retrieving credentials from various sources.
/// Handles PAM resolution, kubeconfig parsing, and password retrieval from K8S secrets.
/// </summary>
public class CredentialResolver
{
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new CredentialResolver.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    public CredentialResolver(ILogger logger = null)
    {
        _logger = logger ?? LogHandler.GetClassLogger(typeof(CredentialResolver));
    }

    /// <summary>
    /// Resolves a store password from the operation context.
    /// Handles direct passwords, passwords from K8S secrets, and password field resolution.
    /// </summary>
    /// <param name="context">The operation context containing password configuration.</param>
    /// <param name="client">The Kubernetes client for secret retrieval.</param>
    /// <param name="existingSecret">Optional existing secret that may contain the password.</param>
    /// <returns>The resolved password string.</returns>
    /// <exception cref="PasswordRetrievalException">Thrown when password cannot be retrieved.</exception>
    public string ResolvePassword(
        SecretOperationContext context,
        KubeCertificateManagerClient client,
        V1Secret existingSecret = null)
    {
        _logger.LogDebug("Resolving password for {Namespace}/{SecretName}",
            context.Namespace, context.SecretName);

        // If password is directly provided and not a K8S secret reference
        if (!context.PasswordIsK8SSecret && !string.IsNullOrEmpty(context.StorePassword))
        {
            _logger.LogTrace("Using directly provided store password");
            return NormalizePassword(context.StorePassword);
        }

        // If password should be retrieved from a K8S secret
        if (context.PasswordIsK8SSecret && !string.IsNullOrEmpty(context.PasswordSecretPath))
        {
            return ResolvePasswordFromSecret(context, client);
        }

        // Try to get password from existing secret if provided
        if (existingSecret?.Data != null)
        {
            var passwordFieldName = GetPasswordFieldName(context);

            if (existingSecret.Data.TryGetValue(passwordFieldName, out var passwordBytes))
            {
                var password = Encoding.UTF8.GetString(passwordBytes);
                _logger.LogTrace("Retrieved password from existing secret field '{FieldName}'", passwordFieldName);
                return NormalizePassword(password);
            }
        }

        // Fallback to context store password
        return NormalizePassword(context.StorePassword ?? string.Empty);
    }

    /// <summary>
    /// Retrieves a password from a separate Kubernetes secret.
    /// </summary>
    /// <param name="context">The operation context.</param>
    /// <param name="client">The Kubernetes client.</param>
    /// <returns>The password from the secret.</returns>
    /// <exception cref="PasswordRetrievalException">Thrown if the password cannot be retrieved.</exception>
    public string ResolvePasswordFromSecret(SecretOperationContext context, KubeCertificateManagerClient client)
    {
        _logger.LogDebug("Retrieving password from K8S secret: {Path}", context.PasswordSecretPath);

        try
        {
            var (passwordNamespace, passwordSecretName) = ParsePasswordPath(
                context.PasswordSecretPath,
                context.Namespace);

            var passwordSecret = client.GetCertificateStoreSecret(passwordSecretName, passwordNamespace);
            if (passwordSecret?.Data == null)
            {
                throw new PasswordRetrievalException(
                    $"Password secret '{passwordSecretName}' in namespace '{passwordNamespace}' is empty or not found.",
                    context.PasswordSecretPath);
            }

            var fieldName = GetPasswordFieldName(context);

            if (!passwordSecret.Data.TryGetValue(fieldName, out var passwordBytes))
            {
                throw new PasswordRetrievalException(
                    $"Password field '{fieldName}' not found in secret '{passwordSecretName}'.",
                    context.PasswordSecretPath);
            }

            return NormalizePassword(Encoding.UTF8.GetString(passwordBytes));
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
    /// Parses a password path into namespace and secret name components.
    /// </summary>
    /// <param name="path">The password path (e.g., "namespace/secret-name" or "secret-name").</param>
    /// <param name="defaultNamespace">The default namespace if not specified in path.</param>
    /// <returns>Tuple of (namespace, secretName).</returns>
    public (string Namespace, string SecretName) ParsePasswordPath(string path, string defaultNamespace)
    {
        if (string.IsNullOrEmpty(path))
        {
            return (defaultNamespace, string.Empty);
        }

        var parts = path.Split('/');
        if (parts.Length >= 2)
        {
            return (parts[0], parts[1]);
        }

        return (defaultNamespace, path);
    }

    /// <summary>
    /// Gets the password field name from context, with fallback to default.
    /// </summary>
    /// <param name="context">The operation context.</param>
    /// <returns>The password field name.</returns>
    public string GetPasswordFieldName(SecretOperationContext context)
    {
        return string.IsNullOrEmpty(context.PasswordFieldName)
            ? SecretFieldNames.DefaultPassword
            : context.PasswordFieldName;
    }

    /// <summary>
    /// Normalizes a password by trimming trailing newlines.
    /// This handles a common issue with kubectl-created secrets.
    /// </summary>
    /// <param name="password">The raw password string.</param>
    /// <returns>The normalized password.</returns>
    public string NormalizePassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            return string.Empty;

        return password.TrimEnd('\n', '\r');
    }

    /// <summary>
    /// Validates that credentials are properly configured for an operation.
    /// </summary>
    /// <param name="context">The operation context to validate.</param>
    /// <returns>True if credentials are valid; otherwise, false.</returns>
    public bool ValidateCredentials(SecretOperationContext context)
    {
        // For password-protected stores, validate password configuration
        if (context.PasswordIsK8SSecret)
        {
            if (string.IsNullOrEmpty(context.PasswordSecretPath))
            {
                _logger.LogWarning("Password is configured as K8S secret but no path is provided");
                return false;
            }
        }

        return true;
    }
}
