// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Services;

/// <summary>
/// Result of password resolution containing both byte array and string forms.
/// </summary>
public record PasswordResult(byte[] Bytes, string Value);

/// <summary>
/// Resolves keystore passwords from various sources (K8S secrets, direct values, or defaults).
/// Centralizes the password resolution logic used across PKCS12 and JKS operations.
/// </summary>
public class PasswordResolver
{
    private readonly ILogger _logger;

    /// <summary>
    /// Delegate for reading a "buddy" secret (a secret in a different namespace containing the password).
    /// </summary>
    public delegate k8s.Models.V1Secret BuddySecretReader(string secretName, string namespaceName);

    /// <summary>
    /// Initializes a new instance of the PasswordResolver.
    /// </summary>
    /// <param name="logger">Logger instance for diagnostic output.</param>
    public PasswordResolver(ILogger logger)
    {
        _logger = logger ?? LogHandler.GetClassLogger<PasswordResolver>();
    }

    /// <summary>
    /// Resolves the store password from the job certificate configuration.
    /// Supports three sources:
    /// 1. K8S secret (same secret or "buddy" secret in different namespace)
    /// 2. Direct password from job configuration
    /// 3. Default password
    /// </summary>
    /// <param name="jobCertificate">Job certificate containing password configuration.</param>
    /// <param name="defaultPassword">Default password to use if no other source is available.</param>
    /// <param name="existingSecretData">Data from the existing K8S secret (for same-secret passwords).</param>
    /// <param name="passwordFieldName">Name of the field containing the password.</param>
    /// <param name="buddySecretReader">Function to read a buddy secret from a different namespace.</param>
    /// <returns>PasswordResult containing the resolved password as bytes and string.</returns>
    public PasswordResult ResolveStorePassword(
        K8SJobCertificate jobCertificate,
        string defaultPassword,
        IDictionary<string, byte[]> existingSecretData = null,
        string passwordFieldName = "password",
        BuddySecretReader buddySecretReader = null)
    {
        _logger.LogDebug("Resolving store password");

        byte[] passwordBytes;
        string passwordString;

        if (jobCertificate.PasswordIsK8SSecret)
        {
            (passwordBytes, passwordString) = ResolveFromK8sSecret(
                jobCertificate,
                existingSecretData,
                passwordFieldName,
                buddySecretReader);
        }
        else if (!string.IsNullOrEmpty(jobCertificate.StorePassword))
        {
            _logger.LogDebug("Using password from job configuration");
            passwordBytes = Encoding.UTF8.GetBytes(jobCertificate.StorePassword);
            passwordString = jobCertificate.StorePassword;
        }
        else
        {
            _logger.LogDebug("Using default store password");
            passwordBytes = Encoding.UTF8.GetBytes(defaultPassword ?? "");
            passwordString = defaultPassword ?? "";
        }

        // Trim trailing newlines (common issue with kubectl-created secrets)
        passwordString = passwordString.TrimEnd('\r', '\n');
        passwordBytes = Encoding.UTF8.GetBytes(passwordString);

        _logger.LogTrace("Password: {Password}", LoggingUtilities.RedactPassword(passwordString));
        _logger.LogTrace("Password correlation: {CorrelationId}", LoggingUtilities.GetPasswordCorrelationId(passwordString));

        return new PasswordResult(passwordBytes, passwordString);
    }

    /// <summary>
    /// Resolves password from a K8S secret, either from the same secret or a buddy secret.
    /// </summary>
    private (byte[] bytes, string value) ResolveFromK8sSecret(
        K8SJobCertificate jobCertificate,
        IDictionary<string, byte[]> existingSecretData,
        string passwordFieldName,
        BuddySecretReader buddySecretReader)
    {
        byte[] passwordBytes;

        if (!string.IsNullOrEmpty(jobCertificate.StorePasswordPath))
        {
            // Password is in a separate "buddy" secret
            _logger.LogDebug("Password is stored in K8S secret at path: {Path}", jobCertificate.StorePasswordPath);

            var passwordPath = jobCertificate.StorePasswordPath.Split("/");
            if (passwordPath.Length < 2)
            {
                throw new InvalidOperationException(
                    $"Invalid StorePasswordPath format: '{jobCertificate.StorePasswordPath}'. Expected format: 'namespace/secretname' or 'secretname/namespace'");
            }

            var passwordNamespace = passwordPath.Length > 1 ? passwordPath[0] : "default";
            var passwordSecretName = passwordPath.Length > 1 ? passwordPath[1] : passwordPath[0];

            _logger.LogDebug("Buddy secret metadata - Name: {Name}, Namespace: {Namespace}, Field: {Field}",
                passwordSecretName, passwordNamespace, passwordFieldName);

            if (buddySecretReader == null)
            {
                throw new InvalidOperationException("BuddySecretReader is required when StorePasswordPath is specified");
            }

            var buddySecret = buddySecretReader(passwordSecretName, passwordNamespace);
            _logger.LogTrace("Buddy secret: {Summary}", LoggingUtilities.GetSecretSummary(buddySecret));

            if (buddySecret?.Data == null || !buddySecret.Data.ContainsKey(passwordFieldName))
            {
                throw new InvalidOperationException(
                    $"Password field '{passwordFieldName}' not found in buddy secret '{passwordSecretName}'");
            }

            passwordBytes = buddySecret.Data[passwordFieldName];
        }
        else
        {
            // Password is in the same secret
            _logger.LogDebug("Password is stored in same secret, field: {Field}", passwordFieldName);

            if (existingSecretData == null || !existingSecretData.ContainsKey(passwordFieldName))
            {
                throw new InvalidOperationException(
                    $"Password field '{passwordFieldName}' not found in existing secret data");
            }

            passwordBytes = existingSecretData[passwordFieldName];
        }

        var passwordString = Encoding.UTF8.GetString(passwordBytes);
        return (passwordBytes, passwordString);
    }
}
