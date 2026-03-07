// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Factory for creating store-type-specific secret handlers.
/// Maps normalized secret types to their corresponding handler implementations.
/// </summary>
public static class SecretHandlerFactory
{
    /// <summary>
    /// Creates a secret handler for the specified secret type.
    /// </summary>
    /// <param name="secretType">The secret type (will be normalized).</param>
    /// <param name="kubeClient">Kubernetes client for API operations.</param>
    /// <param name="logger">Logger for diagnostic output.</param>
    /// <param name="context">Operation context with configuration and job parameters.</param>
    /// <returns>An ISecretHandler implementation for the specified type.</returns>
    /// <exception cref="NotSupportedException">Thrown when the secret type is not supported.</exception>
    public static ISecretHandler Create(
        string secretType,
        KubeCertificateManagerClient kubeClient,
        ILogger logger,
        ISecretOperationContext context)
    {
        if (string.IsNullOrEmpty(secretType))
            throw new ArgumentNullException(nameof(secretType), "Secret type cannot be null or empty");

        var normalizedType = SecretTypes.Normalize(secretType);

        return normalizedType switch
        {
            SecretTypes.Tls => new TlsSecretHandler(kubeClient, logger, context),
            SecretTypes.Opaque => new OpaqueSecretHandler(kubeClient, logger, context),
            SecretTypes.Jks => new JksSecretHandler(kubeClient, logger, context),
            SecretTypes.Pkcs12 => new Pkcs12SecretHandler(kubeClient, logger, context),
            SecretTypes.Certificate => new CertificateSecretHandler(kubeClient, logger, context),
            SecretTypes.Cluster => new ClusterSecretHandler(kubeClient, logger, context),
            SecretTypes.Namespace => new NamespaceSecretHandler(kubeClient, logger, context),
            _ => throw new NotSupportedException($"Secret type '{secretType}' (normalized: '{normalizedType}') is not supported")
        };
    }

    /// <summary>
    /// Determines if a handler exists for the specified secret type.
    /// </summary>
    /// <param name="secretType">The secret type to check.</param>
    /// <returns>True if a handler exists for this type; otherwise, false.</returns>
    public static bool HasHandler(string secretType)
    {
        if (string.IsNullOrEmpty(secretType))
            return false;

        var normalizedType = SecretTypes.Normalize(secretType);

        return normalizedType is SecretTypes.Tls
            or SecretTypes.Opaque
            or SecretTypes.Jks
            or SecretTypes.Pkcs12
            or SecretTypes.Certificate
            or SecretTypes.Cluster
            or SecretTypes.Namespace;
    }

    /// <summary>
    /// Determines if the secret type supports management operations (add/remove).
    /// </summary>
    /// <param name="secretType">The secret type to check.</param>
    /// <returns>True if management operations are supported; otherwise, false.</returns>
    public static bool SupportsManagement(string secretType)
    {
        if (string.IsNullOrEmpty(secretType))
            return false;

        var normalizedType = SecretTypes.Normalize(secretType);

        // K8SCert (Certificate) is read-only - no management
        return normalizedType is not SecretTypes.Certificate;
    }

    /// <summary>
    /// Gets the handler type name for the specified secret type (for logging/debugging).
    /// </summary>
    /// <param name="secretType">The secret type.</param>
    /// <returns>The handler class name.</returns>
    public static string GetHandlerTypeName(string secretType)
    {
        var normalizedType = SecretTypes.Normalize(secretType);

        return normalizedType switch
        {
            SecretTypes.Tls => nameof(TlsSecretHandler),
            SecretTypes.Opaque => nameof(OpaqueSecretHandler),
            SecretTypes.Jks => nameof(JksSecretHandler),
            SecretTypes.Pkcs12 => nameof(Pkcs12SecretHandler),
            SecretTypes.Certificate => nameof(CertificateSecretHandler),
            SecretTypes.Cluster => nameof(ClusterSecretHandler),
            SecretTypes.Namespace => nameof(NamespaceSecretHandler),
            _ => $"Unknown({secretType})"
        };
    }
}
