// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
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
    private static readonly Dictionary<string, Func<KubeCertificateManagerClient, ILogger, ISecretOperationContext, ISecretHandler>> _factories = new()
    {
        [SecretTypes.Tls]         = (c, l, ctx) => new TlsSecretHandler(c, l, ctx),
        [SecretTypes.Opaque]      = (c, l, ctx) => new OpaqueSecretHandler(c, l, ctx),
        [SecretTypes.Jks]         = (c, l, ctx) => new JksSecretHandler(c, l, ctx),
        [SecretTypes.Pkcs12]      = (c, l, ctx) => new Pkcs12SecretHandler(c, l, ctx),
        [SecretTypes.Certificate] = (c, l, ctx) => new CertificateSecretHandler(c, l, ctx),
        [SecretTypes.Cluster]     = (c, l, ctx) => new ClusterSecretHandler(c, l, ctx),
        [SecretTypes.Namespace]   = (c, l, ctx) => new NamespaceSecretHandler(c, l, ctx),
    };

    private static readonly Dictionary<string, string> _handlerTypeNames = new()
    {
        [SecretTypes.Tls]         = nameof(TlsSecretHandler),
        [SecretTypes.Opaque]      = nameof(OpaqueSecretHandler),
        [SecretTypes.Jks]         = nameof(JksSecretHandler),
        [SecretTypes.Pkcs12]      = nameof(Pkcs12SecretHandler),
        [SecretTypes.Certificate] = nameof(CertificateSecretHandler),
        [SecretTypes.Cluster]     = nameof(ClusterSecretHandler),
        [SecretTypes.Namespace]   = nameof(NamespaceSecretHandler),
    };

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
        if (_factories.TryGetValue(normalizedType, out var factory))
            return factory(kubeClient, logger, context);

        throw new NotSupportedException($"Secret type '{secretType}' (normalized: '{normalizedType}') is not supported");
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

        return _factories.ContainsKey(SecretTypes.Normalize(secretType));
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

        // K8SCert (Certificate) is read-only - no management
        return SecretTypes.Normalize(secretType) is not SecretTypes.Certificate;
    }

    /// <summary>
    /// Gets the handler type name for the specified secret type (for logging/debugging).
    /// </summary>
    /// <param name="secretType">The secret type.</param>
    /// <returns>The handler class name.</returns>
    public static string GetHandlerTypeName(string secretType)
    {
        var normalizedType = SecretTypes.Normalize(secretType);
        return _handlerTypeNames.TryGetValue(normalizedType, out var name)
            ? name
            : $"Unknown({secretType})";
    }
}
