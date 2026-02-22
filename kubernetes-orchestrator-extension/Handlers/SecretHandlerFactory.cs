// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Exceptions;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Factory for creating and retrieving the appropriate ISecretHandler based on secret or store type.
/// Centralizes handler registration and retrieval, replacing switch statements throughout the codebase.
/// </summary>
public class SecretHandlerFactory
{
    private readonly Dictionary<SecretType, ISecretHandler> _handlers;
    private readonly ILogger _logger;
    private readonly string _jobProperties;

    /// <summary>
    /// Creates a new SecretHandlerFactory with default handlers.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    /// <param name="jobProperties">Optional job properties JSON for serializer configuration.</param>
    public SecretHandlerFactory(ILogger logger = null, string jobProperties = null)
    {
        _logger = logger ?? LogHandler.GetClassLogger(typeof(SecretHandlerFactory));
        _jobProperties = jobProperties;
        _handlers = new Dictionary<SecretType, ISecretHandler>();

        RegisterDefaultHandlers();
    }

    /// <summary>
    /// Registers all default handlers.
    /// </summary>
    private void RegisterDefaultHandlers()
    {
        RegisterHandler(new TlsSecretHandler(_logger));
        RegisterHandler(new OpaqueSecretHandler(_logger));
        RegisterHandler(new CertificateSecretHandler(_logger));
        RegisterHandler(new JksSecretHandler(_logger, _jobProperties));
        RegisterHandler(new Pkcs12SecretHandler(_logger, _jobProperties));
        RegisterHandler(new ClusterSecretHandler(_logger));
        RegisterHandler(new NamespaceSecretHandler(_logger));
    }

    /// <summary>
    /// Registers a handler for its supported secret type.
    /// </summary>
    /// <param name="handler">The handler to register.</param>
    public void RegisterHandler(ISecretHandler handler)
    {
        _handlers[handler.SupportedSecretType] = handler;
        _logger.LogTrace("Registered handler for {SecretType}", handler.SupportedSecretType);
    }

    /// <summary>
    /// Gets the handler for the specified secret type.
    /// </summary>
    /// <param name="secretType">The secret type.</param>
    /// <returns>The appropriate handler.</returns>
    /// <exception cref="UnsupportedStoreTypeException">Thrown if no handler is registered for the type.</exception>
    public ISecretHandler GetHandler(SecretType secretType)
    {
        if (_handlers.TryGetValue(secretType, out var handler))
        {
            _logger.LogDebug("Using {HandlerType} for secret type {SecretType}",
                handler.GetType().Name, secretType);
            return handler;
        }

        throw new UnsupportedStoreTypeException(secretType.ToString(), "GetHandler");
    }

    /// <summary>
    /// Gets the handler for the specified secret type string.
    /// Parses the string to determine the appropriate SecretType enum.
    /// </summary>
    /// <param name="secretTypeString">The secret type as a string (e.g., "tls", "opaque", "jks").</param>
    /// <returns>The appropriate handler.</returns>
    /// <exception cref="UnsupportedStoreTypeException">Thrown if no handler is registered for the type.</exception>
    public ISecretHandler GetHandler(string secretTypeString)
    {
        var secretType = SecretTypeParser.ParseSecretType(secretTypeString);
        if (secretType == SecretType.Unknown)
        {
            throw new UnsupportedStoreTypeException(secretTypeString, "GetHandler");
        }

        return GetHandler(secretType);
    }

    /// <summary>
    /// Gets the handler for the specified store type.
    /// Maps the store type to the appropriate secret type and returns the handler.
    /// </summary>
    /// <param name="storeType">The store type.</param>
    /// <returns>The appropriate handler.</returns>
    /// <exception cref="UnsupportedStoreTypeException">Thrown if no handler is registered for the type.</exception>
    public ISecretHandler GetHandlerForStoreType(StoreType storeType)
    {
        var secretType = SecretTypeParser.GetDefaultSecretType(storeType);
        if (secretType == SecretType.Unknown)
        {
            throw new UnsupportedStoreTypeException(storeType, "GetHandlerForStoreType");
        }

        return GetHandler(secretType);
    }

    /// <summary>
    /// Gets the handler based on the capability string from job configuration.
    /// </summary>
    /// <param name="capability">The capability string (e.g., "CertStores.K8SJKS.Inventory").</param>
    /// <returns>The appropriate handler.</returns>
    /// <exception cref="UnsupportedStoreTypeException">Thrown if no handler is registered for the capability.</exception>
    public ISecretHandler GetHandlerForCapability(string capability)
    {
        var storeType = SecretTypeParser.ParseStoreType(capability);
        if (storeType == StoreType.Unknown)
        {
            throw new UnsupportedStoreTypeException(capability, "GetHandlerForCapability");
        }

        return GetHandlerForStoreType(storeType);
    }

    /// <summary>
    /// Tries to get a handler for the specified secret type.
    /// </summary>
    /// <param name="secretType">The secret type.</param>
    /// <param name="handler">The handler if found.</param>
    /// <returns>True if a handler was found; otherwise, false.</returns>
    public bool TryGetHandler(SecretType secretType, out ISecretHandler handler)
    {
        return _handlers.TryGetValue(secretType, out handler);
    }

    /// <summary>
    /// Tries to get a handler for the specified secret type string.
    /// </summary>
    /// <param name="secretTypeString">The secret type as a string.</param>
    /// <param name="handler">The handler if found.</param>
    /// <returns>True if a handler was found; otherwise, false.</returns>
    public bool TryGetHandler(string secretTypeString, out ISecretHandler handler)
    {
        handler = null;
        var secretType = SecretTypeParser.ParseSecretType(secretTypeString);
        if (secretType == SecretType.Unknown)
        {
            return false;
        }

        return TryGetHandler(secretType, out handler);
    }

    /// <summary>
    /// Checks if a handler is registered for the specified secret type.
    /// </summary>
    /// <param name="secretType">The secret type to check.</param>
    /// <returns>True if a handler is registered; otherwise, false.</returns>
    public bool HasHandler(SecretType secretType)
    {
        return _handlers.ContainsKey(secretType);
    }

    /// <summary>
    /// Gets all registered handlers.
    /// </summary>
    /// <returns>Collection of all registered handlers.</returns>
    public IEnumerable<ISecretHandler> GetAllHandlers()
    {
        return _handlers.Values;
    }

    /// <summary>
    /// Creates a new factory instance with job-specific properties.
    /// Useful when handlers need access to job configuration.
    /// </summary>
    /// <param name="jobProperties">Job properties JSON.</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>A new SecretHandlerFactory configured with the job properties.</returns>
    public static SecretHandlerFactory CreateWithJobProperties(string jobProperties, ILogger logger = null)
    {
        return new SecretHandlerFactory(logger, jobProperties);
    }
}
