// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Services;

/// <summary>
/// Service for resolving and parsing Kubernetes store paths.
/// Extracts namespace, secret name, and secret type from various path formats.
/// </summary>
public class StorePathResolver
{
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new StorePathResolver.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    public StorePathResolver(ILogger logger = null)
    {
        _logger = logger ?? LogHandler.GetClassLogger(typeof(StorePathResolver));
    }

    /// <summary>
    /// Resolves a store path to its components based on the store type.
    /// </summary>
    /// <param name="storePath">The store path to resolve.</param>
    /// <param name="storeType">The store type (affects path interpretation).</param>
    /// <param name="existingNamespace">Optional pre-existing namespace value.</param>
    /// <param name="existingSecretName">Optional pre-existing secret name value.</param>
    /// <returns>Parsed store path information.</returns>
    public StorePathInfo Resolve(
        string storePath,
        StoreType storeType,
        string existingNamespace = null,
        string existingSecretName = null)
    {
        _logger.LogDebug("Resolving store path: {StorePath} for store type: {StoreType}", storePath, storeType);

        if (string.IsNullOrWhiteSpace(storePath))
        {
            return StorePathInfo.Failed(storePath, "Store path is empty or null");
        }

        var parts = storePath.Split('/');
        _logger.LogTrace("Store path split into {Count} parts", parts.Length);

        return parts.Length switch
        {
            1 => ResolveSinglePart(parts, storeType, existingNamespace, existingSecretName, storePath),
            2 => ResolveTwoParts(parts, storeType, existingNamespace, existingSecretName, storePath),
            3 => ResolveThreeParts(parts, storeType, existingNamespace, existingSecretName, storePath),
            4 => ResolveFourParts(parts, storeType, existingNamespace, existingSecretName, storePath),
            _ => StorePathInfo.Failed(storePath, $"Store path has too many parts ({parts.Length})")
        };
    }

    private StorePathInfo ResolveSinglePart(
        string[] parts,
        StoreType storeType,
        string existingNamespace,
        string existingSecretName,
        string originalPath)
    {
        var secretType = SecretTypeParser.GetDefaultSecretType(storeType);

        if (SecretTypeParser.IsMultiSecretStore(storeType))
        {
            if (storeType == StoreType.K8SNS)
            {
                // For K8SNS, single part is the namespace
                _logger.LogInformation(
                    "Store path is 1 part for K8SNS, treating as namespace name: {Namespace}", parts[0]);
                return StorePathInfo.Success(originalPath, parts[0], "", secretType, storeType);
            }
            else // K8SCluster
            {
                // For K8SCluster, single part is the cluster name
                _logger.LogInformation(
                    "Store path is 1 part for K8SCluster, treating as cluster name: {Cluster}", parts[0]);
                return StorePathInfo.Success(originalPath, "", "", secretType, storeType, parts[0]);
            }
        }

        // For single-secret stores, single part is the secret name
        var ns = string.IsNullOrEmpty(existingNamespace) ? "default" : existingNamespace;
        var secretName = string.IsNullOrEmpty(existingSecretName) ? parts[0] : existingSecretName;

        _logger.LogInformation(
            "Store path is 1 part, treating as secret name: {SecretName} in namespace: {Namespace}",
            secretName, ns);

        return StorePathInfo.Success(originalPath, ns, secretName, secretType, storeType);
    }

    private StorePathInfo ResolveTwoParts(
        string[] parts,
        StoreType storeType,
        string existingNamespace,
        string existingSecretName,
        string originalPath)
    {
        var secretType = SecretTypeParser.GetDefaultSecretType(storeType);

        if (storeType == StoreType.K8SCluster)
        {
            _logger.LogWarning("Store path is 2 parts for K8SCluster - invalid combination, ignoring");
            return StorePathInfo.Failed(originalPath, "2-part path is not valid for K8SCluster store type");
        }

        if (storeType == StoreType.K8SNS)
        {
            // Pattern: <cluster_name>/<namespace_name> or namespace/<namespace_name>
            var ns = string.IsNullOrEmpty(existingNamespace) ? parts[1] : existingNamespace;
            _logger.LogInformation(
                "Store path is 2 parts for K8SNS, treating as cluster/namespace: {Namespace}", ns);
            return StorePathInfo.Success(originalPath, ns, "", secretType, storeType, parts[0]);
        }

        // Pattern: <namespace>/<secret_name>
        var resolvedNs = string.IsNullOrEmpty(existingNamespace) ? parts[0] : existingNamespace;
        var resolvedSecret = string.IsNullOrEmpty(existingSecretName) ? parts[1] : existingSecretName;

        _logger.LogInformation(
            "Store path is 2 parts, treating as namespace/secret: {Namespace}/{Secret}",
            resolvedNs, resolvedSecret);

        return StorePathInfo.Success(originalPath, resolvedNs, resolvedSecret, secretType, storeType);
    }

    private StorePathInfo ResolveThreeParts(
        string[] parts,
        StoreType storeType,
        string existingNamespace,
        string existingSecretName,
        string originalPath)
    {
        var secretType = SecretTypeParser.GetDefaultSecretType(storeType);

        if (storeType == StoreType.K8SCluster)
        {
            _logger.LogWarning("Store path is 3 parts for K8SCluster - invalid combination");
            return StorePathInfo.Failed(originalPath, "3-part path is not valid for K8SCluster store type");
        }

        if (storeType == StoreType.K8SNS)
        {
            // Pattern: <cluster>/namespace/<namespace_name>
            var ns = string.IsNullOrEmpty(existingNamespace) ? parts[2] : existingNamespace;
            _logger.LogInformation(
                "Store path is 3 parts for K8SNS, treating as cluster/namespace/ns_name: {Namespace}", ns);
            return StorePathInfo.Success(originalPath, ns, "", secretType, storeType, parts[0]);
        }

        // Check if middle part is a reserved keyword
        if (IsReservedKeyword(parts[1]))
        {
            // Pattern: <namespace>/<keyword>/<secret_name>
            var ns = string.IsNullOrEmpty(existingNamespace) ? parts[0] : existingNamespace;
            var secret = string.IsNullOrEmpty(existingSecretName) ? parts[2] : existingSecretName;
            _logger.LogInformation(
                "Store path is 3 parts with keyword, treating as namespace/type/secret: {Namespace}/{Secret}",
                ns, secret);
            return StorePathInfo.Success(originalPath, ns, secret, secretType, storeType);
        }

        // Pattern: <cluster>/<namespace>/<secret_name>
        var resolvedNs = string.IsNullOrEmpty(existingNamespace) ? parts[1] : existingNamespace;
        var resolvedSecret = string.IsNullOrEmpty(existingSecretName) ? parts[2] : existingSecretName;

        _logger.LogInformation(
            "Store path is 3 parts, treating as cluster/namespace/secret: {Namespace}/{Secret}",
            resolvedNs, resolvedSecret);

        return StorePathInfo.Success(originalPath, resolvedNs, resolvedSecret, secretType, storeType, parts[0]);
    }

    private StorePathInfo ResolveFourParts(
        string[] parts,
        StoreType storeType,
        string existingNamespace,
        string existingSecretName,
        string originalPath)
    {
        if (SecretTypeParser.IsMultiSecretStore(storeType))
        {
            _logger.LogWarning("Store path is 4 parts for multi-secret store - invalid combination");
            return StorePathInfo.Failed(originalPath, $"4-part path is not valid for {storeType} store type");
        }

        // Pattern: <cluster>/<namespace>/<secret_type>/<secret_name>
        var resolvedNs = string.IsNullOrEmpty(existingNamespace) ? parts[1] : existingNamespace;
        var resolvedSecret = string.IsNullOrEmpty(existingSecretName) ? parts[3] : existingSecretName;
        var parsedSecretType = SecretTypeParser.ParseSecretType(parts[2]);

        if (parsedSecretType == SecretType.Unknown)
        {
            parsedSecretType = SecretTypeParser.GetDefaultSecretType(storeType);
        }

        _logger.LogInformation(
            "Store path is 4 parts, treating as cluster/namespace/type/secret: {Namespace}/{Type}/{Secret}",
            resolvedNs, parsedSecretType, resolvedSecret);

        return StorePathInfo.Success(originalPath, resolvedNs, resolvedSecret, parsedSecretType, storeType, parts[0]);
    }

    private static bool IsReservedKeyword(string value)
    {
        return value.ToLowerInvariant() switch
        {
            "secret" or "secrets" or "tls" or "certificate" or "certificates" or
            "namespace" or "namespaces" or "opaque" or "jks" or "pkcs12" or "p12" or "pfx" => true,
            _ => false
        };
    }

    /// <summary>
    /// Builds a canonical store path from components.
    /// </summary>
    /// <param name="clusterName">Optional cluster name.</param>
    /// <param name="namespace">Kubernetes namespace.</param>
    /// <param name="secretType">Type of secret (for path formatting).</param>
    /// <param name="secretName">Name of the secret.</param>
    /// <returns>Canonical path string.</returns>
    public string BuildPath(string clusterName, string @namespace, SecretType secretType, string secretName)
    {
        var typeString = secretType switch
        {
            SecretType.Tls => "tls",
            SecretType.Opaque => "secrets",
            SecretType.Jks => "jks",
            SecretType.Pkcs12 => "pkcs12",
            SecretType.Certificate => "csr",
            _ => "secrets"
        };

        if (!string.IsNullOrEmpty(clusterName))
        {
            return $"{clusterName}/{@namespace}/{typeString}/{secretName}";
        }

        return $"{@namespace}/{typeString}/{secretName}";
    }
}
