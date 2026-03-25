// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Services;

/// <summary>
/// Result of store path resolution containing namespace, secret name, and any warnings.
/// </summary>
public record PathResolutionResult
{
    /// <summary>The resolved Kubernetes namespace.</summary>
    public string Namespace { get; init; } = "";

    /// <summary>The resolved Kubernetes secret name.</summary>
    public string SecretName { get; init; } = "";

    /// <summary>Whether the resolution was successful.</summary>
    public bool Success { get; init; } = true;

    /// <summary>Warning message if any path components were ignored or re-interpreted.</summary>
    public string Warning { get; init; }
}

/// <summary>
/// Resolves store paths into Kubernetes namespace and secret name components.
/// Handles various path formats based on store type (Cluster, Namespace, or individual secret).
/// </summary>
/// <remarks>
/// Supported path formats:
/// - 1 part: secret_name (for regular stores), namespace_name (for K8SNS), cluster_name (for K8SCluster)
/// - 2 parts: namespace/secret (for regular), cluster/namespace (for K8SNS)
/// - 3 parts: cluster/namespace/secret or namespace/type/secret
/// - 4 parts: cluster/namespace/type/secret
/// </remarks>
public class StorePathResolver
{
    private readonly ILogger _logger;
    private static readonly string[] ReservedKeywords = { "secret", "secrets", "tls", "certificate", "namespace" };

    /// <summary>
    /// Initializes a new instance of StorePathResolver.
    /// </summary>
    /// <param name="logger">Logger instance for diagnostic output.</param>
    public StorePathResolver(ILogger logger = null)
    {
        _logger = logger ?? LogHandler.GetClassLogger<StorePathResolver>();
    }

    /// <summary>
    /// Resolves a store path into namespace and secret name components.
    /// </summary>
    /// <param name="storePath">The store path to resolve.</param>
    /// <param name="capability">The capability string indicating store type (e.g., "K8SNS", "K8SCluster").</param>
    /// <param name="currentNamespace">Current namespace value (may be overridden by path).</param>
    /// <param name="currentSecretName">Current secret name value (may be overridden by path).</param>
    /// <returns>PathResolutionResult containing the resolved components.</returns>
    public PathResolutionResult Resolve(
        string storePath,
        string capability,
        string currentNamespace,
        string currentSecretName)
    {
        _logger.LogDebug("Resolving store path: {StorePath}", storePath);

        if (string.IsNullOrEmpty(storePath))
        {
            _logger.LogDebug("Store path is empty, using current values");
            return new PathResolutionResult
            {
                Namespace = currentNamespace,
                SecretName = currentSecretName
            };
        }

        var parts = storePath.Split('/');
        _logger.LogTrace("Store path has {Count} parts", parts.Length);

        var isNamespaceStore = IsNamespaceStore(capability);
        var isClusterStore = IsClusterStore(capability);

        return parts.Length switch
        {
            1 => ResolveSinglePart(parts[0], isNamespaceStore, isClusterStore, currentNamespace, currentSecretName),
            2 => ResolveTwoPart(parts, isNamespaceStore, isClusterStore, currentNamespace, currentSecretName, storePath),
            3 => ResolveThreePart(parts, isNamespaceStore, isClusterStore, currentNamespace, currentSecretName, storePath),
            4 => ResolveFourPart(parts, isNamespaceStore, isClusterStore, currentNamespace, currentSecretName, storePath),
            _ => ResolveMultiPart(parts, currentNamespace, currentSecretName, storePath)
        };
    }

    /// <summary>
    /// Resolves a single-part path (just a name).
    /// </summary>
    private PathResolutionResult ResolveSinglePart(
        string part,
        bool isNamespaceStore,
        bool isClusterStore,
        string currentNamespace,
        string currentSecretName)
    {
        if (isNamespaceStore)
        {
            // For K8SNS, single part is the namespace name
            var ns = string.IsNullOrEmpty(currentNamespace) ? part : currentNamespace;
            if (!string.IsNullOrEmpty(currentNamespace) && currentNamespace != part)
            {
                _logger.LogInformation(
                    "K8SNS store: KubeNamespace already set to {Current}, ignoring StorePath value {Path}",
                    currentNamespace, part);
            }
            else if (string.IsNullOrEmpty(currentNamespace))
            {
                _logger.LogInformation("K8SNS store: Setting KubeNamespace to {Namespace}", part);
            }

            return new PathResolutionResult
            {
                Namespace = ns,
                SecretName = ""  // Namespace stores don't have a secret name
            };
        }

        if (isClusterStore)
        {
            // For K8SCluster, single part is cluster name - namespace and secret should be empty
            var warning = "";
            if (!string.IsNullOrEmpty(currentSecretName))
            {
                warning = "KubeSecretName is not valid for K8SCluster and was cleared";
            }
            if (!string.IsNullOrEmpty(currentNamespace))
            {
                warning += string.IsNullOrEmpty(warning) ? "" : "; ";
                warning += "KubeNamespace is not valid for K8SCluster and was cleared";
            }

            _logger.LogInformation("K8SCluster store: Path is cluster name, clearing namespace and secret name");
            return new PathResolutionResult
            {
                Namespace = "",
                SecretName = "",
                Warning = string.IsNullOrEmpty(warning) ? null : warning
            };
        }

        // Regular store - single part is the secret name
        var secretName = string.IsNullOrEmpty(currentSecretName) ? part : currentSecretName;
        if (!string.IsNullOrEmpty(currentSecretName))
        {
            _logger.LogInformation(
                "Single-part path but KubeSecretName already set, ignoring StorePath value {Path}", part);
        }
        else
        {
            _logger.LogInformation("Single-part path: Setting KubeSecretName to {SecretName}", part);
        }

        return new PathResolutionResult
        {
            Namespace = currentNamespace,
            SecretName = secretName
        };
    }

    /// <summary>
    /// Resolves a two-part path (e.g., namespace/secret).
    /// </summary>
    private PathResolutionResult ResolveTwoPart(
        string[] parts,
        bool isNamespaceStore,
        bool isClusterStore,
        string currentNamespace,
        string currentSecretName,
        string storePath)
    {
        if (isClusterStore)
        {
            _logger.LogWarning(
                "Two-part path is not valid for K8SCluster store type, ignoring: {StorePath}", storePath);
            return new PathResolutionResult
            {
                Namespace = currentNamespace,
                SecretName = currentSecretName,
                Warning = "Two-part path not valid for K8SCluster"
            };
        }

        if (isNamespaceStore)
        {
            // For K8SNS: cluster/namespace or namespace-prefix/namespace
            var ns = string.IsNullOrEmpty(currentNamespace) ? parts[1] : currentNamespace;
            if (!string.IsNullOrEmpty(currentNamespace))
            {
                _logger.LogInformation(
                    "K8SNS store: KubeNamespace already set, ignoring StorePath value {StorePath}", storePath);
            }
            else
            {
                _logger.LogInformation("K8SNS store: Setting KubeNamespace to {Namespace}", parts[1]);
            }

            return new PathResolutionResult
            {
                Namespace = ns,
                SecretName = ""
            };
        }

        // Regular store: namespace/secret
        _logger.LogInformation(
            "Two-part path: Interpreting as namespace/secret pattern");

        var resolvedNs = string.IsNullOrEmpty(currentNamespace) ? parts[0] : currentNamespace;
        var resolvedSecret = string.IsNullOrEmpty(currentSecretName) ? parts[1] : currentSecretName;

        if (string.IsNullOrEmpty(currentNamespace))
        {
            _logger.LogInformation("Setting KubeNamespace to {Namespace}", parts[0]);
        }
        if (string.IsNullOrEmpty(currentSecretName))
        {
            _logger.LogInformation("Setting KubeSecretName to {SecretName}", parts[1]);
        }

        return new PathResolutionResult
        {
            Namespace = resolvedNs,
            SecretName = resolvedSecret
        };
    }

    /// <summary>
    /// Resolves a three-part path (e.g., cluster/namespace/secret or namespace/type/secret).
    /// </summary>
    private PathResolutionResult ResolveThreePart(
        string[] parts,
        bool isNamespaceStore,
        bool isClusterStore,
        string currentNamespace,
        string currentSecretName,
        string storePath)
    {
        if (isClusterStore)
        {
            _logger.LogError(
                "Three-part path is not valid for K8SCluster store type, ignoring: {StorePath}", storePath);
            return new PathResolutionResult
            {
                Namespace = currentNamespace,
                SecretName = currentSecretName,
                Success = false,
                Warning = "Three-part path not valid for K8SCluster"
            };
        }

        if (isNamespaceStore)
        {
            // For K8SNS: cluster/namespace/namespace-name pattern
            var ns = string.IsNullOrEmpty(currentNamespace) ? parts[2] : currentNamespace;
            var warning = !string.IsNullOrEmpty(currentSecretName)
                ? "KubeSecretName is not supported for K8SNS store type and was cleared"
                : null;

            if (!string.IsNullOrEmpty(currentNamespace))
            {
                _logger.LogInformation(
                    "K8SNS store: KubeNamespace already set, ignoring StorePath value {StorePath}", storePath);
            }
            else
            {
                _logger.LogInformation("K8SNS store: Setting KubeNamespace to {Namespace}", parts[2]);
            }

            return new PathResolutionResult
            {
                Namespace = ns,
                SecretName = "",
                Warning = warning
            };
        }

        // Regular store: cluster/namespace/secret or namespace/type/secret
        _logger.LogInformation(
            "Three-part path: Interpreting as cluster/namespace/secret pattern");

        var kN = parts[1];
        var kS = parts[2];

        // Check if middle part is a reserved keyword (namespace/type/secret pattern)
        if (IsReservedKeyword(parts[1]))
        {
            _logger.LogInformation(
                "Middle part '{Keyword}' is a reserved keyword, re-interpreting as namespace/type/secret pattern",
                parts[1]);
            kN = parts[0];  // First part is actually the namespace
            kS = parts[2];  // Third part is still the secret name
        }

        var resolvedNs = string.IsNullOrEmpty(currentNamespace) ? kN : currentNamespace;
        var resolvedSecret = string.IsNullOrEmpty(currentSecretName) ? kS : currentSecretName;

        return new PathResolutionResult
        {
            Namespace = resolvedNs,
            SecretName = resolvedSecret
        };
    }

    /// <summary>
    /// Resolves a four-part path (cluster/namespace/type/secret).
    /// </summary>
    private PathResolutionResult ResolveFourPart(
        string[] parts,
        bool isNamespaceStore,
        bool isClusterStore,
        string currentNamespace,
        string currentSecretName,
        string storePath)
    {
        if (isClusterStore || isNamespaceStore)
        {
            _logger.LogError(
                "Four-part path is not valid for {StoreType} store type: {StorePath}",
                isClusterStore ? "K8SCluster" : "K8SNS", storePath);
            return new PathResolutionResult
            {
                Namespace = currentNamespace,
                SecretName = currentSecretName,
                Success = false,
                Warning = $"Four-part path not valid for {(isClusterStore ? "K8SCluster" : "K8SNS")}"
            };
        }

        // Regular store: cluster/namespace/type/secret
        _logger.LogTrace(
            "Four-part path: Interpreting as cluster/namespace/type/secret pattern");

        var resolvedNs = string.IsNullOrEmpty(currentNamespace) ? parts[1] : currentNamespace;
        var resolvedSecret = string.IsNullOrEmpty(currentSecretName) ? parts[3] : currentSecretName;

        if (string.IsNullOrEmpty(currentNamespace))
        {
            _logger.LogTrace("Setting KubeNamespace to {Namespace}", parts[1]);
        }
        if (string.IsNullOrEmpty(currentSecretName))
        {
            _logger.LogTrace("Setting KubeSecretName to {SecretName}", parts[3]);
        }

        return new PathResolutionResult
        {
            Namespace = resolvedNs,
            SecretName = resolvedSecret
        };
    }

    /// <summary>
    /// Resolves paths with more than 4 parts (fallback).
    /// </summary>
    private PathResolutionResult ResolveMultiPart(
        string[] parts,
        string currentNamespace,
        string currentSecretName,
        string storePath)
    {
        _logger.LogWarning(
            "Unable to resolve store path with {PartCount} parts: {StorePath}. Using first part as namespace and last as secret name",
            parts.Length, storePath);

        return new PathResolutionResult
        {
            Namespace = string.IsNullOrEmpty(currentNamespace) ? parts[0] : currentNamespace,
            SecretName = string.IsNullOrEmpty(currentSecretName) ? parts[^1] : currentSecretName,
            Warning = $"Path has {parts.Length} parts; using first as namespace and last as secret name"
        };
    }

    /// <summary>
    /// Checks if a string segment is a reserved keyword.
    /// </summary>
    private static bool IsReservedKeyword(string segment)
    {
        if (string.IsNullOrEmpty(segment)) return false;
        var lower = segment.ToLowerInvariant();
        return Array.Exists(ReservedKeywords, k => k == lower);
    }

    /// <summary>
    /// Determines if the capability indicates a namespace-level store.
    /// </summary>
    private static bool IsNamespaceStore(string capability)
    {
        return !string.IsNullOrEmpty(capability) &&
               capability.Contains("K8SNS", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines if the capability indicates a cluster-level store.
    /// </summary>
    private static bool IsClusterStore(string capability)
    {
        return !string.IsNullOrEmpty(capability) &&
               capability.Contains("K8SCluster", StringComparison.OrdinalIgnoreCase);
    }
}
