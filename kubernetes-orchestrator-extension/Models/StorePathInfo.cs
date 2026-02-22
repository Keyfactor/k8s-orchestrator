// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;

namespace Keyfactor.Extensions.Orchestrator.K8S.Models;

/// <summary>
/// Represents parsed store path information extracted from various path formats.
/// Handles paths like: "secret_name", "namespace/secret", "cluster/namespace/type/name", etc.
/// </summary>
public class StorePathInfo
{
    /// <summary>
    /// The Kubernetes cluster name or identifier.
    /// May be empty if not specified in the path.
    /// </summary>
    public string ClusterName { get; set; } = string.Empty;

    /// <summary>
    /// The Kubernetes namespace for the secret.
    /// </summary>
    public string Namespace { get; set; } = string.Empty;

    /// <summary>
    /// The name of the Kubernetes secret.
    /// </summary>
    public string SecretName { get; set; } = string.Empty;

    /// <summary>
    /// The type of secret (Opaque, TLS, etc.).
    /// </summary>
    public SecretType SecretType { get; set; } = SecretType.Unknown;

    /// <summary>
    /// The store type derived from the capability string.
    /// </summary>
    public StoreType StoreType { get; set; } = StoreType.Unknown;

    /// <summary>
    /// The original unparsed store path.
    /// </summary>
    public string OriginalPath { get; set; } = string.Empty;

    /// <summary>
    /// Indicates whether the path was successfully parsed.
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// Error message if parsing failed.
    /// </summary>
    public string ErrorMessage { get; set; } = string.Empty;

    /// <summary>
    /// Creates a canonical store path string from the parsed components.
    /// Format: cluster/namespace/type/name (where applicable).
    /// </summary>
    /// <returns>The canonical store path.</returns>
    public string ToCanonicalPath()
    {
        var parts = new List<string>();

        if (!string.IsNullOrEmpty(ClusterName))
            parts.Add(ClusterName);

        if (!string.IsNullOrEmpty(Namespace))
            parts.Add(Namespace);

        if (SecretType != SecretType.Unknown && SecretType != SecretType.Cluster && SecretType != SecretType.Namespace)
        {
            var typeString = SecretType switch
            {
                SecretType.Tls => "tls",
                SecretType.Opaque => "opaque",
                SecretType.Jks => "jks",
                SecretType.Pkcs12 => "pkcs12",
                SecretType.Certificate => "csr",
                _ => ""
            };
            if (!string.IsNullOrEmpty(typeString))
                parts.Add(typeString);
        }

        if (!string.IsNullOrEmpty(SecretName))
            parts.Add(SecretName);

        return string.Join("/", parts);
    }

    /// <summary>
    /// Creates a failed StorePathInfo with an error message.
    /// </summary>
    /// <param name="originalPath">The original path that failed to parse.</param>
    /// <param name="errorMessage">The error message describing the failure.</param>
    /// <returns>A StorePathInfo indicating failure.</returns>
    public static StorePathInfo Failed(string originalPath, string errorMessage)
    {
        return new StorePathInfo
        {
            OriginalPath = originalPath,
            IsValid = false,
            ErrorMessage = errorMessage
        };
    }

    /// <summary>
    /// Creates a successful StorePathInfo.
    /// </summary>
    /// <param name="originalPath">The original path.</param>
    /// <param name="namespace">The parsed namespace.</param>
    /// <param name="secretName">The parsed secret name.</param>
    /// <param name="secretType">The parsed secret type.</param>
    /// <param name="storeType">The store type.</param>
    /// <param name="clusterName">Optional cluster name.</param>
    /// <returns>A valid StorePathInfo.</returns>
    public static StorePathInfo Success(
        string originalPath,
        string @namespace,
        string secretName,
        SecretType secretType,
        StoreType storeType,
        string clusterName = "")
    {
        return new StorePathInfo
        {
            OriginalPath = originalPath,
            Namespace = @namespace,
            SecretName = secretName,
            SecretType = secretType,
            StoreType = storeType,
            ClusterName = clusterName,
            IsValid = true
        };
    }
}
