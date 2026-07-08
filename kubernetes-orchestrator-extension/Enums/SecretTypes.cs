// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Linq;

namespace Keyfactor.Extensions.Orchestrator.K8S.Enums;

/// <summary>
/// Provides constants and helper methods for Kubernetes secret type detection and normalization.
/// Centralizes all magic strings for secret types used throughout the codebase.
/// </summary>
public static class SecretTypes
{
    /// <summary>
    /// Normalized type constant for TLS secrets (kubernetes.io/tls).
    /// </summary>
    public const string Tls = "tls";

    /// <summary>
    /// Normalized type constant for Opaque secrets (generic secrets).
    /// </summary>
    public const string Opaque = "secret";

    /// <summary>
    /// Normalized type constant for Certificate Signing Requests.
    /// </summary>
    public const string Certificate = "certificate";

    /// <summary>
    /// Normalized type constant for PKCS12/PFX keystores.
    /// </summary>
    public const string Pkcs12 = "pkcs12";

    /// <summary>
    /// Normalized type constant for JKS keystores.
    /// </summary>
    public const string Jks = "jks";

    /// <summary>
    /// Normalized type constant for namespace-level store operations.
    /// </summary>
    public const string Namespace = "namespace";

    /// <summary>
    /// Normalized type constant for cluster-level store operations.
    /// </summary>
    public const string Cluster = "cluster";

    /// <summary>
    /// All variant strings that map to TLS secret type.
    /// </summary>
    public static readonly string[] TlsVariants = { "tls_secret", "tls", "tlssecret", "tls_secrets" };

    /// <summary>
    /// All variant strings that map to Opaque secret type.
    /// </summary>
    public static readonly string[] OpaqueVariants = { "opaque", "secret", "secrets" };

    /// <summary>
    /// All variant strings that map to Certificate/CSR type.
    /// </summary>
    public static readonly string[] CsrVariants = { "certificate", "cert", "csr", "csrs", "certs", "certificates" };

    /// <summary>
    /// All variant strings that map to PKCS12 keystore type.
    /// </summary>
    public static readonly string[] Pkcs12Variants = { "pfx", "pkcs12", "p12" };

    /// <summary>
    /// All variant strings that map to JKS keystore type.
    /// </summary>
    public static readonly string[] JksVariants = { "jks" };

    /// <summary>
    /// All variant strings that map to Namespace store type.
    /// </summary>
    public static readonly string[] NamespaceVariants = { "namespace", "ns" };

    /// <summary>
    /// All variant strings that map to Cluster store type.
    /// </summary>
    public static readonly string[] ClusterVariants = { "cluster", "k8scluster" };

    /// <summary>
    /// Determines if the given type string represents a TLS secret.
    /// </summary>
    /// <param name="type">The type string to check.</param>
    /// <returns>True if the type is a TLS variant; otherwise, false.</returns>
    public static bool IsTlsType(string type) =>
        !string.IsNullOrEmpty(type) && TlsVariants.Contains(type.ToLower());

    /// <summary>
    /// Determines if the given type string represents an Opaque secret.
    /// </summary>
    /// <param name="type">The type string to check.</param>
    /// <returns>True if the type is an Opaque variant; otherwise, false.</returns>
    public static bool IsOpaqueType(string type) =>
        !string.IsNullOrEmpty(type) && OpaqueVariants.Contains(type.ToLower());

    /// <summary>
    /// Determines if the given type string represents a Certificate/CSR.
    /// </summary>
    /// <param name="type">The type string to check.</param>
    /// <returns>True if the type is a CSR variant; otherwise, false.</returns>
    public static bool IsCsrType(string type) =>
        !string.IsNullOrEmpty(type) && CsrVariants.Contains(type.ToLower());

    /// <summary>
    /// Determines if the given type string represents a PKCS12 keystore.
    /// </summary>
    /// <param name="type">The type string to check.</param>
    /// <returns>True if the type is a PKCS12 variant; otherwise, false.</returns>
    public static bool IsPkcs12Type(string type) =>
        !string.IsNullOrEmpty(type) && Pkcs12Variants.Contains(type.ToLower());

    /// <summary>
    /// Determines if the given type string represents a JKS keystore.
    /// </summary>
    /// <param name="type">The type string to check.</param>
    /// <returns>True if the type is a JKS variant; otherwise, false.</returns>
    public static bool IsJksType(string type) =>
        !string.IsNullOrEmpty(type) && JksVariants.Contains(type.ToLower());

    /// <summary>
    /// Determines if the given type string represents a Namespace store.
    /// </summary>
    /// <param name="type">The type string to check.</param>
    /// <returns>True if the type is a Namespace variant; otherwise, false.</returns>
    public static bool IsNamespaceType(string type) =>
        !string.IsNullOrEmpty(type) && NamespaceVariants.Contains(type.ToLower());

    /// <summary>
    /// Determines if the given type string represents a Cluster store.
    /// </summary>
    /// <param name="type">The type string to check.</param>
    /// <returns>True if the type is a Cluster variant; otherwise, false.</returns>
    public static bool IsClusterType(string type) =>
        !string.IsNullOrEmpty(type) && ClusterVariants.Contains(type.ToLower());

    /// <summary>
    /// Normalizes a secret type string to its canonical form.
    /// </summary>
    /// <param name="type">The type string to normalize.</param>
    /// <returns>The normalized type constant, or the original type if not recognized.</returns>
    public static string Normalize(string type)
    {
        if (string.IsNullOrEmpty(type))
            return type;

        var lowerType = type.ToLower();

        // Check from most specific to least specific
        if (JksVariants.Contains(lowerType))
            return Jks;
        if (Pkcs12Variants.Contains(lowerType))
            return Pkcs12;
        if (TlsVariants.Contains(lowerType))
            return Tls;
        if (OpaqueVariants.Contains(lowerType))
            return Opaque;
        if (CsrVariants.Contains(lowerType))
            return Certificate;
        if (NamespaceVariants.Contains(lowerType))
            return Namespace;
        if (ClusterVariants.Contains(lowerType))
            return Cluster;

        return type;
    }

    /// <summary>
    /// Determines if the type represents a keystore format (JKS or PKCS12) that supports multiple entries.
    /// </summary>
    /// <param name="type">The type string to check.</param>
    /// <returns>True if the type is a keystore format; otherwise, false.</returns>
    public static bool IsKeystoreType(string type) =>
        IsJksType(type) || IsPkcs12Type(type);

    /// <summary>
    /// Determines if the type represents an aggregate store (namespace or cluster level).
    /// </summary>
    /// <param name="type">The type string to check.</param>
    /// <returns>True if the type is an aggregate store; otherwise, false.</returns>
    public static bool IsAggregateStoreType(string type) =>
        IsNamespaceType(type) || IsClusterType(type);

    /// <summary>
    /// Determines if the type represents a simple secret type (TLS or Opaque).
    /// </summary>
    /// <param name="type">The type string to check.</param>
    /// <returns>True if the type is a simple secret; otherwise, false.</returns>
    public static bool IsSimpleSecretType(string type) =>
        IsTlsType(type) || IsOpaqueType(type);
}
