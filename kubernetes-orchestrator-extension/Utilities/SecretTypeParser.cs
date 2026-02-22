// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;

namespace Keyfactor.Extensions.Orchestrator.K8S.Utilities;

/// <summary>
/// Utility class for parsing string representations of secret and store types into their enum equivalents.
/// Handles the various string formats used throughout the codebase for consistent type identification.
/// </summary>
public static class SecretTypeParser
{
    /// <summary>
    /// Parses a string representation of a secret type into the corresponding SecretType enum.
    /// Handles various string formats (e.g., "tls", "tls_secret", "tlssecret" all map to SecretType.Tls).
    /// </summary>
    /// <param name="input">The string representation of the secret type.</param>
    /// <returns>The corresponding SecretType enum value, or SecretType.Unknown if not recognized.</returns>
    public static SecretType ParseSecretType(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return SecretType.Unknown;

        return input.ToLowerInvariant() switch
        {
            // Opaque secret variations
            "secret" or "secrets" or "opaque" => SecretType.Opaque,

            // TLS secret variations
            "tls" or "tls_secret" or "tlssecret" or "tls_secrets" => SecretType.Tls,

            // Certificate/CSR variations
            "certificate" or "cert" or "csr" or "csrs" or "certs" or "certificates" => SecretType.Certificate,

            // JKS keystore
            "jks" => SecretType.Jks,

            // PKCS12/PFX keystore variations
            "pkcs12" or "p12" or "pfx" => SecretType.Pkcs12,

            // Cluster-wide scope
            "cluster" => SecretType.Cluster,

            // Namespace-wide scope
            "namespace" => SecretType.Namespace,

            // Default to Unknown
            _ => SecretType.Unknown
        };
    }

    /// <summary>
    /// Parses a capability string to extract the store type.
    /// Capability strings are in format "CertStores.{StoreType}.{Operation}" (e.g., "CertStores.K8SJKS.Inventory").
    /// </summary>
    /// <param name="capability">The capability string from job configuration.</param>
    /// <returns>The corresponding StoreType enum value, or StoreType.Unknown if not recognized.</returns>
    public static StoreType ParseStoreType(string capability)
    {
        if (string.IsNullOrWhiteSpace(capability))
            return StoreType.Unknown;

        // Extract the store type from capability string (e.g., "CertStores.K8SJKS.Inventory" -> "K8SJKS")
        var parts = capability.Split('.');
        if (parts.Length < 2)
            return StoreType.Unknown;

        var storeTypeName = parts[1].ToUpperInvariant();

        return storeTypeName switch
        {
            "K8SCERT" => StoreType.K8SCert,
            "K8SCLUSTER" => StoreType.K8SCluster,
            "K8SNS" => StoreType.K8SNS,
            "K8SJKS" => StoreType.K8SJKS,
            "K8SPKCS12" or "K8SPFX" => StoreType.K8SPKCS12,
            "K8SSECRET" => StoreType.K8SSecret,
            "K8STLSSECR" => StoreType.K8STLSSecr,
            _ => StoreType.Unknown
        };
    }

    /// <summary>
    /// Determines the default SecretType for a given StoreType.
    /// Used to set the appropriate secret handling based on store configuration.
    /// </summary>
    /// <param name="storeType">The store type.</param>
    /// <returns>The default SecretType for the given store type.</returns>
    public static SecretType GetDefaultSecretType(StoreType storeType)
    {
        return storeType switch
        {
            StoreType.K8SCert => SecretType.Certificate,
            StoreType.K8SCluster => SecretType.Cluster,
            StoreType.K8SNS => SecretType.Namespace,
            StoreType.K8SJKS => SecretType.Jks,
            StoreType.K8SPKCS12 => SecretType.Pkcs12,
            StoreType.K8SSecret => SecretType.Opaque,
            StoreType.K8STLSSecr => SecretType.Tls,
            _ => SecretType.Unknown
        };
    }

    /// <summary>
    /// Converts a SecretType to its canonical string representation for Kubernetes operations.
    /// </summary>
    /// <param name="secretType">The secret type enum value.</param>
    /// <returns>The canonical string representation used in Kubernetes API calls.</returns>
    public static string ToKubernetesType(SecretType secretType)
    {
        return secretType switch
        {
            SecretType.Opaque => "Opaque",
            SecretType.Tls => "kubernetes.io/tls",
            SecretType.Certificate => "certificates.k8s.io/v1",
            SecretType.Jks => "Opaque",  // JKS is stored in Opaque secrets
            SecretType.Pkcs12 => "Opaque",  // PKCS12 is stored in Opaque secrets
            SecretType.Cluster => "cluster",  // Special scope value
            SecretType.Namespace => "namespace",  // Special scope value
            _ => "Opaque"
        };
    }

    /// <summary>
    /// Checks if a given store type supports cluster-wide or namespace-wide operations.
    /// </summary>
    /// <param name="storeType">The store type to check.</param>
    /// <returns>True if the store type operates at cluster or namespace scope.</returns>
    public static bool IsMultiSecretStore(StoreType storeType)
    {
        return storeType is StoreType.K8SCluster or StoreType.K8SNS;
    }

    /// <summary>
    /// Checks if a given store type uses keystore-based storage (JKS or PKCS12).
    /// </summary>
    /// <param name="storeType">The store type to check.</param>
    /// <returns>True if the store type uses JKS or PKCS12 format.</returns>
    public static bool IsKeystoreStore(StoreType storeType)
    {
        return storeType is StoreType.K8SJKS or StoreType.K8SPKCS12;
    }

    /// <summary>
    /// Checks if a given store type is read-only (like CSR).
    /// </summary>
    /// <param name="storeType">The store type to check.</param>
    /// <returns>True if the store type only supports inventory/discovery operations.</returns>
    public static bool IsReadOnly(StoreType storeType)
    {
        return storeType == StoreType.K8SCert;
    }
}
