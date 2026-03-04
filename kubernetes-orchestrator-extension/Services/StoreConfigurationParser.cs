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
/// Configuration data extracted from store properties.
/// Contains all settings needed to configure a Kubernetes certificate store.
/// </summary>
public class StoreConfiguration
{
    /// <summary>Kubernetes namespace where the secret resides.</summary>
    public string KubeNamespace { get; set; } = "";

    /// <summary>Name of the Kubernetes secret.</summary>
    public string KubeSecretName { get; set; } = "";

    /// <summary>Type of secret (tls, opaque, jks, pkcs12, etc.).</summary>
    public string KubeSecretType { get; set; } = "";

    /// <summary>Kubeconfig JSON for API authentication.</summary>
    public string KubeSvcCreds { get; set; } = "";

    /// <summary>Whether the keystore password is stored in a separate K8S secret.</summary>
    public bool PasswordIsSeparateSecret { get; set; }

    /// <summary>Field name in the secret containing the password.</summary>
    public string PasswordFieldName { get; set; } = "password";

    /// <summary>Path to a separate K8S secret containing the store password.</summary>
    public string StorePasswordPath { get; set; } = "";

    /// <summary>Field name in the secret containing the certificate/keystore data.</summary>
    public string CertificateDataFieldName { get; set; } = "";

    /// <summary>Whether the password is stored as a K8S secret (vs inline).</summary>
    public bool PasswordIsK8SSecret { get; set; }

    /// <summary>The K8S secret password value.</summary>
    public object KubeSecretPassword { get; set; }

    /// <summary>Whether to store the certificate chain in a separate field.</summary>
    public bool SeparateChain { get; set; }

    /// <summary>Whether to include the full certificate chain.</summary>
    public bool IncludeCertChain { get; set; } = true;
}

/// <summary>
/// Parses store properties from job configuration into a StoreConfiguration object.
/// Provides helper methods for safely extracting values with defaults.
/// </summary>
public class StoreConfigurationParser
{
    private readonly ILogger _logger;

    // Default field names
    private const string DefaultPasswordFieldName = "password";
    private const string DefaultPfxFieldName = "pfx";
    private const string DefaultJksFieldName = "jks";

    /// <summary>
    /// Initializes a new instance of the StoreConfigurationParser.
    /// </summary>
    /// <param name="logger">Logger instance for diagnostic output.</param>
    public StoreConfigurationParser(ILogger logger)
    {
        _logger = logger ?? LogHandler.GetClassLogger<StoreConfigurationParser>();
    }

    /// <summary>
    /// Gets a property value from a dynamic properties object, with a default fallback.
    /// </summary>
    /// <typeparam name="T">The expected type of the property value.</typeparam>
    /// <param name="properties">The dynamic properties object.</param>
    /// <param name="key">The property key to look up.</param>
    /// <param name="defaultValue">The default value if key is not found.</param>
    /// <returns>The property value, or the default if not found.</returns>
    public T GetPropertyOrDefault<T>(dynamic properties, string key, T defaultValue)
    {
        if (properties == null)
        {
            _logger.LogDebug("Properties object is null, using default for {Key}", key);
            return defaultValue;
        }

        try
        {
            if (properties.ContainsKey(key))
            {
                var value = properties[key];
                if (value == null)
                {
                    _logger.LogDebug("{Key} is null, using default", key);
                    return defaultValue;
                }

                // Handle string to bool conversion
                if (typeof(T) == typeof(bool) && value is string strValue)
                {
                    if (bool.TryParse(strValue, out var boolResult))
                    {
                        return (T)(object)boolResult;
                    }
                    _logger.LogDebug("Could not parse {Key} as bool, using default", key);
                    return defaultValue;
                }

                // Handle string to string (with trim)
                if (typeof(T) == typeof(string))
                {
                    return (T)(object)(value?.ToString()?.Trim() ?? defaultValue?.ToString());
                }

                return (T)value;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Error reading {Key}: {Error}, using default", key, ex.Message);
        }

        _logger.LogDebug("{Key} not found in store properties, using default", key);
        return defaultValue;
    }

    /// <summary>
    /// Parses the store properties into a StoreConfiguration object.
    /// </summary>
    /// <param name="storeProperties">Dynamic dictionary of store properties.</param>
    /// <param name="capability">The store capability string for deriving secret type.</param>
    /// <returns>A populated StoreConfiguration object.</returns>
    public StoreConfiguration Parse(dynamic storeProperties, string capability = null)
    {
        _logger.LogDebug("Parsing store configuration");

        var config = new StoreConfiguration
        {
            KubeNamespace = GetPropertyOrDefault(storeProperties, "KubeNamespace", ""),
            KubeSecretName = GetPropertyOrDefault(storeProperties, "KubeSecretName", ""),
            KubeSvcCreds = GetPropertyOrDefault<string>(storeProperties, "KubeSvcCreds", null),
            PasswordIsSeparateSecret = GetPropertyOrDefault(storeProperties, "PasswordIsSeparateSecret", false),
            PasswordFieldName = GetPropertyOrDefault(storeProperties, "PasswordFieldName", DefaultPasswordFieldName),
            StorePasswordPath = GetPropertyOrDefault(storeProperties, "StorePasswordPath", ""),
            CertificateDataFieldName = GetPropertyOrDefault(storeProperties, "KubeSecretKey", ""),
            PasswordIsK8SSecret = GetPropertyOrDefault(storeProperties, "PasswordIsK8SSecret", false),
            KubeSecretPassword = GetPropertyOrDefault<object>(storeProperties, "KubeSecretPassword", null),
            SeparateChain = GetPropertyOrDefault(storeProperties, "SeparateChain", false),
            IncludeCertChain = GetPropertyOrDefault(storeProperties, "IncludeCertChain", true)
        };

        // Derive secret type from capability if available
        if (!string.IsNullOrEmpty(capability))
        {
            config.KubeSecretType = DeriveSecretTypeFromCapability(capability);
            _logger.LogTrace("Derived KubeSecretType from Capability: {Type}", config.KubeSecretType);
        }

        // Fall back to property if capability didn't provide a type
        if (string.IsNullOrEmpty(config.KubeSecretType))
        {
            var propertyType = GetPropertyOrDefault<string>(storeProperties, "KubeSecretType", null);
            if (!string.IsNullOrEmpty(propertyType))
            {
                _logger.LogWarning(
                    "DEPRECATION WARNING: The 'KubeSecretType' store property is deprecated. " +
                    "The secret type should be derived from the Capability.");
                config.KubeSecretType = propertyType;
            }
        }

        // Validate conflicting configuration
        if (config.SeparateChain && !config.IncludeCertChain)
        {
            _logger.LogWarning(
                "Invalid configuration: SeparateChain=true but IncludeCertChain=false. " +
                "Cannot separate a certificate chain that is not being included. " +
                "SeparateChain will be ignored.");
            config.SeparateChain = false;
        }

        _logger.LogDebug("Parsed store configuration: Namespace={Namespace}, SecretName={SecretName}, Type={Type}",
            config.KubeNamespace, config.KubeSecretName, config.KubeSecretType);

        return config;
    }

    /// <summary>
    /// Applies keystore-specific defaults based on secret type.
    /// </summary>
    /// <param name="config">The configuration to update.</param>
    /// <param name="storeProperties">The original store properties for additional lookups.</param>
    public void ApplyKeystoreDefaults(StoreConfiguration config, dynamic storeProperties)
    {
        var secretType = config.KubeSecretType?.ToLower();

        switch (secretType)
        {
            case "pfx":
            case "p12":
            case "pkcs12":
                _logger.LogDebug("Applying PKCS12 defaults");
                if (string.IsNullOrEmpty(config.PasswordFieldName))
                    config.PasswordFieldName = DefaultPasswordFieldName;
                if (string.IsNullOrEmpty(config.CertificateDataFieldName))
                    config.CertificateDataFieldName = DefaultPfxFieldName;

                // Re-parse PKCS12-specific properties
                config.PasswordIsSeparateSecret = GetPropertyOrDefault(storeProperties, "PasswordIsSeparateSecret", false);
                config.StorePasswordPath = GetPropertyOrDefault(storeProperties, "StorePasswordPath", "");
                config.PasswordIsK8SSecret = GetPropertyOrDefault(storeProperties, "PasswordIsK8SSecret", false);
                config.KubeSecretPassword = GetPropertyOrDefault<object>(storeProperties, "KubeSecretPassword", null);
                config.CertificateDataFieldName = GetPropertyOrDefault(storeProperties, "CertificateDataFieldName", DefaultPfxFieldName);
                break;

            case "jks":
                _logger.LogDebug("Applying JKS defaults");
                if (string.IsNullOrEmpty(config.PasswordFieldName))
                    config.PasswordFieldName = DefaultPasswordFieldName;
                if (string.IsNullOrEmpty(config.CertificateDataFieldName))
                    config.CertificateDataFieldName = DefaultJksFieldName;

                // Re-parse JKS-specific properties with proper bool parsing
                config.PasswordFieldName = GetPropertyOrDefault(storeProperties, "PasswordFieldName", DefaultPasswordFieldName);
                config.PasswordIsSeparateSecret = ParseBoolProperty(storeProperties, "PasswordIsSeparateSecret", false);
                config.StorePasswordPath = GetPropertyOrDefault(storeProperties, "StorePasswordPath", "");
                config.PasswordIsK8SSecret = ParseBoolProperty(storeProperties, "PasswordIsK8SSecret", false);
                config.KubeSecretPassword = GetPropertyOrDefault<object>(storeProperties, "KubeSecretPassword", null);
                config.CertificateDataFieldName = GetPropertyOrDefault(storeProperties, "CertificateDataFieldName", DefaultJksFieldName);
                break;
        }
    }

    /// <summary>
    /// Parses a boolean property with proper string handling.
    /// </summary>
    private bool ParseBoolProperty(dynamic properties, string key, bool defaultValue)
    {
        if (properties == null) return defaultValue;

        try
        {
            if (!properties.ContainsKey(key)) return defaultValue;

            var value = properties[key];
            if (value == null || string.IsNullOrEmpty(value?.ToString()))
                return defaultValue;

            return bool.TryParse(value.ToString(), out bool result) ? result : defaultValue;
        }
        catch
        {
            return defaultValue;
        }
    }

    /// <summary>
    /// Derives the secret type from the capability string.
    /// </summary>
    private static string DeriveSecretTypeFromCapability(string capability)
    {
        if (string.IsNullOrEmpty(capability))
            return null;

        // Order matters - check more specific patterns first
        if (capability.Contains("K8STLSSecr", StringComparison.OrdinalIgnoreCase))
            return "tls_secret";
        if (capability.Contains("K8SSecret", StringComparison.OrdinalIgnoreCase))
            return "secret";
        if (capability.Contains("K8SJKS", StringComparison.OrdinalIgnoreCase))
            return "jks";
        if (capability.Contains("K8SPKCS12", StringComparison.OrdinalIgnoreCase))
            return "pkcs12";
        if (capability.Contains("K8SCluster", StringComparison.OrdinalIgnoreCase))
            return "cluster";
        if (capability.Contains("K8SNS", StringComparison.OrdinalIgnoreCase))
            return "namespace";
        if (capability.Contains("K8SCert", StringComparison.OrdinalIgnoreCase))
            return "certificate";

        return null;
    }
}
