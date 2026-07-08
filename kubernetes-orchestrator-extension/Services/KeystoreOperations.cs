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
/// Result of parsing an alias that may contain a field name prefix.
/// </summary>
/// <param name="FieldName">The K8S secret field name (e.g., "mystore.jks").</param>
/// <param name="Alias">The actual entry alias within the keystore.</param>
public record AliasParseResult(string FieldName, string Alias);

/// <summary>
/// Provides common operations for JKS and PKCS12 keystore handling.
/// Eliminates duplication between HandleJksSecret and HandlePkcs12Secret methods.
/// </summary>
public interface IKeystoreOperations
{
    /// <summary>
    /// Parses an alias that may contain a field name prefix (e.g., "mystore.jks/myalias").
    /// </summary>
    /// <param name="alias">The alias to parse.</param>
    /// <param name="defaultFieldName">The default field name to use if not specified in alias.</param>
    /// <returns>Tuple containing the field name and the actual alias.</returns>
    AliasParseResult ParseAliasAndFieldName(string alias, string defaultFieldName);

    /// <summary>
    /// Extracts the StoreFileName property from a JSON properties string.
    /// </summary>
    /// <param name="propertiesJson">The JSON string containing store properties.</param>
    /// <param name="defaultFileName">The default file name to use if not found.</param>
    /// <returns>The extracted store file name, or the default.</returns>
    string ExtractStoreFileNameFromProperties(string propertiesJson, string defaultFileName);
}

/// <summary>
/// Implementation of keystore operations for JKS and PKCS12 stores.
/// </summary>
public class KeystoreOperations : IKeystoreOperations
{
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of KeystoreOperations.
    /// </summary>
    /// <param name="logger">Logger instance for diagnostic output.</param>
    public KeystoreOperations(ILogger logger)
    {
        _logger = logger ?? LogHandler.GetClassLogger<KeystoreOperations>();
    }

    /// <inheritdoc/>
    public AliasParseResult ParseAliasAndFieldName(string alias, string defaultFieldName)
    {
        if (string.IsNullOrEmpty(alias))
        {
            _logger.LogDebug("Alias is null or empty, using default field name: {DefaultFieldName}", defaultFieldName);
            return new AliasParseResult(defaultFieldName, "default");
        }

        // Check if alias contains '/' - indicates pattern is 'field-name/alias'
        if (alias.Contains('/'))
        {
            _logger.LogDebug("Alias contains '/', splitting to extract field name and alias");
            var parts = alias.Split('/');

            if (parts.Length >= 2)
            {
                var fieldName = parts[0];
                var actualAlias = parts[1];

                _logger.LogDebug("Extracted field name: {FieldName}, alias: {Alias}", fieldName, actualAlias);
                return new AliasParseResult(fieldName, actualAlias);
            }
        }

        _logger.LogDebug("Using default field name: {DefaultFieldName}, alias: {Alias}", defaultFieldName, alias);
        return new AliasParseResult(defaultFieldName, alias);
    }

    /// <inheritdoc/>
    public string ExtractStoreFileNameFromProperties(string propertiesJson, string defaultFileName)
    {
        if (string.IsNullOrEmpty(propertiesJson))
        {
            _logger.LogDebug("Properties JSON is null or empty, using default: {DefaultFileName}", defaultFileName);
            return defaultFileName;
        }

        try
        {
            using var jsonDoc = System.Text.Json.JsonDocument.Parse(propertiesJson);

            if (jsonDoc.RootElement.TryGetProperty("StoreFileName", out var storeFileNameElement))
            {
                var value = storeFileNameElement.GetString();
                if (!string.IsNullOrEmpty(value))
                {
                    _logger.LogDebug("Found StoreFileName in properties: {StoreFileName}", value);
                    return value;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Error parsing StoreFileName from Properties: {Message}. Using default '{DefaultFileName}'",
                ex.Message, defaultFileName);
        }

        _logger.LogDebug("StoreFileName not found in properties, using default: {DefaultFileName}", defaultFileName);
        return defaultFileName;
    }
}
