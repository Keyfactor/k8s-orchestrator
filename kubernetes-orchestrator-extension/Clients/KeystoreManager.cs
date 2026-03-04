// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.IO;
using System.Text;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.Clients;

/// <summary>
/// Manages PKCS12 and JKS keystore operations.
/// Provides methods for loading, searching, and manipulating keystore entries.
/// </summary>
public class KeystoreManager
{
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of KeystoreManager.
    /// </summary>
    /// <param name="logger">Logger instance for diagnostic output.</param>
    public KeystoreManager(ILogger logger = null)
    {
        _logger = logger ?? LogHandler.GetClassLogger<KeystoreManager>();
    }

    /// <summary>
    /// Loads a PKCS12 store from byte array.
    /// </summary>
    /// <param name="pkcs12Bytes">The PKCS12 data.</param>
    /// <param name="password">The password to unlock the store.</param>
    /// <returns>The loaded Pkcs12Store, or null if data is empty.</returns>
    public Pkcs12Store LoadPkcs12Store(byte[] pkcs12Bytes, string password)
    {
        if (pkcs12Bytes == null || pkcs12Bytes.Length == 0)
        {
            _logger.LogDebug("PKCS12 bytes are null or empty");
            return null;
        }

        var storeBuilder = new Pkcs12StoreBuilder();
        var store = storeBuilder.Build();

        using var ms = new MemoryStream(pkcs12Bytes);
        store.Load(ms, password?.ToCharArray() ?? Array.Empty<char>());

        _logger.LogDebug("Loaded PKCS12 store with {Count} entries", store.Count);
        return store;
    }

    /// <summary>
    /// Saves a PKCS12 store to byte array.
    /// </summary>
    /// <param name="store">The store to save.</param>
    /// <param name="password">The password to protect the store.</param>
    /// <returns>The PKCS12 data as byte array.</returns>
    public byte[] SavePkcs12Store(Pkcs12Store store, string password)
    {
        if (store == null)
            return Array.Empty<byte>();

        using var outStream = new MemoryStream();
        store.Save(outStream, password?.ToCharArray() ?? Array.Empty<char>(), new SecureRandom());
        return outStream.ToArray();
    }

    /// <summary>
    /// Creates an empty PKCS12 store.
    /// </summary>
    /// <returns>An empty Pkcs12Store.</returns>
    public Pkcs12Store CreateEmptyStore()
    {
        var storeBuilder = new Pkcs12StoreBuilder();
        return storeBuilder.Build();
    }

    /// <summary>
    /// Finds an alias in the store by Common Name (CN).
    /// </summary>
    /// <param name="store">The store to search.</param>
    /// <param name="cn">The Common Name to find.</param>
    /// <returns>The matching alias, or null if not found.</returns>
    public string FindAliasByCn(Pkcs12Store store, string cn)
    {
        if (store == null || string.IsNullOrEmpty(cn))
            return null;

        _logger.LogTrace("Searching for alias by CN: {CN}", cn);

        foreach (var alias in store.Aliases)
        {
            var aliasStr = alias.ToString();
            var cert = store.GetCertificate(aliasStr)?.Certificate;
            if (cert == null) continue;

            var certCn = ExtractCn(cert.SubjectDN.ToString());
            if (certCn?.Equals(cn, StringComparison.OrdinalIgnoreCase) == true)
            {
                _logger.LogDebug("Found alias {Alias} for CN {CN}", aliasStr, cn);
                return aliasStr;
            }
        }

        _logger.LogDebug("No alias found for CN {CN}", cn);
        return null;
    }

    /// <summary>
    /// Finds an alias in the store by certificate thumbprint.
    /// </summary>
    /// <param name="store">The store to search.</param>
    /// <param name="thumbprint">The thumbprint to find.</param>
    /// <returns>The matching alias, or null if not found.</returns>
    public string FindAliasByThumbprint(Pkcs12Store store, string thumbprint)
    {
        if (store == null || string.IsNullOrEmpty(thumbprint))
            return null;

        _logger.LogTrace("Searching for alias by thumbprint: {Thumbprint}", thumbprint);

        foreach (var alias in store.Aliases)
        {
            var aliasStr = alias.ToString();
            var cert = store.GetCertificate(aliasStr)?.Certificate;
            if (cert == null) continue;

            var certThumbprint = CalculateThumbprint(cert);
            if (certThumbprint?.Equals(thumbprint, StringComparison.OrdinalIgnoreCase) == true)
            {
                _logger.LogDebug("Found alias {Alias} for thumbprint {Thumbprint}", aliasStr, thumbprint);
                return aliasStr;
            }
        }

        _logger.LogDebug("No alias found for thumbprint {Thumbprint}", thumbprint);
        return null;
    }

    /// <summary>
    /// Finds an alias in the store by name (exact or partial match).
    /// </summary>
    /// <param name="store">The store to search.</param>
    /// <param name="aliasSearch">The alias name to find.</param>
    /// <returns>The matching alias, or null if not found.</returns>
    public string FindAliasByName(Pkcs12Store store, string aliasSearch)
    {
        if (store == null || string.IsNullOrEmpty(aliasSearch))
            return null;

        _logger.LogTrace("Searching for alias by name: {AliasSearch}", aliasSearch);

        // First try exact match
        if (store.ContainsAlias(aliasSearch))
        {
            _logger.LogDebug("Found exact alias match: {Alias}", aliasSearch);
            return aliasSearch;
        }

        // Try case-insensitive match
        foreach (var alias in store.Aliases)
        {
            var aliasStr = alias.ToString();
            if (aliasStr.Equals(aliasSearch, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogDebug("Found case-insensitive alias match: {Alias}", aliasStr);
                return aliasStr;
            }
        }

        // Try by thumbprint
        var thumbprintMatch = FindAliasByThumbprint(store, aliasSearch);
        if (thumbprintMatch != null)
            return thumbprintMatch;

        // Try by CN
        var cnMatch = FindAliasByCn(store, aliasSearch);
        if (cnMatch != null)
            return cnMatch;

        _logger.LogDebug("No alias found for search: {AliasSearch}", aliasSearch);
        return null;
    }

    /// <summary>
    /// Deletes an entry from the store.
    /// </summary>
    /// <param name="store">The store to modify.</param>
    /// <param name="alias">The alias of the entry to delete.</param>
    /// <returns>True if the entry was deleted, false if not found.</returns>
    public bool DeleteEntry(Pkcs12Store store, string alias)
    {
        if (store == null || string.IsNullOrEmpty(alias))
            return false;

        var foundAlias = FindAliasByName(store, alias);
        if (foundAlias == null)
        {
            _logger.LogDebug("Entry not found for deletion: {Alias}", alias);
            return false;
        }

        store.DeleteEntry(foundAlias);
        _logger.LogDebug("Deleted entry: {Alias}", foundAlias);
        return true;
    }

    /// <summary>
    /// Calculates the SHA1 thumbprint of a certificate.
    /// </summary>
    private string CalculateThumbprint(X509Certificate cert)
    {
        if (cert == null) return null;

        try
        {
            var certBytes = cert.GetEncoded();
            using var sha1 = System.Security.Cryptography.SHA1.Create();
            var hash = sha1.ComputeHash(certBytes);
            return BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to calculate thumbprint: {Error}", ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Extracts the Common Name from a DN string.
    /// </summary>
    private string ExtractCn(string dn)
    {
        if (string.IsNullOrEmpty(dn))
            return null;

        const string cnPrefix = "CN=";
        var startIndex = dn.IndexOf(cnPrefix, StringComparison.OrdinalIgnoreCase);
        if (startIndex < 0)
            return null;

        startIndex += cnPrefix.Length;
        var endIndex = dn.IndexOf(',', startIndex);
        if (endIndex < 0)
            endIndex = dn.Length;

        return dn.Substring(startIndex, endIndex - startIndex).Trim();
    }
}
