// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SPKCS12;

/// <summary>
/// Serializer for PKCS12/PFX certificate stores in Kubernetes secrets.
/// Handles loading, saving, and manipulation of PKCS12 stores.
/// </summary>
internal class Pkcs12CertificateStoreSerializer : ICertificateStoreSerializer
{
    /// <summary>Logger instance for diagnostic output.</summary>
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the PKCS12 certificate store serializer.
    /// </summary>
    /// <param name="storeProperties">JSON string of store properties (currently unused).</param>
    public Pkcs12CertificateStoreSerializer(string storeProperties)
    {
        _logger = LogHandler.GetClassLogger(GetType());
    }

    /// <summary>
    /// Deserializes a PKCS12 keystore from byte data.
    /// </summary>
    /// <param name="storeContents">The PKCS12 keystore bytes.</param>
    /// <param name="storePath">Path to the store (for logging context).</param>
    /// <param name="storePassword">Password to decrypt the keystore.</param>
    /// <returns>A Pkcs12Store containing the certificates and keys.</returns>
    public Pkcs12Store DeserializeRemoteCertificateStore(byte[] storeContents, string storePath, string storePassword)
    {
        _logger.MethodEntry(MsLogLevel.Debug);

        var storeBuilder = new Pkcs12StoreBuilder();
        var store = storeBuilder.Build();

        using var ms = new MemoryStream(storeContents);
        _logger.LogDebug("Loading Pkcs12Store from MemoryStream from {Path}", storePath);
        store.Load(ms, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray());
        _logger.LogDebug("Pkcs12Store loaded from {Path}", storePath);
        _logger.MethodExit(MsLogLevel.Debug);
        return store;
    }

    /// <summary>
    /// Serializes a Pkcs12Store back to PKCS12 format for storage in Kubernetes.
    /// </summary>
    /// <param name="certificateStore">The Pkcs12Store to serialize.</param>
    /// <param name="storePath">Directory path for the store.</param>
    /// <param name="storeFileName">Filename for the serialized store.</param>
    /// <param name="storePassword">Password to encrypt the keystore.</param>
    /// <returns>List of SerializedStoreInfo containing the PKCS12 bytes and path.</returns>
    public List<SerializedStoreInfo> SerializeRemoteCertificateStore(Pkcs12Store certificateStore, string storePath,
        string storeFileName, string storePassword)
    {
        _logger.MethodEntry(MsLogLevel.Debug);

        var storeBuilder = new Pkcs12StoreBuilder();
        var pkcs12Store = storeBuilder.Build();

        foreach (var alias in certificateStore.Aliases)
        {
            _logger.LogDebug("Processing alias '{Alias}'", alias);
            var keyEntry = certificateStore.GetKey(alias);

            if (certificateStore.IsKeyEntry(alias))
            {
                _logger.LogDebug("Alias '{Alias}' is a key entry", alias);
                pkcs12Store.SetKeyEntry(alias, keyEntry, certificateStore.GetCertificateChain(alias));
            }
            else
            {
                _logger.LogDebug("Alias '{Alias}' is a certificate entry", alias);
                var certEntry = certificateStore.GetCertificate(alias);
                _logger.LogTrace("Certificate entry '{Entry}'", certEntry.Certificate.SubjectDN.ToString());
                _logger.LogDebug("Attempting to SetCertificateEntry for '{Alias}'", alias);
                pkcs12Store.SetCertificateEntry(alias, certEntry);
            }
        }

        using var outStream = new MemoryStream();
        _logger.LogDebug("Saving Pkcs12Store to MemoryStream");
        pkcs12Store.Save(outStream,
            string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray(),
            new SecureRandom());

        var storeInfo = new List<SerializedStoreInfo>();

        _logger.LogDebug("Adding store to list of serialized stores");
        var filePath = Path.Combine(storePath, storeFileName);
        _logger.LogDebug("Filepath '{Path}'", filePath);
        storeInfo.Add(new SerializedStoreInfo
        {
            FilePath = filePath,
            Contents = outStream.ToArray()
        });

        _logger.MethodExit(MsLogLevel.Debug);
        return storeInfo;
    }

    /// <summary>
    /// Returns the private key path (not applicable for PKCS12 stores).
    /// </summary>
    /// <returns>Always returns null for PKCS12 stores.</returns>
    public string GetPrivateKeyPath()
    {
        return null;
    }

    /// <summary>
    /// Creates a new PKCS12 store or updates an existing one with a new certificate.
    /// Handles both add and remove operations.
    /// </summary>
    /// <param name="newPkcs12Bytes">PKCS12 bytes containing the new certificate to add.</param>
    /// <param name="newCertPassword">Password for the new certificate's private key.</param>
    /// <param name="alias">Alias for the certificate entry in the store.</param>
    /// <param name="existingStore">Existing PKCS12 store bytes (null for new store).</param>
    /// <param name="existingStorePassword">Password for the existing store.</param>
    /// <param name="remove">True to remove the certificate, false to add.</param>
    /// <param name="includeChain">Whether to include the certificate chain.</param>
    /// <returns>The updated PKCS12 store as byte array.</returns>
    public byte[] CreateOrUpdatePkcs12(byte[] newPkcs12Bytes, string newCertPassword, string alias,
        byte[] existingStore = null, string existingStorePassword = null,
        bool remove = false, bool includeChain = true)
    {
        _logger.MethodEntry(MsLogLevel.Debug);

        _logger.LogDebug("Creating or updating PKCS12 store for alias '{Alias}'", alias);
        // If existingStore is null, create a new store
        var storeBuilder = new Pkcs12StoreBuilder();
        var existingPkcs12Store = storeBuilder.Build();
        var pkcs12StoreNew = storeBuilder.Build();
        var createdNewStore = false;

        // If existingStore is not null, load it into pkcs12Store
        if (existingStore != null)
        {
            _logger.LogDebug("Attempting to load existing Pkcs12Store");
            using var ms = new MemoryStream(existingStore);
            existingPkcs12Store.Load(ms,
                string.IsNullOrEmpty(existingStorePassword)
                    ? Array.Empty<char>()
                    : existingStorePassword.ToCharArray());
            _logger.LogDebug("Existing Pkcs12Store loaded");

            _logger.LogDebug("Checking if alias '{Alias}' exists in existingPkcs12Store", alias);
            if (existingPkcs12Store.ContainsAlias(alias))
            {
                // If alias exists, delete it from existingPkcs12Store
                _logger.LogDebug("Alias '{Alias}' exists in existingPkcs12Store", alias);
                _logger.LogDebug("Deleting alias '{Alias}' from existingPkcs12Store", alias);
                existingPkcs12Store.DeleteEntry(alias);
                if (remove)
                {
                    // If remove is true, save existingPkcs12Store and return
                    _logger.LogDebug("Alias '{Alias}' was removed from existing store", alias);
                    using var mms = new MemoryStream();
                    _logger.LogDebug("Saving removal operation");
                    existingPkcs12Store.Save(mms,
                        string.IsNullOrEmpty(existingStorePassword)
                            ? Array.Empty<char>()
                            : existingStorePassword.ToCharArray(), new SecureRandom());

                    _logger.LogDebug("Converting existingPkcs12Store to byte[] and returning");
                    _logger.MethodExit(MsLogLevel.Debug);
                    return mms.ToArray();
                }
            }
            else if (remove)
            {
                // If alias does not exist and remove is true, return existingStore
                _logger.LogDebug("Alias '{Alias}' does not exist in existingPkcs12Store, nothing to remove", alias);
                using var existingPkcs12StoreMs = new MemoryStream();
                existingPkcs12Store.Save(existingPkcs12StoreMs,
                    string.IsNullOrEmpty(existingStorePassword)
                        ? Array.Empty<char>()
                        : existingStorePassword.ToCharArray(),
                    new SecureRandom());

                _logger.LogDebug("Converting existingPkcs12Store to byte[] and returning");
                _logger.MethodExit(MsLogLevel.Debug);
                return existingPkcs12StoreMs.ToArray();
            }
        }
        else
        {
            _logger.LogDebug("Attempting to create new Pkcs12Store");
            createdNewStore = true;
        }

        var newCert = storeBuilder.Build();

        try
        {
            _logger.LogDebug("Attempting to load pkcs12 bytes");
            using var newPkcs12Ms = new MemoryStream(newPkcs12Bytes);
            newCert.Load(newPkcs12Ms,
                string.IsNullOrEmpty(newCertPassword) ? Array.Empty<char>() : newCertPassword.ToCharArray());
            _logger.LogDebug("pkcs12 bytes loaded");
        }
        catch (Exception)
        {
            _logger.LogError("Unknown error loading pkcs12 bytes, attempting to parse certificate");
            var certificateParser = new X509CertificateParser();
            var certificate = certificateParser.ReadCertificate(newPkcs12Bytes);
            _logger.LogDebug("Certificate parse successful, attempting to create new Pkcs12Store from certificate");

            // create new Pkcs12Store from certificate
            storeBuilder = new Pkcs12StoreBuilder();
            newCert = storeBuilder.Build();

            _logger.LogDebug("Attempting to set PKCS12 certificate entry using alias '{Alias}'", alias);
            newCert.SetCertificateEntry(alias, new X509CertificateEntry(certificate));
            _logger.LogDebug("PKCS12 certificate entry set using alias '{Alias}'", alias);
        }


        // Iterate through newCert aliases. WARNING: This assumes there is only one alias in the newCert
        _logger.LogTrace("Iterating through PKCS12 certificate aliases");
        foreach (var al in newCert.Aliases)
        {
            _logger.LogTrace("Handling alias {Alias}", al);
            if (newCert.IsKeyEntry(al))
            {
                _logger.LogDebug("Attempting to parse key for alias {Alias}", al);
                var keyEntry = newCert.GetKey(al);
                _logger.LogDebug("Key parsed for alias {Alias}", al);

                _logger.LogDebug("Attempting to parse certificate chain for alias {Alias}", al);
                var certificateChain = newCert.GetCertificateChain(al);
                if (!includeChain)
                {
                    _logger.LogDebug("includeChain is false, reducing certificate chain to only the end-entity certificate");
                    // If includeChain is false, reduce certificate chain to only the end-entity certificate
                    certificateChain =
                    [
                        new X509CertificateEntry(certificateChain[0].Certificate)
                    ];
                }
                _logger.LogDebug("Certificate chain parsed for alias {Alias}", al);
                if (createdNewStore)
                {
                    // If createdNewStore is true, create a new store
                    _logger.LogDebug("Attempting to set key entry for alias '{Alias}'", alias);
                    pkcs12StoreNew.SetKeyEntry(
                        alias,
                        keyEntry,
                        certificateChain
                    );
                }
                else
                {
                    // If createdNewStore is false, add to existingPkcs12Store
                    // check if alias exists in existingPkcs12Store
                    if (existingPkcs12Store.ContainsAlias(alias))
                    {
                        _logger.LogDebug("Removing existing entry for alias '{Alias}'", alias);
                        // If alias exists, delete it from existingPkcs12Store
                        existingPkcs12Store.DeleteEntry(alias);
                    }

                    _logger.LogDebug("Attempting to set key entry for alias '{Alias}'", alias);
                    existingPkcs12Store.SetKeyEntry(
                        alias,
                        keyEntry,
                        // string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray(),
                        certificateChain
                    );
                }
            }
            else
            {
                if (createdNewStore)
                {
                    _logger.LogDebug("Attempting to set certificate entry for alias '{Alias}'", alias);
                    pkcs12StoreNew.SetCertificateEntry(alias, newCert.GetCertificate(alias));
                }
                else
                {
                    _logger.LogDebug("Attempting to set certificate entry for alias '{Alias}'", alias);
                    existingPkcs12Store.SetCertificateEntry(alias, newCert.GetCertificate(alias));
                }
            }
        }

        using var outStream = new MemoryStream();
        if (createdNewStore)
        {
            _logger.LogDebug("Attempting to save new Pkcs12Store");
            pkcs12StoreNew.Save(outStream,
                string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray(),
                new SecureRandom());
            _logger.LogDebug("New Pkcs12Store saved");
        }
        else
        {
            _logger.LogDebug("Attempting to save existing Pkcs12Store");
            existingPkcs12Store.Save(outStream,
                string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray(),
                new SecureRandom());
            _logger.LogDebug("Existing Pkcs12Store saved");
        }
        // Return existingPkcs12Store as byte[]

        _logger.LogDebug("Converting existingPkcs12Store to byte[] and returning");
        _logger.MethodExit(MsLogLevel.Debug);
        return outStream.ToArray();
    }
}