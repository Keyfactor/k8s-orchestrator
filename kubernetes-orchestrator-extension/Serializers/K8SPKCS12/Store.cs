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

namespace Keyfactor.Extensions.Orchestrator.K8S.Serializers.K8SPKCS12;

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
        _logger.LogDebug("CreateOrUpdatePkcs12: alias='{Alias}', remove={Remove}, includeChain={IncludeChain}", alias, remove, includeChain);
        var passwordChars = PasswordToChars(existingStorePassword);

        // Load or create the target PKCS12 store
        var storeBuilder = new Pkcs12StoreBuilder();
        var targetStore = storeBuilder.Build();

        if (existingStore != null)
        {
            using var ms = new MemoryStream(existingStore);
            targetStore.Load(ms, passwordChars);

            // Handle removal or alias cleanup
            if (targetStore.ContainsAlias(alias))
            {
                _logger.LogDebug("Deleting existing alias '{Alias}'", alias);
                targetStore.DeleteEntry(alias);
                if (remove) return SavePkcs12Store(targetStore, passwordChars);
            }
            else if (remove)
            {
                _logger.LogDebug("Alias '{Alias}' not found, nothing to remove", alias);
                return SavePkcs12Store(targetStore, passwordChars);
            }
        }

        // Parse the new certificate from PKCS12 bytes
        var newCert = LoadNewCertificate(storeBuilder, newPkcs12Bytes, newCertPassword, alias);

        // Add entries from new certificate to target store
        foreach (var al in newCert.Aliases)
        {
            if (newCert.IsKeyEntry(al))
            {
                var keyEntry = newCert.GetKey(al);
                var certificateChain = newCert.GetCertificateChain(al);
                if (!includeChain)
                    certificateChain = [new X509CertificateEntry(certificateChain[0].Certificate)];

                if (targetStore.ContainsAlias(alias))
                    targetStore.DeleteEntry(alias);

                targetStore.SetKeyEntry(alias, keyEntry, certificateChain);
            }
            else
            {
                targetStore.SetCertificateEntry(alias, newCert.GetCertificate(alias));
            }
        }

        return SavePkcs12Store(targetStore, passwordChars);
    }

    /// <summary>
    /// Loads a new certificate from PKCS12 bytes, falling back to raw X509 parsing.
    /// </summary>
    private Pkcs12Store LoadNewCertificate(Pkcs12StoreBuilder storeBuilder, byte[] pkcs12Bytes, string password, string alias)
    {
        var newCert = storeBuilder.Build();

        try
        {
            using var ms = new MemoryStream(pkcs12Bytes);
            newCert.Load(ms, PasswordToChars(password));
        }
        catch (Exception)
        {
            _logger.LogDebug("PKCS12 load failed, parsing as raw X509 certificate");
            var certificate = new X509CertificateParser().ReadCertificate(pkcs12Bytes);
            newCert = storeBuilder.Build();
            newCert.SetCertificateEntry(alias, new X509CertificateEntry(certificate));
        }

        return newCert;
    }

    /// <summary>
    /// Saves a PKCS12 store to a byte array.
    /// </summary>
    private static byte[] SavePkcs12Store(Pkcs12Store store, char[] password)
    {
        using var ms = new MemoryStream();
        store.Save(ms, password, new SecureRandom());
        return ms.ToArray();
    }

    /// <summary>
    /// Converts a password string to char array, handling null/empty.
    /// </summary>
    private static char[] PasswordToChars(string password)
    {
        return string.IsNullOrEmpty(password) ? Array.Empty<char>() : password.ToCharArray();
    }
}