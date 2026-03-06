// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.Serializers.K8SJKS;

/// <summary>
/// Serializer for Java KeyStore (JKS) certificate stores in Kubernetes secrets.
/// Handles conversion between JKS format and BouncyCastle's Pkcs12Store for internal processing.
/// </summary>
/// <remarks>
/// JKS stores are converted to PKCS12 internally because BouncyCastle provides better
/// manipulation capabilities for PKCS12 stores. The conversion is transparent to callers.
/// </remarks>
internal class JksCertificateStoreSerializer : ICertificateStoreSerializer
{
    /// <summary>Logger instance for diagnostic output.</summary>
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the JKS certificate store serializer.
    /// </summary>
    /// <param name="storeProperties">JSON string of store properties (currently unused).</param>
    public JksCertificateStoreSerializer(string storeProperties)
    {
        _logger = LogHandler.GetClassLogger(GetType());
    }

    /// <summary>
    /// Deserializes a JKS keystore from byte data into a Pkcs12Store for manipulation.
    /// Handles both true JKS format and PKCS12 format that may have been stored as JKS.
    /// </summary>
    /// <param name="storeContents">The JKS keystore bytes.</param>
    /// <param name="storePath">Path to the store (for logging context).</param>
    /// <param name="storePassword">Password to decrypt the keystore.</param>
    /// <returns>A Pkcs12Store containing the certificates and keys from the JKS.</returns>
    /// <exception cref="ArgumentException">Thrown when store password is null or empty.</exception>
    /// <exception cref="JkSisPkcs12Exception">Thrown when the data is actually PKCS12 format.</exception>
    public Pkcs12Store DeserializeRemoteCertificateStore(byte[] storeContents, string storePath, string storePassword)
    {
        _logger.MethodEntry(MsLogLevel.Debug);
        var storeBuilder = new Pkcs12StoreBuilder();
        var pkcs12Store = storeBuilder.Build();
        var pkcs12StoreNew = storeBuilder.Build();

        _logger.LogTrace("storePath: {Path}", storePath);
        
        if (string.IsNullOrEmpty(storePassword))
        {
            _logger.LogError("JKS store password is null or empty for store at path '{Path}'", storePath);
            throw new ArgumentException("JKS store password is null or empty");
        }

        _logger.LogTrace("StorePassword: {Password}", LoggingUtilities.RedactPassword(storePassword));
        _logger.LogTrace("Password correlation: {CorrelationId}", LoggingUtilities.GetPasswordCorrelationId(storePassword));

        var jksStore = new JksStore();

        _logger.LogDebug("Loading JKS store");
        try
        {
            _logger.LogTrace("Attempting to load JKS store with provided password");

            using (var ms = new MemoryStream(storeContents))
            {
                jksStore.Load(ms, string.IsNullOrEmpty(storePassword) ? [] : storePassword.ToCharArray());
            }

            _logger.LogDebug("JKS store loaded");
        }
        catch (Exception ex)
        {
            _logger.LogError("Error loading JKS store: {Ex}", ex.Message);
            if (ex.Message.Contains("password incorrect or store tampered with"))
            {
                if (storePassword == string.Empty)
                {
                    _logger.LogError("Unable to load JKS store using empty password, please provide a valid password");
                }
                else
                {
                    _logger.LogError("Unable to load JKS store using provided password: {Password}", LoggingUtilities.RedactPassword(storePassword));
                    _logger.LogTrace("Password correlation: {CorrelationId}", LoggingUtilities.GetPasswordCorrelationId(storePassword));
                }
                
                throw;
            }

            // Attempt to read JKS store as Pkcs12Store
            try
            {
                if (string.IsNullOrEmpty(storePassword))
                {
                    _logger.LogError("JKS store password is null or empty for store at path '{Path}'", storePath);
                    throw new ArgumentException("JKS store password is null or empty");
                }
                
                _logger.LogDebug("Attempting to load JKS store as Pkcs12Store using provided password");

                using (var ms = new MemoryStream(storeContents))
                {
                    pkcs12Store.Load(ms, string.IsNullOrEmpty(storePassword) ? [] : storePassword.ToCharArray());
                }

                _logger.LogDebug("JKS store loaded as Pkcs12Store");
                // return pkcs12Store;
                throw new JkSisPkcs12Exception("JKS store is actually a Pkcs12Store");
            }
            catch (Exception ex2)
            {
                _logger.LogError("Error loading JKS store as Jks or Pkcs12Store: {Ex}", ex2.Message);
                throw;
            }
        }

        _logger.LogDebug("Converting JKS store to Pkcs12Store ny iterating over aliases");
        foreach (var alias in jksStore.Aliases)
        {
            _logger.LogDebug("Processing alias '{Alias}'", alias);

            _logger.LogDebug("Getting key for alias '{Alias}'", alias);
            var keyParam = jksStore.GetKey(alias,
                string.IsNullOrEmpty(storePassword) ? [] : storePassword.ToCharArray());

            _logger.LogDebug("Creating AsymmetricKeyEntry for alias '{Alias}'", alias);
            var keyEntry = new AsymmetricKeyEntry(keyParam);

            if (jksStore.IsKeyEntry(alias))
            {
                _logger.LogDebug("Alias '{Alias}' is a key entry", alias);
                _logger.LogDebug("Getting certificate chain for alias '{Alias}'", alias);
                var certificateChain = jksStore.GetCertificateChain(alias);

                _logger.LogDebug("Adding key entry and certificate chain to Pkcs12Store");
                pkcs12Store.SetKeyEntry(alias, keyEntry,
                    certificateChain.Select(certificate => new X509CertificateEntry(certificate)).ToArray());
            }
            else
            {
                _logger.LogDebug("Alias '{Alias}' is a certificate entry", alias);
                _logger.LogDebug("Setting certificate for alias '{Alias}'", alias);
                pkcs12Store.SetCertificateEntry(alias, new X509CertificateEntry(jksStore.GetCertificate(alias)));
            }
        }

        // Second Pkcs12Store necessary because of an obscure BC bug where creating a Pkcs12Store without .Load (code above using "Set" methods only) does not set all
        // internal hashtables necessary to avoid an error later when processing store.
        var ms2 = new MemoryStream();
        _logger.LogDebug("Saving Pkcs12Store to MemoryStream using provided password");
        pkcs12Store.Save(ms2, string.IsNullOrEmpty(storePassword) ? [] : storePassword.ToCharArray(),
            new SecureRandom());
        ms2.Position = 0;

        _logger.LogDebug("Loading Pkcs12Store from MemoryStream");
        pkcs12StoreNew.Load(ms2, string.IsNullOrEmpty(storePassword) ? [] : storePassword.ToCharArray());

        _logger.LogDebug("Returning Pkcs12Store");
        _logger.MethodExit(MsLogLevel.Debug);
        return pkcs12StoreNew;
    }

    /// <summary>
    /// Serializes a Pkcs12Store back to JKS format for storage in Kubernetes.
    /// </summary>
    /// <param name="certificateStore">The Pkcs12Store to serialize.</param>
    /// <param name="storePath">Directory path for the store.</param>
    /// <param name="storeFileName">Filename for the serialized store.</param>
    /// <param name="storePassword">Password to encrypt the keystore.</param>
    /// <returns>List of SerializedStoreInfo containing the JKS bytes and path.</returns>
    public List<SerializedStoreInfo> SerializeRemoteCertificateStore(Pkcs12Store certificateStore, string storePath,
        string storeFileName, string storePassword)
    {
        _logger.MethodEntry(MsLogLevel.Debug);

        var jksStore = new JksStore();

        foreach (var alias in certificateStore.Aliases)
        {
            var keyEntry = certificateStore.GetKey(alias);
            var certificateChain = certificateStore.GetCertificateChain(alias);
            var certificates = new List<X509Certificate>();
            if (certificateStore.IsKeyEntry(alias))
            {
                certificates.AddRange(certificateChain.Select(certificateEntry => certificateEntry.Certificate));
                _logger.LogDebug("Processing key entry for alias '{Alias}' using provided password", alias);
                jksStore.SetKeyEntry(alias, keyEntry.Key,
                    string.IsNullOrEmpty(storePassword) ? [] : storePassword.ToCharArray(), certificates.ToArray());
            }
            else
            {
                jksStore.SetCertificateEntry(alias, certificateStore.GetCertificate(alias).Certificate);
            }
        }

        using var outStream = new MemoryStream();
        _logger.LogDebug("Saving JKS store to MemoryStream using provided password");
        jksStore.Save(outStream, string.IsNullOrEmpty(storePassword) ? [] : storePassword.ToCharArray());

        var storeInfo = new List<SerializedStoreInfo>
            { new() { FilePath = Path.Combine(storePath, storeFileName), Contents = outStream.ToArray() } };

        _logger.MethodExit(MsLogLevel.Debug);
        return storeInfo;
    }

    /// <summary>
    /// Returns the private key path (not applicable for JKS stores).
    /// </summary>
    /// <returns>Always returns null for JKS stores.</returns>
    public string GetPrivateKeyPath()
    {
        return null;
    }

    /// <summary>
    /// Creates a new JKS store or updates an existing one with a new certificate.
    /// Handles both add and remove operations.
    /// </summary>
    /// <param name="newPkcs12Bytes">PKCS12 bytes containing the new certificate to add.</param>
    /// <param name="newCertPassword">Password for the new certificate's private key.</param>
    /// <param name="alias">Alias for the certificate entry in the JKS.</param>
    /// <param name="existingStore">Existing JKS store bytes (null for new store).</param>
    /// <param name="existingStorePassword">Password for the existing store.</param>
    /// <param name="remove">True to remove the certificate, false to add.</param>
    /// <param name="includeChain">Whether to include the certificate chain.</param>
    /// <returns>The updated JKS store as byte array.</returns>
    /// <exception cref="JkSisPkcs12Exception">Thrown when the existing store is actually PKCS12 format.</exception>
    public byte[] CreateOrUpdateJks(byte[] newPkcs12Bytes, string newCertPassword, string alias,
        byte[] existingStore = null, string existingStorePassword = null,
        bool remove = false, bool includeChain = true)
    {
        _logger.MethodEntry(MsLogLevel.Debug);
        // If existingStore is null, create a new store
        var existingJksStore = new JksStore();
        var newJksStore = new JksStore();
        var createdNewStore = false;

        _logger.LogTrace("alias: {Alias}", alias);
        _logger.LogTrace("newCertPassword: {Password}", LoggingUtilities.RedactPassword(newCertPassword));
        _logger.LogTrace("existingStorePassword: {Password}", LoggingUtilities.RedactPassword(existingStorePassword));

        // If existingStore is not null, load it into jksStore
        if (existingStore != null)
        {
            _logger.LogDebug("Loading existing JKS store");
            using var ms = new MemoryStream(existingStore);

            try
            {
                existingJksStore.Load(ms,
                    string.IsNullOrEmpty(existingStorePassword) ? [] : existingStorePassword.ToCharArray());
            }
            catch (Exception ex)
            {
                _logger.LogError("Error loading existing JKS store: {Ex}", ex.Message);

                if (ex.Message.Contains("password incorrect or store tampered with"))
                {
                    _logger.LogError("Unable to load existing JKS store using provided password: {Password}", LoggingUtilities.RedactPassword(existingStorePassword));
                    _logger.LogTrace("Password correlation: {CorrelationId}", LoggingUtilities.GetPasswordCorrelationId(existingStorePassword));
                    throw;
                }

                try
                {
                    _logger.LogDebug("Attempting to load existing JKS store as Pkcs12Store");
                    var pkcs12Store = new Pkcs12StoreBuilder().Build();
                    using (var ms2 = new MemoryStream(existingStore))
                    {
                        pkcs12Store.Load(ms2,
                            string.IsNullOrEmpty(existingStorePassword) ? [] : existingStorePassword.ToCharArray());
                    }

                    _logger.LogDebug("Existing JKS store loaded as Pkcs12Store");
                    // return pkcs12Store;
                    throw new JkSisPkcs12Exception("Existing JKS store is actually a Pkcs12Store");
                }
                catch (Exception ex2)
                {
                    _logger.LogError("Error loading existing JKS store as Jks or Pkcs12Store: {Ex}", ex2.Message);
                    throw;
                }
            }

            if (existingJksStore.ContainsAlias(alias))
            {
                // If alias exists, delete it from existingJksStore
                _logger.LogDebug("Alias '{Alias}' exists in existing JKS store, deleting it", alias);
                existingJksStore.DeleteEntry(alias);
                if (remove)
                {
                    // If remove is true, save existingJksStore and return
                    _logger.LogDebug("This is a removal operation, saving existing JKS store");
                    using var mms = new MemoryStream();
                    existingJksStore.Save(mms,
                        string.IsNullOrEmpty(existingStorePassword) ? [] : existingStorePassword.ToCharArray());
                    _logger.LogDebug("Returning existing JKS store");
                    return mms.ToArray();
                }
            }
            else if (remove)
            {
                // If alias does not exist and remove is true, return existingStore
                _logger.LogDebug(
                    "Alias '{Alias}' does not exist in existing JKS store and this is a removal operation, returning existing JKS store as-is",
                    alias);
                using var mms = new MemoryStream();
                existingJksStore.Save(mms,
                    string.IsNullOrEmpty(existingStorePassword) ? [] : existingStorePassword.ToCharArray());
                return mms.ToArray();
            }
        }
        else
        {
            _logger.LogDebug("Existing JKS store is null, creating new JKS store");
            createdNewStore = true;
        }

        // Create new Pkcs12Store from newPkcs12Bytes
        var storeBuilder = new Pkcs12StoreBuilder();
        var newCert = storeBuilder.Build();

        try
        {
            _logger.LogDebug("Loading new Pkcs12Store from newPkcs12Bytes");
            _logger.LogTrace("PKCS12 data: {Data}", LoggingUtilities.RedactPkcs12Bytes(newPkcs12Bytes));
            using var pkcs12Ms = new MemoryStream(newPkcs12Bytes);
            if (pkcs12Ms.Length != 0) newCert.Load(pkcs12Ms, (newCertPassword ?? string.Empty).ToCharArray());
        }
        catch (Exception)
        {
            _logger.LogDebug("Loading new Pkcs12Store from newPkcs12Bytes failed, trying to load as X509Certificate");
            var certificateParser = new X509CertificateParser();
            var certificate = certificateParser.ReadCertificate(newPkcs12Bytes);

            _logger.LogDebug("Creating new Pkcs12Store from certificate");
            // create new Pkcs12Store from certificate
            storeBuilder = new Pkcs12StoreBuilder();
            newCert = storeBuilder.Build();
            _logger.LogDebug("Setting certificate entry in new Pkcs12Store as alias '{Alias}'", alias);
            newCert.SetCertificateEntry(alias, new X509CertificateEntry(certificate));
        }


        // Iterate through newCert aliases.
        _logger.LogDebug("Iterating through new Pkcs12Store aliases");
        foreach (var al in newCert.Aliases)
        {
            _logger.LogTrace("Alias: {Alias}", al);
            if (newCert.IsKeyEntry(al))
            {
                _logger.LogDebug("Alias '{Alias}' is a key entry, getting key entry and certificate chain", al);
                var keyEntry = newCert.GetKey(al);
                _logger.LogDebug("Getting certificate chain for alias '{Alias}'", al);
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

                _logger.LogDebug("Creating certificate list from certificate chain");
                var certificates = certificateChain.Select(certificateEntry => certificateEntry.Certificate).ToList();

                if (createdNewStore)
                {
                    // If createdNewStore is true, create a new store
                    _logger.LogDebug("Created new JKS store, setting key entry for alias '{Alias}'", al);
                    newJksStore.SetKeyEntry(alias,
                        keyEntry.Key,
                        string.IsNullOrEmpty(existingStorePassword) ? [] : existingStorePassword.ToCharArray(),
                        certificates.ToArray());
                }
                else
                {
                    // If createdNewStore is false, add to existingJksStore
                    // check if alias exists in existingJksStore
                    if (existingJksStore.ContainsAlias(alias))
                    {
                        // If alias exists, delete it from existingJksStore
                        _logger.LogDebug("Alias '{Alias}' exists in existing JKS store, deleting it", alias);
                        existingJksStore.DeleteEntry(alias);
                    }

                    _logger.LogDebug("Setting key entry for alias '{Alias}'", alias);
                    existingJksStore.SetKeyEntry(alias,
                        keyEntry.Key,
                        string.IsNullOrEmpty(existingStorePassword) ? [] : existingStorePassword.ToCharArray(),
                        certificates.ToArray());
                }
            }
            else
            {
                if (createdNewStore)
                {
                    _logger.LogDebug("Created new JKS store, setting certificate entry for alias '{Alias}'", alias);
                    _logger.LogDebug("Setting certificate entry for new JKS store, alias '{Alias}'", alias);
                    newJksStore.SetCertificateEntry(alias, newCert.GetCertificate(alias).Certificate);
                }
                else
                {
                    _logger.LogDebug("Setting certificate entry for existing JKS store, alias '{Alias}'", alias);
                    existingJksStore.SetCertificateEntry(alias, newCert.GetCertificate(alias).Certificate);
                }
            }
        }

        using var outStream = new MemoryStream();
        if (createdNewStore)
        {
            _logger.LogDebug("Created new JKS store, saving it to outStream");
            newJksStore.Save(outStream,
                string.IsNullOrEmpty(existingStorePassword) ? [] : existingStorePassword.ToCharArray());
        }
        else
        {
            _logger.LogDebug("Saving existing JKS store to outStream");
            existingJksStore.Save(outStream,
                string.IsNullOrEmpty(existingStorePassword) ? [] : existingStorePassword.ToCharArray());
        }

        // Return existingJksStore as byte[]
        _logger.LogDebug("JKS store operation complete");
        _logger.MethodExit(MsLogLevel.Debug);
        return outStream.ToArray();
    }
}