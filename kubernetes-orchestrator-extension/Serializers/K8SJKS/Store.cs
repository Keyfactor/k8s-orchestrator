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
        _logger.LogDebug("CreateOrUpdateJks: alias='{Alias}', remove={Remove}, includeChain={IncludeChain}", alias, remove, includeChain);
        var passwordChars = PasswordToChars(existingStorePassword);

        // Load or create the target JKS store
        var targetStore = new JksStore();
        if (existingStore != null)
        {
            LoadExistingJksStore(targetStore, existingStore, existingStorePassword);

            // Handle removal or alias cleanup
            if (targetStore.ContainsAlias(alias))
            {
                _logger.LogDebug("Deleting existing alias '{Alias}'", alias);
                targetStore.DeleteEntry(alias);
                if (remove)
                {
                    _logger.MethodExit(MsLogLevel.Debug);
                    return SaveJksStore(targetStore, passwordChars);
                }
            }
            else if (remove)
            {
                _logger.LogDebug("Alias '{Alias}' not found, nothing to remove", alias);
                _logger.MethodExit(MsLogLevel.Debug);
                return SaveJksStore(targetStore, passwordChars);
            }
        }

        // Parse the new certificate from PKCS12 bytes
        var newCert = LoadNewCertificate(newPkcs12Bytes, newCertPassword, alias);

        // Add entries from new certificate to target store
        foreach (var al in newCert.Aliases)
        {
            if (newCert.IsKeyEntry(al))
            {
                var keyEntry = newCert.GetKey(al);
                var certificateChain = newCert.GetCertificateChain(al);
                if (!includeChain)
                    certificateChain = [new X509CertificateEntry(certificateChain[0].Certificate)];

                var certificates = certificateChain.Select(e => e.Certificate).ToArray();

                if (targetStore.ContainsAlias(alias))
                    targetStore.DeleteEntry(alias);

                targetStore.SetKeyEntry(alias, keyEntry.Key, passwordChars, certificates);
            }
            else
            {
                targetStore.SetCertificateEntry(alias, newCert.GetCertificate(alias).Certificate);
            }
        }

        var result = SaveJksStore(targetStore, passwordChars);
        _logger.MethodExit(MsLogLevel.Debug);
        return result;
    }

    /// <summary>
    /// Loads an existing JKS store, falling back to PKCS12 detection.
    /// </summary>
    private void LoadExistingJksStore(JksStore jksStore, byte[] storeBytes, string password)
    {
        _logger.MethodEntry(MsLogLevel.Debug);
        try
        {
            using var ms = new MemoryStream(storeBytes);
            jksStore.Load(ms, PasswordToChars(password));
            _logger.MethodExit(MsLogLevel.Debug);
        }
        catch (Exception ex)
        {
            if (ex.Message.Contains("password incorrect or store tampered with"))
            {
                _logger.LogError("Unable to load JKS store: incorrect password");
                throw;
            }

            // Check if it's actually PKCS12 format
            try
            {
                var pkcs12Store = new Pkcs12StoreBuilder().Build();
                using var ms2 = new MemoryStream(storeBytes);
                pkcs12Store.Load(ms2, PasswordToChars(password));
                throw new JkSisPkcs12Exception("Existing JKS store is actually a Pkcs12Store");
            }
            catch (JkSisPkcs12Exception) { throw; }
            catch (Exception ex2)
            {
                _logger.LogError("Error loading store as JKS or PKCS12: {Error}", ex2.Message);
                throw;
            }
        }
    }

    /// <summary>
    /// Loads a new certificate from PKCS12 bytes, falling back to raw X509 parsing.
    /// </summary>
    private Pkcs12Store LoadNewCertificate(byte[] pkcs12Bytes, string password, string alias)
    {
        _logger.MethodEntry(MsLogLevel.Debug);
        var storeBuilder = new Pkcs12StoreBuilder();
        var newCert = storeBuilder.Build();

        try
        {
            using var ms = new MemoryStream(pkcs12Bytes);
            if (ms.Length != 0) newCert.Load(ms, (password ?? string.Empty).ToCharArray());
        }
        catch (Exception)
        {
            _logger.LogDebug("PKCS12 load failed, parsing as raw X509 certificate");
            var certificate = new X509CertificateParser().ReadCertificate(pkcs12Bytes);
            newCert = storeBuilder.Build();
            newCert.SetCertificateEntry(alias, new X509CertificateEntry(certificate));
        }

        _logger.MethodExit(MsLogLevel.Debug);
        return newCert;
    }

    /// <summary>
    /// Saves a JKS store to a byte array.
    /// </summary>
    private static byte[] SaveJksStore(JksStore store, char[] password)
    {
        using var ms = new MemoryStream();
        store.Save(ms, password);
        return ms.ToArray();
    }

    /// <summary>
    /// Converts a password string to char array, handling null/empty.
    /// </summary>
    private static char[] PasswordToChars(string password)
    {
        return string.IsNullOrEmpty(password) ? [] : password.ToCharArray();
    }
}