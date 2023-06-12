// Copyright 2023 Keyfactor
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
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SJKS
{
    class JksCertificateStoreSerializer : ICertificateStoreSerializer
    {
        private readonly ILogger _logger;
        public JksCertificateStoreSerializer(string storeProperties)
        {
            _logger = LogHandler.GetClassLogger(GetType());
        }

        public Pkcs12Store DeserializeRemoteCertificateStore(byte[] storeContents, string storePath, string storePassword)
        {
            _logger.LogDebug("Entering DeserializeRemoteCertificateStore");
            var storeBuilder = new Pkcs12StoreBuilder();
            var pkcs12Store = storeBuilder.Build();
            var pkcs12StoreNew = storeBuilder.Build();

            _logger.LogTrace("storePath: {Path}", storePath);
            // _logger.LogTrace("storePassword: {Pass}", storePassword ?? "null");
            var hashedStorePassword = GetSHA256Hash(storePassword);
            _logger.LogTrace("hashedStorePassword: {Pass}", hashedStorePassword ?? "null");
            
            var jksStore = new JksStore();

            _logger.LogDebug("Loading JKS store");
            try
            {
                _logger.LogTrace("Attempting to load JKS store w/ password '{Pass}'", hashedStorePassword ?? "null");
                using (var ms = new MemoryStream(storeContents))
                {
                    jksStore.Load(ms, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray());
                }
                _logger.LogDebug("JKS store loaded");                
            } catch (Exception ex)
            {
                _logger.LogError("Error loading JKS store: {Ex}", ex.Message);
                
                // Attempt to read JKS store as Pkcs12Store
                try
                {
                    _logger.LogTrace("Attempting to load JKS store as Pkcs12Store w/ password '{Pass}'", hashedStorePassword ?? "null");
                    using (var ms = new MemoryStream(storeContents))
                    {
                        pkcs12Store.Load(ms, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray());
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
                var keyParam = jksStore.GetKey(alias, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray());
                
                _logger.LogDebug("Creating AsymmetricKeyEntry for alias '{Alias}'", alias);
                var keyEntry = new AsymmetricKeyEntry(keyParam);
                
                if (jksStore.IsKeyEntry(alias))
                {
                    _logger.LogDebug("Alias '{Alias}' is a key entry", alias);
                    _logger.LogDebug("Getting certificate chain for alias '{Alias}'", alias);
                    var certificateChain = jksStore.GetCertificateChain(alias);

                    _logger.LogDebug("Adding key entry and certificate chain to Pkcs12Store");
                    pkcs12Store.SetKeyEntry(alias, keyEntry, certificateChain.Select(certificate => new X509CertificateEntry(certificate)).ToArray());
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
            _logger.LogDebug("Saving Pkcs12Store to MemoryStream");
            pkcs12Store.Save(ms2, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray(), new SecureRandom());
            ms2.Position = 0;

            _logger.LogDebug("Loading Pkcs12Store from MemoryStream");
            pkcs12StoreNew.Load(ms2, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray());

            _logger.LogDebug("Returning Pkcs12Store");
            return pkcs12StoreNew;
        }
        
        public byte[] CreateOrUpdateJks(byte[] newPkcs12Bytes, string newCertPassword, string alias, byte[] existingStore = null, string existingStorePassword = null,
            bool remove = false)
        {
            _logger.LogDebug("Entering CreateOrUpdateJks");
            // If existingStore is null, create a new store
            var existingJksStore = new JksStore();
            var newJksStore = new JksStore();
            var createdNewStore = false;
            
            var hashedNewCertPassword = GetSHA256Hash(newCertPassword);
            var hashedExistingStorePassword = GetSHA256Hash(existingStorePassword);
            
            _logger.LogTrace("newCertPassword: {Pass}", hashedNewCertPassword ?? "null");
            _logger.LogTrace("alias: {Alias}", alias);
            _logger.LogTrace("existingStorePassword: {Pass}", hashedExistingStorePassword ?? "null");

            // If existingStore is not null, load it into jksStore
            if (existingStore != null)
            {
                _logger.LogDebug("Loading existing JKS store");
                using var ms = new MemoryStream(existingStore);

                existingJksStore.Load(ms, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
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
                        existingJksStore.Save(mms, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
                        _logger.LogDebug("Returning existing JKS store");
                        return mms.ToArray();
                    }
                }
                else if (remove)
                {
                    // If alias does not exist and remove is true, return existingStore
                    _logger.LogDebug("Alias '{Alias}' does not exist in existing JKS store and this is a removal operation, returning existing JKS store as-is", alias);
                    using var mms = new MemoryStream();
                    existingJksStore.Save(mms, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
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
                _logger.LogTrace("hashedNewCertPassword: {Pass}", hashedNewCertPassword ?? "null");
                using var pkcs12Ms = new MemoryStream(newPkcs12Bytes);
                newCert.Load(pkcs12Ms, string.IsNullOrEmpty(newCertPassword) ? Array.Empty<char>() : newCertPassword.ToCharArray());
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

                    _logger.LogDebug("Creating certificate list from certificate chain");
                    var certificates = certificateChain.Select(certificateEntry => certificateEntry.Certificate).ToList();

                    if (createdNewStore)
                    {
                        // If createdNewStore is true, create a new store
                        _logger.LogDebug("Created new JKS store, setting key entry for alias '{Alias}'", al);
                        newJksStore.SetKeyEntry(alias,
                            keyEntry.Key,
                            string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray(),
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
                            string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray(),
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
                newJksStore.Save(outStream, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
            }
            else
            {
                _logger.LogDebug("Saving existing JKS store to outStream");
                existingJksStore.Save(outStream, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
            }
            // Return existingJksStore as byte[]
            _logger.LogDebug("Returning JKS store as byte[]");
            return outStream.ToArray();
        }
        public List<SerializedStoreInfo> SerializeRemoteCertificateStore(Pkcs12Store certificateStore, string storePath, string storeFileName, string storePassword)
        {
            _logger.MethodEntry(LogLevel.Debug);

            var jksStore = new JksStore();

            foreach (var alias in certificateStore.Aliases)
            {
                var keyEntry = certificateStore.GetKey(alias);
                var certificateChain = certificateStore.GetCertificateChain(alias);
                var certificates = new List<X509Certificate>();
                if (certificateStore.IsKeyEntry(alias))
                {

                    certificates.AddRange(certificateChain.Select(certificateEntry => certificateEntry.Certificate));

                    jksStore.SetKeyEntry(alias, keyEntry.Key, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray(), certificates.ToArray());
                }
                else
                {
                    jksStore.SetCertificateEntry(alias, certificateStore.GetCertificate(alias).Certificate);
                }
            }

            using var outStream = new MemoryStream();
            jksStore.Save(outStream, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray());

            var storeInfo = new List<SerializedStoreInfo>();
            storeInfo.Add(new SerializedStoreInfo() { FilePath = storePath + storeFileName, Contents = outStream.ToArray() });

            _logger.MethodExit(LogLevel.Debug);
            return storeInfo;

        }

        public string GetPrivateKeyPath()
        {
            return null;
        }
        
        public string GetSHA256Hash(string input)
        {
            var passwordHashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(input));
            var passwordHash = BitConverter.ToString(passwordHashBytes).Replace("-", "").ToLower();
            return passwordHash;
        }
    }
}
