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
using System.Text;
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
        private ILogger _logger;
        public JksCertificateStoreSerializer(string storeProperties)
        {
            _logger = LogHandler.GetClassLogger(GetType());
        }

        public Pkcs12Store DeserializeRemoteCertificateStore(byte[] storeContents, string storePath, string storePassword)
        {
            _logger.MethodEntry(LogLevel.Debug);

            var storeBuilder = new Pkcs12StoreBuilder();
            var pkcs12Store = storeBuilder.Build();
            var pkcs12StoreNew = storeBuilder.Build();

            var jksStore = new JksStore();

            using (var ms = new MemoryStream(storeContents))
            {
                jksStore.Load(ms, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray());
            }

            foreach (var alias in jksStore.Aliases)
            {
                var keyParam = jksStore.GetKey(alias, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray());
                var keyEntry = new AsymmetricKeyEntry(keyParam);
                if (jksStore.IsKeyEntry(alias))
                {

                    var certificateChain = jksStore.GetCertificateChain(alias);

                    pkcs12Store.SetKeyEntry(alias, keyEntry, certificateChain.Select(certificate => new X509CertificateEntry(certificate)).ToArray());
                }
                else
                {
                    pkcs12Store.SetCertificateEntry(alias, new X509CertificateEntry(jksStore.GetCertificate(alias)));
                }
            }

            // Second Pkcs12Store necessary because of an obscure BC bug where creating a Pkcs12Store without .Load (code above using "Set" methods only) does not set all
            // internal hashtables necessary to avoid an error later when processing store.
            var ms2 = new MemoryStream();
            pkcs12Store.Save(ms2, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray(), new SecureRandom());
            ms2.Position = 0;

            pkcs12StoreNew.Load(ms2, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray());

            _logger.MethodExit(LogLevel.Debug);
            return pkcs12StoreNew;
        }

        


        public byte[] CreateOrUpdateJks(byte[] newPkcs12Bytes, string newCertPassword, string alias, byte[] existingStore = null, string existingStorePassword = null,
            bool remove = false)
        {
            _logger.MethodEntry(LogLevel.Debug);

            _logger.LogDebug("Creating or updating JKS store");
            // If existingStore is null, create a new store
            var existingJksStore = new JksStore();
            var newJksStore = new JksStore();
            var createdNewStore = false;

            // If existingStore is not null, load it into jksStore
            if (existingStore != null)
            {
                using var ms = new MemoryStream(existingStore);

                existingJksStore.Load(ms, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
                if (existingJksStore.ContainsAlias(alias))
                {
                    // If alias exists, delete it from existingJksStore
                    existingJksStore.DeleteEntry(alias);
                    if (remove)
                    {
                        // If remove is true, save existingJksStore and return
                        using var mms = new MemoryStream();
                        existingJksStore.Save(mms, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
                        return mms.ToArray();
                    }
                }
                else if (remove)
                {
                    // If alias does not exist and remove is true, return existingStore
                    using var mms = new MemoryStream();
                    existingJksStore.Save(mms, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
                    return mms.ToArray();
                }
            }
            else
            {
                createdNewStore = true;
            }

            // Create new Pkcs12Store from newPkcs12Bytes
            var storeBuilder = new Pkcs12StoreBuilder();
            var newCert = storeBuilder.Build();

            try
            {
                using var pkcs12Ms = new MemoryStream(newPkcs12Bytes);
                newCert.Load(pkcs12Ms, string.IsNullOrEmpty(newCertPassword) ? Array.Empty<char>() : newCertPassword.ToCharArray());
            }
            catch (Exception)
            {
                var certificateParser = new X509CertificateParser();
                var certificate = certificateParser.ReadCertificate(newPkcs12Bytes);

                // create new Pkcs12Store from certificate
                storeBuilder = new Pkcs12StoreBuilder();
                newCert = storeBuilder.Build();
                newCert.SetCertificateEntry(alias, new X509CertificateEntry(certificate));
            }


            // Iterate through newCert aliases. WARNING: This assumes there is only one alias in the newCert
            foreach (var al in newCert.Aliases)
            {
                if (newCert.IsKeyEntry(al))
                {
                    var keyEntry = newCert.GetKey(al);
                    var certificateChain = newCert.GetCertificateChain(al);

                    var certificates = certificateChain.Select(certificateEntry => certificateEntry.Certificate).ToList();

                    if (createdNewStore)
                    {
                        // If createdNewStore is true, create a new store
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
                            existingJksStore.DeleteEntry(alias);
                        }

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
                        newJksStore.SetCertificateEntry(alias, newCert.GetCertificate(alias).Certificate);
                    }
                    else
                    {
                        existingJksStore.SetCertificateEntry(alias, newCert.GetCertificate(alias).Certificate);
                    }

                }
            }

            using var outStream = new MemoryStream();
            if (createdNewStore)
            {
                newJksStore.Save(outStream, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
            }
            else
            {
                existingJksStore.Save(outStream, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
            }
            // Return existingJksStore as byte[]
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
    }
}
