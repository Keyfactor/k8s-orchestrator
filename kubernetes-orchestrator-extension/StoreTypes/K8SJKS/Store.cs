// Copyright 2021 Keyfactor
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
using System.Text.RegularExpressions;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SJKS
{
    class JksCertificateStoreSerializer : ICertificateStoreSerializer
    {
        private ILogger logger;
        public JksCertificateStoreSerializer(string storeProperties)
        {
            logger = LogHandler.GetClassLogger(this.GetType());
        }

        public Pkcs12Store DeserializeRemoteCertificateStore(byte[] storeContents, string storePath, string storePassword)
        {
            logger.MethodEntry(LogLevel.Debug);

            Pkcs12StoreBuilder storeBuilder = new Pkcs12StoreBuilder();
            Pkcs12Store pkcs12Store = storeBuilder.Build();
            Pkcs12Store pkcs12StoreNew = storeBuilder.Build();

            JksStore jksStore = new JksStore();

            using (MemoryStream ms = new MemoryStream(storeContents))
            {
                jksStore.Load(ms, string.IsNullOrEmpty(storePassword) ? new char[0] : storePassword.ToCharArray());
            }

            foreach (string alias in jksStore.Aliases)
            {
                if (jksStore.IsKeyEntry(alias))
                {
                    AsymmetricKeyParameter keyParam = jksStore.GetKey(alias, string.IsNullOrEmpty(storePassword) ? new char[0] : storePassword.ToCharArray());
                    AsymmetricKeyEntry keyEntry = new AsymmetricKeyEntry(keyParam);

                    X509Certificate[] certificateChain = jksStore.GetCertificateChain(alias);
                    List<X509CertificateEntry> certificateChainEntries = new List<X509CertificateEntry>();
                    foreach (X509Certificate certificate in certificateChain)
                    {
                        certificateChainEntries.Add(new X509CertificateEntry(certificate));
                    }

                    pkcs12Store.SetKeyEntry(alias, keyEntry, certificateChainEntries.ToArray());
                }
                else
                {
                    pkcs12Store.SetCertificateEntry(alias, new X509CertificateEntry(jksStore.GetCertificate(alias)));
                }
            }

            // Second Pkcs12Store necessary because of an obscure BC bug where creating a Pkcs12Store without .Load (code above using "Set" methods only) does not set all internal hashtables necessary to avoid an error later
            //  when processing store.
            MemoryStream ms2 = new MemoryStream();
            pkcs12Store.Save(ms2, string.IsNullOrEmpty(storePassword) ? new char[0] : storePassword.ToCharArray(), new Org.BouncyCastle.Security.SecureRandom());
            ms2.Position = 0;

            pkcs12StoreNew.Load(ms2, string.IsNullOrEmpty(storePassword) ? new char[0] : storePassword.ToCharArray());

            logger.MethodExit(LogLevel.Debug);
            return pkcs12StoreNew;
        }


        string ConvertToPEM(Asn1Object asn1Object)
        {
            string header = "-----BEGIN CERTIFICATE-----";
            string footer = "-----END CERTIFICATE-----";

            byte[] derData = asn1Object.GetEncoded();
            string base64Data = Convert.ToBase64String(derData);
            string pemData = header + Environment.NewLine;
            pemData += InsertLineBreaks(base64Data, 64);
            pemData += Environment.NewLine + footer;

            return pemData;
        }

        string InsertLineBreaks(string input, int lineLength)
        {
            StringBuilder sb = new StringBuilder();
            int i = 0;
            while (i < input.Length)
            {
                sb.Append(input.Substring(i, Math.Min(lineLength, input.Length - i)));
                sb.AppendLine();
                i += lineLength;
            }
            return sb.ToString();
        }


        public byte[] CreateOrUpdateJks(byte[] newPkcs12bytes, string newCertPassword, string alias, byte[] existingStore = null, string existingStorePassword = null,
            bool remove = false)
        {
            logger.MethodEntry(LogLevel.Debug);

            logger.LogDebug("Creating or updating JKS store");
            // If existingStore is null, create a new store
            JksStore existingJksStore = new JksStore();
            JksStore newJksStore = new JksStore();
            bool createdNewStore = false;

            // If existingStore is not null, load it into jksStore
            if (existingStore != null)
            {
                using MemoryStream ms = new MemoryStream(existingStore);
                existingJksStore.Load(ms, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
                if (existingJksStore.ContainsAlias(alias))
                {
                    // If alias exists, delete it from existingJksStore
                    existingJksStore.DeleteEntry(alias);
                    if (remove)
                    {
                        // If remove is true, save existingJksStore and return
                        using MemoryStream mms = new MemoryStream();
                        existingJksStore.Save(mms, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
                        return mms.ToArray();
                    }
                }
                else if (remove)
                {
                    // If alias does not exist and remove is true, return existingStore
                    using MemoryStream mms = new MemoryStream();
                    existingJksStore.Save(mms, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
                    return mms.ToArray();
                }
            }
            else
            {
                createdNewStore = true;
            }

            // check if pkcs12 bytes are der encoded
            string pemData = System.Text.Encoding.UTF8.GetString(newPkcs12bytes);

            bool isPEMFormat = Regex.IsMatch(pemData, @"-----BEGIN ([\w ]+)-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END \1-----");

            if (isPEMFormat)
            {
                // Print as string in PEM format
                string pemString = System.Text.Encoding.UTF8.GetString(newPkcs12bytes);
                // Convert to byte array in DER format
                byte[] derBytes = Convert.FromBase64String(pemString);
                // Convert to byte array in PEM format
                byte[] pemBytes = Encoding.UTF8.GetBytes(pemString);


            }
            Pkcs12StoreBuilder storeBuilder = new Pkcs12StoreBuilder();
            Pkcs12Store newCert = storeBuilder.Build();

            try
            {
                using MemoryStream pkcsmms = new MemoryStream(newPkcs12bytes);
                newCert.Load(pkcsmms, string.IsNullOrEmpty(newCertPassword) ? Array.Empty<char>() : newCertPassword.ToCharArray());
            }
            catch (Exception)
            {
                var certificateParser = new X509CertificateParser();
                X509Certificate certificate = certificateParser.ReadCertificate(newPkcs12bytes);

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
            logger.MethodEntry(LogLevel.Debug);

            JksStore jksStore = new JksStore();

            foreach (string alias in certificateStore.Aliases)
            {
                if (certificateStore.IsKeyEntry(alias))
                {
                    AsymmetricKeyEntry keyEntry = certificateStore.GetKey(alias);
                    X509CertificateEntry[] certificateChain = certificateStore.GetCertificateChain(alias);

                    List<X509Certificate> certificates = new List<X509Certificate>();
                    foreach (X509CertificateEntry certificateEntry in certificateChain)
                    {
                        certificates.Add(certificateEntry.Certificate);
                    }

                    jksStore.SetKeyEntry(alias, keyEntry.Key, string.IsNullOrEmpty(storePassword) ? new char[0] : storePassword.ToCharArray(), certificates.ToArray());
                }
                else
                {
                    jksStore.SetCertificateEntry(alias, certificateStore.GetCertificate(alias).Certificate);
                }
            }

            using (MemoryStream outStream = new MemoryStream())
            {
                jksStore.Save(outStream, string.IsNullOrEmpty(storePassword) ? new char[0] : storePassword.ToCharArray());

                List<SerializedStoreInfo> storeInfo = new List<SerializedStoreInfo>();
                storeInfo.Add(new SerializedStoreInfo() { FilePath = storePath + storeFileName, Contents = outStream.ToArray() });

                logger.MethodExit(LogLevel.Debug);
                return storeInfo;
            }
        }

        public string GetPrivateKeyPath()
        {
            return null;
        }
    }
}
