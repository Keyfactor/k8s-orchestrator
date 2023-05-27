// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.IO;
using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Models;

using Keyfactor.Logging;

using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;

using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Security;

namespace Keyfactor.Extensions.Orchestrator.RemoteFile.JKS
{
    class JKSCertificateStoreSerializer : ICertificateStoreSerializer
    {
        private ILogger logger;
        public JKSCertificateStoreSerializer(string storeProperties)
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

            foreach(string alias in jksStore.Aliases)
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

        public List<SerializedStoreInfo> SerializeRemoteCertificateStore(Pkcs12Store certificateStore, string storePath, string storeFileName, string storePassword)
        {
            logger.MethodEntry(LogLevel.Debug);

            JksStore jksStore = new JksStore();

            foreach(string alias in certificateStore.Aliases)
            {
                if (certificateStore.IsKeyEntry(alias))
                {
                    AsymmetricKeyEntry keyEntry = certificateStore.GetKey(alias);
                    X509CertificateEntry[] certificateChain = certificateStore.GetCertificateChain(alias);

                    List<X509Certificate> certificates = new List<X509Certificate>();
                    foreach(X509CertificateEntry certificateEntry in certificateChain)
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
                storeInfo.Add(new SerializedStoreInfo() { FilePath = storePath+storeFileName, Contents = outStream.ToArray() });

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