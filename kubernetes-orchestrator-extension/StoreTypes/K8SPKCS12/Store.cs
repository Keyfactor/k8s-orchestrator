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
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SPKCS12;

class Pkcs12CertificateStoreSerializer : ICertificateStoreSerializer
{
    private readonly ILogger _logger;
    public Pkcs12CertificateStoreSerializer(string storeProperties)
    {
        _logger = LogHandler.GetClassLogger(GetType());
    }

    public Pkcs12Store DeserializeRemoteCertificateStore(byte[] storeContents, string storePath, string storePassword)
    {
        _logger.MethodEntry(LogLevel.Debug);

        var storeBuilder = new Pkcs12StoreBuilder();
        var store = storeBuilder.Build();

        using var ms = new MemoryStream(storeContents);
        store.Load(ms, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray());

        return store;
    }

    public byte[] CreateOrUpdatePkcs12(byte[] newPkcs12Bytes, string newCertPassword, string alias, byte[] existingStore = null, string existingStorePassword = null,
        bool remove = false)
    {
        _logger.MethodEntry(LogLevel.Debug);

        _logger.LogDebug("Creating or updating PKCS12 store");
        // If existingStore is null, create a new store
        var storeBuilder = new Pkcs12StoreBuilder();
        var existingPkcs12Store = storeBuilder.Build();
        var pkcs12StoreNew = storeBuilder.Build();
        var createdNewStore = false;

        // If existingStore is not null, load it into pkcs12Store
        if (existingStore != null)
        {
            using var ms = new MemoryStream(existingStore);
            existingPkcs12Store.Load(ms, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray());
            if (existingPkcs12Store.ContainsAlias(alias))
            {
                // If alias exists, delete it from existingPkcs12Store
                existingPkcs12Store.DeleteEntry(alias);
                if (remove)
                {
                    // If remove is true, save existingPkcs12Store and return
                    using var mms = new MemoryStream();
                    existingPkcs12Store.Save(mms, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray(), new SecureRandom());
                    return mms.ToArray();
                }
            }
            else if (remove)
            {
                // If alias does not exist and remove is true, return existingStore
                using var existingPkcs12StoreMs = new MemoryStream();
                existingPkcs12Store.Save(existingPkcs12StoreMs,
                    string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray(),
                    new SecureRandom());
                return existingPkcs12StoreMs.ToArray();
            }
        }
        else
        {
            createdNewStore = true;
        }

        var newCert = storeBuilder.Build();

        try
        {
            using var newPkcs12Ms = new MemoryStream(newPkcs12Bytes);
            newCert.Load(newPkcs12Ms, string.IsNullOrEmpty(newCertPassword) ? Array.Empty<char>() : newCertPassword.ToCharArray());
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
                if (createdNewStore)
                {
                    // If createdNewStore is true, create a new store
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
                        // If alias exists, delete it from existingPkcs12Store
                        existingPkcs12Store.DeleteEntry(alias);
                    }

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
                    pkcs12StoreNew.SetCertificateEntry(alias, newCert.GetCertificate(alias));
                }
                else
                {
                    existingPkcs12Store.SetCertificateEntry(alias, newCert.GetCertificate(alias));
                }

            }
        }

        using var outStream = new MemoryStream();
        if (createdNewStore)
        {
            pkcs12StoreNew.Save(outStream, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray(), new SecureRandom());
        }
        else
        {
            existingPkcs12Store.Save(outStream, string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray(), new SecureRandom());
        }
        // Return existingPkcs12Store as byte[]
        return outStream.ToArray();
    }

    public List<SerializedStoreInfo> SerializeRemoteCertificateStore(Pkcs12Store certificateStore, string storePath, string storeFileName, string storePassword)
    {
        _logger.MethodEntry(LogLevel.Debug);

        var storeBuilder = new Pkcs12StoreBuilder();
        var pkcs12Store = storeBuilder.Build();

        foreach (var alias in certificateStore.Aliases)
        {
            var keyEntry = certificateStore.GetKey(alias);
            if (certificateStore.IsKeyEntry(alias))
            {
                pkcs12Store.SetKeyEntry(alias, keyEntry, certificateStore.GetCertificateChain(alias));
            }
            else
            {
                pkcs12Store.SetCertificateEntry(alias, certificateStore.GetCertificate(alias));
            }
        }

        using var outStream = new MemoryStream();
        pkcs12Store.Save(outStream, string.IsNullOrEmpty(storePassword) ? Array.Empty<char>() : storePassword.ToCharArray(), new SecureRandom());

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
