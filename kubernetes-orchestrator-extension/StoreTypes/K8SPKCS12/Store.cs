// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.IO;
using System.Linq;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SPKCS12;

internal class Pkcs12CertificateStoreSerializer : CertificateStoreSerializer
{
    private Pkcs12Store Pkcs12Object { get; set; }
    public string Pkcs8Pem { get; set; }
    public string Pkcs1Pem { get; set; }
    public X509Certificate LeafCertificate { get; set; }
    public string LeafCertificatePem { get; set; }
    public X509CertificateEntry[] Chain { get; set; }
    public string ChainPem { get; set; }

    public Pkcs12Store CreateOrUpdateStore(Pkcs12Store newPkcs12, string newCertPassword, string alias,
        Pkcs12Store existingStore = null, string existingStorePassword = null,
        bool remove = false)
    {
        var newPkcs12Bytes = ToBytes(newPkcs12, newCertPassword);
        existingStore ??= Pkcs12Object;

        if (string.IsNullOrEmpty(existingStorePassword))
        {
            existingStorePassword = StorePassword;
        }

        return CreateOrUpdateStore(newPkcs12Bytes, newCertPassword, alias,
            existingStore == null ? null : ToBytes(existingStore, existingStorePassword), existingStorePassword,
            remove);
    }

    public Pkcs12Store CreateOrUpdateStore(byte[] newPkcs12Bytes, string newCertPassword, string alias,
        byte[] existingStore = null, string existingStorePassword = null,
        bool remove = false)
    {
        Logger.MethodEntry(LogLevel.Debug);

        Logger.LogDebug("Creating or updating PKCS12 store");
        // If existingStore is null, create a new store
        var storeBuilder = new Pkcs12StoreBuilder();
        var existingPkcs12Store = storeBuilder.Build();
        var pkcs12StoreNew = storeBuilder.Build();
        var createdNewStore = false;

        // If existingStore is not null, load it into pkcs12Store
        if (existingStore != null)
        {
            Logger.LogDebug("Loading existing PKCS12 store from byte array for `{Alias}`", alias);
            using var ms = new MemoryStream(existingStore);
            existingPkcs12Store.Load(ms,
                string.IsNullOrEmpty(existingStorePassword)
                    ? Array.Empty<char>()
                    : existingStorePassword.ToCharArray());
            Logger.LogDebug("Existing PKCS12 store loaded successfully for `{Alias}`", alias);
            if (existingPkcs12Store.ContainsAlias(alias))
            {
                // If alias exists, delete it from existingPkcs12Store
                Logger.LogDebug("Alias `{Alias}` exists in existing PKCS12 store, deleting it", alias);
                existingPkcs12Store.DeleteEntry(alias);
                if (remove)
                {
                    Logger.LogDebug("Alias `{Alias}` deleted from existing PKCS12 store, saving results to existingPkcs12Store", alias);
                    // If remove is true, save existingPkcs12Store and return
                    using var mms = new MemoryStream();
                    existingPkcs12Store.Save(mms,
                        string.IsNullOrEmpty(existingStorePassword)
                            ? Array.Empty<char>()
                            : existingStorePassword.ToCharArray(), new SecureRandom());
                    Logger.MethodExit();
                    return existingPkcs12Store;
                }
            }
            else if (remove)
            {
                // If alias does not exist and remove is true, return existingStore
                Logger.LogDebug("Alias `{Alias}` does not exist in existing PKCS12 store, returning existing PKCS12 store", alias);
                using var existingPkcs12StoreMs = new MemoryStream();
                existingPkcs12Store.Save(existingPkcs12StoreMs,
                    string.IsNullOrEmpty(existingStorePassword)
                        ? Array.Empty<char>()
                        : existingStorePassword.ToCharArray(),
                    new SecureRandom());
                Logger.MethodExit();
                return existingPkcs12Store;
            }
        }
        else
        {
            Logger.LogDebug("Creating new PKCS12 store for `{Alias}`", alias);
            createdNewStore = true;
        }

        var newCert = storeBuilder.Build();

        try
        {
            Logger.LogDebug("Loading new PKCS12 store from byte array for `{Alias}`", alias);
            using var newPkcs12Ms = new MemoryStream(newPkcs12Bytes);
            newCert.Load(newPkcs12Ms,
                string.IsNullOrEmpty(newCertPassword) ? Array.Empty<char>() : newCertPassword.ToCharArray());
        }
        catch (Exception ex)
        {
            Logger.LogError("Error loading new PKCS12 store from byte array for `{Alias}`: {Message}", alias, ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            var certificateParser = new X509CertificateParser();
            Logger.LogDebug("Parsing certificate from byte array for `{Alias}`", alias);
            var certificate = certificateParser.ReadCertificate(newPkcs12Bytes);

            // create new Pkcs12Store from certificate
            Logger.LogDebug("Creating new PKCS12 store from certificate for `{Alias}`", alias);
            storeBuilder = new Pkcs12StoreBuilder();
            newCert = storeBuilder.Build();
            Logger.LogDebug("Setting certificate entry for `{Alias}`", alias);
            newCert.SetCertificateEntry(alias, new X509CertificateEntry(certificate));
        }
        // Iterate through newCert aliases. WARNING: This assumes there is only one alias in the newCert
        Logger.LogTrace("Entering loop to process aliases in new PKCS12 store for `{Alias}`", alias);
        foreach (var al in newCert.Aliases)
        {
            Logger.LogTrace("Processing alias: {Alias}", al);
            if (newCert.IsKeyEntry(al))
            {
                Logger.LogTrace("Attempting to GetKey() for alias: {Alias}", al);
                var keyEntry = newCert.GetKey(al);
                Logger.LogTrace("KeyEntry retrieved for alias: {Alias}", al);
                Logger.LogTrace("Attempting to GetCertificateChain() for alias: {Alias}", al);
                var certificateChain = newCert.GetCertificateChain(al);
                Logger.LogTrace("Certificate chain retrieved for alias: {Alias}", al);
                if (createdNewStore)
                {
                    // If createdNewStore is true, create a new store
                    Logger.LogTrace("Setting key entry for alias: {Alias}", al);
                    pkcs12StoreNew.SetKeyEntry(
                        alias,
                        keyEntry,
                        certificateChain
                    );
                    Logger.LogTrace("Key entry set for alias: {Alias}", al);
                }
                else
                {
                    // If createdNewStore is false, add to existingPkcs12Store
                    // check if alias exists in existingPkcs12Store
                    if (existingPkcs12Store.ContainsAlias(alias)) //TODO: this seems redundant
                    {
                        // If alias exists, delete it from existingPkcs12Store
                        Logger.LogTrace("Alias `{Alias}` exists in existing PKCS12 store, deleting it", alias);
                        existingPkcs12Store.DeleteEntry(alias);
                        Logger.LogTrace("Alias `{Alias}` deleted from existing PKCS12 store", alias);
                    }

                    Logger.LogTrace("Setting key entry for alias: {Alias}", al);
                    existingPkcs12Store.SetKeyEntry(
                        alias,
                        keyEntry,
                        // string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray(),
                        certificateChain
                    );
                    Logger.LogTrace("Key entry set for alias: {Alias}", al);
                }
            }
            else
            {
                if (createdNewStore)
                {
                    Logger.LogTrace("Setting certificate entry for alias: `{Alias}` on new pkcs12 store", al);
                    pkcs12StoreNew.SetCertificateEntry(alias, newCert.GetCertificate(alias));
                    Logger.LogTrace("Certificate entry set for alias: {Alias}", al);
                }
                else
                {
                    Logger.LogTrace("Setting certificate entry for alias: `{Alias}` on existing pkcs12 store", al);
                    existingPkcs12Store.SetCertificateEntry(alias, newCert.GetCertificate(alias));
                }
            }
        }
        Logger.LogTrace("Exiting loop to process aliases in new PKCS12 store for `{Alias}`", alias);

        
        using var outStream = new MemoryStream();
        if (createdNewStore)
        {
            Logger.LogDebug("Saving new PKCS12 store to byte array for `{Alias}`", alias);
            pkcs12StoreNew.Save(outStream,
                string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray(),
                new SecureRandom());
            Logger.MethodExit();
            return pkcs12StoreNew;
        }

        Logger.LogDebug("Saving existing PKCS12 store to byte array for `{Alias}`", alias);
        existingPkcs12Store.Save(outStream,
            string.IsNullOrEmpty(existingStorePassword) ? Array.Empty<char>() : existingStorePassword.ToCharArray(),
            new SecureRandom());
        Logger.MethodExit();
        return existingPkcs12Store;
    }

    private byte[] ToBytes(Pkcs12Store store = null, string password = null)
    {
        Logger.MethodEntry();
        store ??= Pkcs12Object;
        password ??= StorePassword;

        using var ms = new MemoryStream();
        store?.Save(ms, string.IsNullOrEmpty(password) ? Array.Empty<char>() : password.ToCharArray(),
            new SecureRandom()); //todo: a new unknown password could be problematic
        Logger.MethodExit(LogLevel.Debug);
        return ms.ToArray();
    }

    private bool IsPkcs12()
    {
        Logger.MethodEntry();
        try
        {
            var storeBuilder = new Pkcs12StoreBuilder();
            var store = storeBuilder.Build();
            using var ms = new MemoryStream(StoreContent);
            Logger.LogDebug("Loading PKCS12 store from byte array");
            store.Load(ms, string.IsNullOrEmpty(StorePassword) ? Array.Empty<char>() : StorePassword.ToCharArray());
            Pkcs12Object = store;
            Logger.MethodExit();
            return true;
        }
        catch (Exception ex)
        {
            Logger.LogError("Unable to convert store to PKCS12: {Message}", ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            Logger.MethodExit();
            return false;
        }
    }

    private void Parse()
    {
        Logger.MethodEntry();
        if (!IsPkcs12()) return;
        var aliases = Pkcs12Object.Aliases;
        Logger.LogTrace("Entering loop to process aliases in PKCS12 store");
        foreach (var alias in aliases)
        {
            Logger.LogTrace("Processing alias: {Alias}", alias);
            if (Pkcs12Object.IsCertificateEntry(alias))
            {
                Logger.LogTrace("'{Alias}' is a certificate entry", alias);
                LeafCertificate = Pkcs12Object.GetCertificate(alias)?.Certificate;
                Chain = Pkcs12Object.GetCertificateChain(alias);

                // Convert the leaf certificate to PEM format
                if (LeafCertificate != null)
                {
                    Logger.LogTrace("Converting certificate '{Alias}' to PEM format", alias);
                    using var sw = new StringWriter();
                    var pemWriter = new PemWriter(sw);
                    pemWriter.WriteObject(new PemObject("CERTIFICATE", LeafCertificate.GetEncoded()));
                    pemWriter.Writer.Flush();
                    LeafCertificatePem = sw.ToString();
                    Logger.LogTrace("Leaf certificate '{Alias}' converted to PEM format\n{Pem}", alias,
                        LeafCertificatePem);
                }


                // Convert the certificate chain to PEM format
                if (Chain is not { Length: > 0 }) continue;
                var chainPem = Chain.Select(cert =>
                {
                    Logger.LogTrace("Converting certificate chain '{Alias}' to PEM format", alias);
                    var chainPem = new StringWriter();
                    var chainPemWriter = new PemWriter(chainPem);
                    chainPemWriter.WriteObject(new PemObject("CERTIFICATE", cert.Certificate.GetEncoded()));
                    chainPemWriter.Writer.Flush();
                    return chainPem.ToString();
                });
                ChainPem = string.Join("", chainPem);
                Logger.LogTrace("Certificate chain '{Alias}' converted to PEM format\n{Pem}", alias, ChainPem);
            }

            if (!Pkcs12Object.IsKeyEntry(alias)) continue;
            Logger.LogTrace("'{Alias}' is a key entry", alias);
            Logger.LogTrace("Calling GetPkcs1Pem() for '{Alias}'", alias);
            Pkcs1Pem = GetPkcs1Pem();
            Logger.LogTrace("Calling GetPkcs8Pem() for '{Alias}'", alias);
            Pkcs8Pem = GetPkcs8Pem();
        }
        Logger.MethodExit();
    }

    private string GetPkcs1Pem(Pkcs12Store pkcs12Object = null, string searchAlias = null)
    {
        Logger.MethodEntry();
        try
        {
            pkcs12Object ??= Pkcs12Object;
            var pkcs1Pem = string.Empty;
            if (pkcs12Object == null) return null;
            var aliases = pkcs12Object.Aliases;

            if (!string.IsNullOrEmpty(searchAlias))
            {
                Logger.LogTrace("Searching for alias: {Alias}", searchAlias);
                aliases = aliases?.Where(alias => alias.Equals(searchAlias)).ToList();
                Logger.LogTrace("Aliases: {Aliases}", aliases);
            }

            Logger.LogDebug("Attempting to get private key from PKCS12 store for PKCS1 conversion");
            var privateKey =
                (from alias in aliases where pkcs12Object.IsKeyEntry(alias) select pkcs12Object.GetKey(alias).Key)
                .FirstOrDefault(); //todo: could this potentially cause mismatches with cert?

            if (privateKey == null)
            {
                Logger.LogWarning("No private key found in PKCS12 store `{StorePath}`", StorePath);
                Logger.MethodExit();
                return pkcs1Pem;
            }

            // Convert the private key to PKCS#1 format (only for RSA keys)
            if (privateKey is not RsaPrivateCrtKeyParameters rsaPrivateKey)
            {
                Logger.LogError("Private key is not an RSA key, unable to convert to PKCS1");
                return string.Empty;
            }

            // Create the PKCS#1 structure
            Logger.LogDebug("Creating PKCS1 structure for private key");
            var sequence = new DerSequence(
                new DerInteger(0), // Version
                new DerInteger(rsaPrivateKey.Modulus),
                new DerInteger(rsaPrivateKey.PublicExponent),
                new DerInteger(rsaPrivateKey.Exponent),
                new DerInteger(rsaPrivateKey.P),
                new DerInteger(rsaPrivateKey.Q),
                new DerInteger(rsaPrivateKey.DP),
                new DerInteger(rsaPrivateKey.DQ),
                new DerInteger(rsaPrivateKey.QInv)
            );

            Logger.LogDebug("Converting PKCS1 structure to byte array");
            var pkcs1Bytes = sequence.GetDerEncoded();

            // Convert the private key to PKCS#1 format
            using var sw = new StringWriter();
            var pemWriter = new PemWriter(sw);
            Logger.LogDebug("Writing PKCS1 private key to PEM format");
            pemWriter.WriteObject(new PemObject("RSA PRIVATE KEY", pkcs1Bytes));
            pemWriter.Writer.Flush();
            pkcs1Pem = sw.ToString();
            Logger.LogDebug("PKCS1 private key converted to PEM format");
            Logger.MethodExit();
            return pkcs1Pem;
        }
        catch (Exception e)
        {
            Logger.LogError("Unknown error occurred while converting PKCS12 to PKCS1: {Message}", e.Message);
            Logger.LogTrace("{Message}", e.ToString());
            Logger.MethodExit();
            return string.Empty;
        }
    }

    private string GetPkcs8Pem(Pkcs12Store pkcs12Object = null, string searchAlias = null)
    {
        Logger.MethodEntry();
        try
        {
            pkcs12Object ??= Pkcs12Object;
            var pkcs8Pem = string.Empty;
            if (pkcs12Object == null) return null;
            var aliases = pkcs12Object.Aliases;
            if (!string.IsNullOrEmpty(searchAlias))
            {
                Logger.LogTrace("Searching for alias: {Alias}", searchAlias);
                aliases = aliases.Where(alias => alias.Equals(searchAlias)).ToList();
                Logger.LogTrace("Aliases: {Aliases}", aliases);
            }

            Logger.LogTrace("Entering loop to process aliases in PKCS12 store");
            foreach (var alias in aliases)
            {
                if (!pkcs12Object.IsKeyEntry(alias))
                {
                    Logger.LogTrace("'{Alias}' is not a key entry", alias);
                    continue;
                }
                Logger.LogTrace("'{Alias}' is a key entry", alias);
                Logger.LogTrace("Attempting to GetKey() for alias: {Alias}", alias);
                var privateKey = pkcs12Object.GetKey(alias).Key;
                // Convert the private key to PKCS#8 format
                Logger.LogDebug("Calling CreatePrivateKeyInfo() to create PKCS8 private key info for `{Alias}`", alias);
                var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
                Logger.LogDebug("Private key info created for `{Alias}`", alias);
                
                Logger.LogDebug("Encoding PKCS8 private key info for `{Alias}`", alias);
                var pkcs8Bytes = privateKeyInfo.GetEncoded();
                Logger.LogDebug("PKCS8 private key info encoded for `{Alias}`", alias);

                // Encode the PKCS#8 private key as a PEM string
                using var sw = new StringWriter();
                var pemWriter = new PemWriter(sw);
                Logger.LogDebug("Writing PKCS8 private key to PEM format for `{Alias}`", alias);
                pemWriter.WriteObject(new PemObject("PRIVATE KEY", pkcs8Bytes));
                pemWriter.Writer.Flush();
                pkcs8Pem = sw.ToString();
                Logger.LogDebug("PKCS8 private key written to PEM format for `{Alias}`", alias);

                // Output the PKCS#8 private key string
                Logger.MethodExit();
                return pkcs8Pem;
            }

            Logger.LogWarning("No key entry found in PKCS12 store `{StorePath}`", StorePath);
            Logger.MethodExit();
            return pkcs8Pem;
        }
        catch (Exception ex)
        {
            Logger.LogError("Unknown error occurred while converting PKCS12 to PKCS8: {Message}", ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            Logger.MethodExit();
            return string.Empty;
        }
    }

    public override TPkcs12Store Deserialize<TPkcs12Store>(byte[] storeContents = null, string storePassword = null)
    {
        Logger.MethodEntry();
        Parse();
        Logger.MethodExit();
        return this as TPkcs12Store;
    }

    public override byte[] Serialize()
    {
        Logger.MethodEntry();
        //Convert Pkcs12Object to byte array
        var bytes = Pkcs12Object == null ? null : ToBytes();

        Logger.MethodExit();
        return bytes;
    }

    public override void Create()
    {
        Logger.MethodEntry();
        
        Logger.MethodExit();
        throw new NotImplementedException();
    }

    public override void Update()
    {
        Logger.MethodEntry();
        
        Logger.MethodExit();
        throw new NotImplementedException();
    }

    public override void Delete()
    {
        Logger.MethodEntry();
        
        Logger.MethodExit();
        throw new NotImplementedException();
    }

    public Pkcs12CertificateStoreSerializer(byte[] storeContent, string storePassword, string storePath = null) : base(
        storeContent, storePassword, storePath)
    {
        Logger.MethodEntry();
        if (storeContent == null || !IsPkcs12())
        {
            Logger.LogError("Store is not a valid PKCS12 store");
            throw new InvalidPkcs12StoreException("Store is not a valid PKCS12 store");
        }

        Logger.LogDebug("Calling Parse() to parse PKCS12 store");
        Parse();
        Logger.LogDebug("PKCS12 store parsed successfully");
        Logger.MethodExit();
    }
}

internal class InvalidPkcs12StoreException : Exception
{
    public InvalidPkcs12StoreException()
    {
    }

    public InvalidPkcs12StoreException(string message)
        : base(message)
    {
    }

    public InvalidPkcs12StoreException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}