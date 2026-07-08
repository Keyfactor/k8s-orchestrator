// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.Serializers.K8SPKCS12;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Handler for PKCS12/PFX keystores stored in Kubernetes Opaque secrets.
/// PKCS12 files are stored as base64-encoded data in secret fields.
/// </summary>
public class Pkcs12SecretHandler : SecretHandlerBase
{
    /// <summary>
    /// Default allowed data keys for PKCS12 keystores.
    /// </summary>
    private static readonly string[] DefaultAllowedKeys = { "pkcs12", "p12", "pfx", "keystore.p12", "keystore.pfx" };

    /// <inheritdoc />
    public override string[] AllowedKeys => DefaultAllowedKeys;

    /// <inheritdoc />
    public override string SecretTypeName => "pkcs12";

    /// <inheritdoc />
    public override bool SupportsManagement => true;

    /// <summary>
    /// Initializes a new instance of the Pkcs12SecretHandler.
    /// </summary>
    public Pkcs12SecretHandler(
        KubeCertificateManagerClient kubeClient,
        ILogger logger,
        ISecretOperationContext context)
        : base(kubeClient, logger, context)
    {
    }

    #region Inventory Operations

    /// <inheritdoc />
    public override Dictionary<string, List<string>> GetCertificatesWithAliases(long jobId)
    {
        LogMethodEntry(nameof(GetCertificatesWithAliases));

        try
        {
            var keys = BuildAllowedKeys(DefaultAllowedKeys);
            var k8sData = KubeClient.GetPkcs12Secret(
                Context.KubeSecretName,
                Context.KubeNamespace,
                "", "",
                keys.ToList());

            var serializer = new Pkcs12CertificateStoreSerializer(null);
            var result = new Dictionary<string, List<string>>();

            foreach (var (keyName, keyBytes) in k8sData.Inventory)
            {
                var password = ResolvePassword(k8sData.Secret);
                var store = serializer.DeserializeRemoteCertificateStore(keyBytes, keyName, password);

                foreach (var alias in store.Aliases)
                {
                    var certsList = new List<string>();

                    // For key entries, get the certificate chain
                    // For certificate-only entries (trusted certs), get the single certificate
                    if (store.IsKeyEntry(alias))
                    {
                        var certChain = store.GetCertificateChain(alias);
                        if (certChain == null) continue;

                        foreach (var cert in certChain)
                        {
                            var pem = new StringBuilder();
                            pem.AppendLine("-----BEGIN CERTIFICATE-----");
                            pem.AppendLine(Convert.ToBase64String(cert.Certificate.GetEncoded()));
                            pem.AppendLine("-----END CERTIFICATE-----");
                            certsList.Add(pem.ToString());
                        }
                    }
                    else
                    {
                        // Certificate-only entry (trusted cert)
                        var certEntry = store.GetCertificate(alias);
                        if (certEntry == null) continue;

                        var pem = new StringBuilder();
                        pem.AppendLine("-----BEGIN CERTIFICATE-----");
                        pem.AppendLine(Convert.ToBase64String(certEntry.Certificate.GetEncoded()));
                        pem.AppendLine("-----END CERTIFICATE-----");
                        certsList.Add(pem.ToString());
                    }

                    var fullAlias = $"{keyName}/{alias}";
                    result[fullAlias] = certsList;
                }
            }

            return result;
        }
        catch (k8s.Autorest.HttpOperationException ex)
            when (ex.Response?.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            throw new StoreNotFoundException(
                $"PKCS12 keystore secret '{Context.KubeSecretName}' was not found in namespace '{Context.KubeNamespace}'.");
        }
        finally
        {
            LogMethodExit(nameof(GetCertificatesWithAliases));
        }
    }

    /// <inheritdoc />
    public override List<InventoryEntry> GetInventoryEntries(long jobId)
    {
        var aliasedCerts = GetCertificatesWithAliases(jobId);
        var entries = new List<InventoryEntry>();

        foreach (var kvp in aliasedCerts)
        {
            entries.Add(new InventoryEntry
            {
                Alias = kvp.Key,
                Certificates = kvp.Value,
                // PKCS12 keystores typically contain private keys
                HasPrivateKey = true
            });
        }

        return entries;
    }

    /// <inheritdoc />
    public override bool HasPrivateKey()
    {
        // PKCS12 keystores typically have private keys
        return true;
    }

    #endregion

    #region Management Operations

    /// <inheritdoc />
    public override V1Secret HandleAdd(K8SJobCertificate certObj, string alias, bool overwrite)
    {
        LogMethodEntry(nameof(HandleAdd));

        try
        {
            // Handle "create store if missing"
            if (string.IsNullOrEmpty(alias) && string.IsNullOrEmpty(certObj?.CertPem))
            {
                return HandleCreateIfMissing();
            }

            var keys = BuildAllowedKeys(DefaultAllowedKeys);
            var serializer = new Pkcs12CertificateStoreSerializer(null);

            // Get existing keystore data (or create empty if not found)
            KubeCertificateManagerClient.Pkcs12Secret k8sData;
            try
            {
                k8sData = KubeClient.GetPkcs12Secret(
                    Context.KubeSecretName,
                    Context.KubeNamespace,
                    Context.PasswordSecretPath ?? "",
                    Context.PasswordFieldName ?? "",
                    keys.ToList());
            }
            catch (StoreNotFoundException)
            {
                Logger.LogDebug("Secret not found, will create new PKCS12 store");
                k8sData = new KubeCertificateManagerClient.Pkcs12Secret
                {
                    Secret = null,
                    Inventory = new Dictionary<string, byte[]>()
                };
            }

            // Get password
            var storePassword = ResolvePassword(k8sData.Secret);

            var (_, certAlias, existingData, existingKeyName) =
                ParseKeystoreAlias(alias, k8sData.Inventory, "keystore.pfx");

            // Get certificate bytes for the serializer
            // Use PKCS12 if available (for certificates with private keys), otherwise use raw cert bytes
            // (for certificate-only entries like trusted CA certs)
            byte[] newCertBytes = certObj.Pkcs12 ?? certObj.CertBytes;

            // Use serializer to update the PKCS12 store
            var newPkcs12Bytes = serializer.CreateOrUpdatePkcs12(
                newCertBytes,
                certObj.Password,
                certAlias,
                existingData,
                storePassword,
                remove: false,
                includeChain: Context.IncludeCertChain);

            // Update the k8sData inventory
            if (k8sData.Inventory == null)
            {
                k8sData.Inventory = new Dictionary<string, byte[]>();
            }
            k8sData.Inventory[existingKeyName] = newPkcs12Bytes;

            // Persist to Kubernetes
            return KubeClient.CreateOrUpdatePkcs12Secret(k8sData, Context.KubeSecretName, Context.KubeNamespace);
        }
        finally
        {
            LogMethodExit(nameof(HandleAdd));
        }
    }

    /// <inheritdoc />
    public override V1Secret HandleRemove(string alias)
    {
        LogMethodEntry(nameof(HandleRemove));

        try
        {
            var keys = BuildAllowedKeys(DefaultAllowedKeys);
            var serializer = new Pkcs12CertificateStoreSerializer(null);

            // Get existing keystore data
            var k8sData = KubeClient.GetPkcs12Secret(
                Context.KubeSecretName,
                Context.KubeNamespace,
                Context.PasswordSecretPath ?? "",
                Context.PasswordFieldName ?? "",
                keys.ToList());

            // Get password
            var storePassword = ResolvePassword(k8sData.Secret);

            var (_, certAlias, existingData, existingKeyName) =
                ParseKeystoreAlias(alias, k8sData.Inventory, "keystore.pfx");

            if (existingData == null)
            {
                throw new InvalidOperationException($"Cannot remove from non-existent keystore field '{existingKeyName}'");
            }

            // Use serializer to remove from the PKCS12 store
            var newPkcs12Bytes = serializer.CreateOrUpdatePkcs12(
                null,
                null,
                certAlias,
                existingData,
                storePassword,
                remove: true,
                includeChain: false);

            // Update the k8sData inventory
            k8sData.Inventory[existingKeyName] = newPkcs12Bytes;

            // Persist to Kubernetes
            return KubeClient.CreateOrUpdatePkcs12Secret(k8sData, Context.KubeSecretName, Context.KubeNamespace);
        }
        finally
        {
            LogMethodExit(nameof(HandleRemove));
        }
    }

    /// <inheritdoc />
    public override V1Secret CreateEmptyStore()
    {
        LogMethodEntry(nameof(CreateEmptyStore));

        try
        {
            // Create empty PKCS12 keystore
            // Use ResolvePassword (not Context.StorePassword directly) so buddy-secret passwords are respected
            var storeBuilder = new Pkcs12StoreBuilder();
            var store = storeBuilder.Build();
            using var ms = new System.IO.MemoryStream();
            var password = ResolvePassword(null);
            store.Save(ms, password.ToCharArray(), new SecureRandom());
            var pkcs12Bytes = ms.ToArray();

            var k8sData = new KubeCertificateManagerClient.Pkcs12Secret
            {
                Secret = null,
                Inventory = new Dictionary<string, byte[]>
                {
                    { "keystore.pfx", pkcs12Bytes }
                }
            };

            return KubeClient.CreateOrUpdatePkcs12Secret(k8sData, Context.KubeSecretName, Context.KubeNamespace);
        }
        finally
        {
            LogMethodExit(nameof(CreateEmptyStore));
        }
    }

    #endregion

    #region Discovery Operations

    /// <inheritdoc />
    public override List<string> DiscoverStores(string[] allowedKeys, string namespacesCsv)
    {
        LogMethodEntry(nameof(DiscoverStores));

        try
        {
            var keys = allowedKeys?.Length > 0 ? allowedKeys : AllowedKeys;
            return KubeClient.DiscoverSecrets(keys, "Opaque", namespacesCsv);
        }
        finally
        {
            LogMethodExit(nameof(DiscoverStores));
        }
    }

    #endregion
}
