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
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SPKCS12;
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
    public override List<string> GetCertificates(long jobId)
    {
        // PKCS12 stores use aliases, return flat list of all certificates
        var aliasedCerts = GetCertificatesWithAliases(jobId);
        var allCerts = new List<string>();

        foreach (var kvp in aliasedCerts)
        {
            allCerts.AddRange(kvp.Value);
        }

        return allCerts;
    }

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
                    var certChain = store.GetCertificateChain(alias);
                    if (certChain == null) continue;

                    var certsList = new List<string>();
                    foreach (var cert in certChain)
                    {
                        var pem = new StringBuilder();
                        pem.AppendLine("-----BEGIN CERTIFICATE-----");
                        pem.AppendLine(Convert.ToBase64String(cert.Certificate.GetEncoded()));
                        pem.AppendLine("-----END CERTIFICATE-----");
                        certsList.Add(pem.ToString());
                    }

                    var fullAlias = $"{keyName}/{alias}";
                    result[fullAlias] = certsList;
                }
            }

            return result;
        }
        catch (Exception ex) when (ex.Message.Contains("NotFound") || ex.Message.Contains("404"))
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
                HasPrivateKey = true // PKCS12 entries typically have private keys
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

            // Get existing keystore data
            var k8sData = KubeClient.GetPkcs12Secret(
                Context.KubeSecretName,
                Context.KubeNamespace,
                Context.PasswordSecretPath ?? "",
                Context.PasswordFieldName ?? "",
                keys.ToList());

            // Get password
            var storePassword = ResolvePassword(k8sData.Secret);

            // Get existing store bytes (first key in inventory or null)
            byte[] existingData = null;
            string existingKeyName = "keystore.p12";
            if (k8sData.Inventory != null && k8sData.Inventory.Count > 0)
            {
                var firstKey = k8sData.Inventory.Keys.First();
                existingData = k8sData.Inventory[firstKey];
                existingKeyName = firstKey;
            }

            // Convert cert to PKCS12 bytes for the serializer
            byte[] newCertBytes = certObj.PrivateKeyBytes;

            // Use serializer to update the PKCS12 store
            var newPkcs12Bytes = serializer.CreateOrUpdatePkcs12(
                newCertBytes,
                certObj.Password,
                alias,
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

            // Get existing store bytes
            byte[] existingData = null;
            string existingKeyName = "keystore.p12";
            if (k8sData.Inventory != null && k8sData.Inventory.Count > 0)
            {
                var firstKey = k8sData.Inventory.Keys.First();
                existingData = k8sData.Inventory[firstKey];
                existingKeyName = firstKey;
            }

            if (existingData == null)
            {
                throw new InvalidOperationException("Cannot remove from non-existent keystore");
            }

            // Use serializer to remove from the PKCS12 store
            var newPkcs12Bytes = serializer.CreateOrUpdatePkcs12(
                null,
                null,
                alias,
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
            var storeBuilder = new Pkcs12StoreBuilder();
            var store = storeBuilder.Build();
            using var ms = new System.IO.MemoryStream();
            var password = Context.StorePassword ?? "";
            store.Save(ms, password.ToCharArray(), new SecureRandom());
            var pkcs12Bytes = ms.ToArray();

            var k8sData = new KubeCertificateManagerClient.Pkcs12Secret
            {
                Secret = null,
                Inventory = new Dictionary<string, byte[]>
                {
                    { "keystore.p12", pkcs12Bytes }
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

    #region Private Helpers

    private V1Secret HandleCreateIfMissing()
    {
        try
        {
            var existingSecret = GetSecret();
            Logger.LogInformation("Secret already exists, nothing to do for empty certificate data");
            return existingSecret;
        }
        catch (StoreNotFoundException)
        {
            Logger.LogDebug("Secret not found, creating empty PKCS12 keystore");
            return CreateEmptyStore();
        }
    }

    private string ResolvePassword(V1Secret secret)
    {
        // Try to get password from buddy secret first
        if (!string.IsNullOrEmpty(Context.PasswordSecretPath))
        {
            var buddySecret = KubeClient.ReadBuddyPass(
                Context.PasswordSecretPath,
                Context.PasswordFieldName ?? "password");

            if (buddySecret?.Data != null)
            {
                var fieldName = Context.PasswordFieldName ?? "password";
                if (buddySecret.Data.TryGetValue(fieldName, out var passwordBytes) && passwordBytes != null)
                {
                    return Encoding.UTF8.GetString(passwordBytes).TrimEnd('\n', '\r');
                }
            }
        }

        // Fall back to configured password
        return Context.StorePassword ?? "";
    }

    #endregion
}
