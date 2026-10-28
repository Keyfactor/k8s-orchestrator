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
using Keyfactor.Extensions.Orchestrator.K8S.Serializers.K8SJKS;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Security;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Handler for JKS keystores stored in Kubernetes Opaque secrets.
/// JKS files are stored as base64-encoded data in secret fields.
/// </summary>
public class JksSecretHandler : SecretHandlerBase
{
    /// <summary>
    /// Default allowed data keys for JKS keystores.
    /// </summary>
    private static readonly string[] DefaultAllowedKeys = { "jks", "keystore.jks", "truststore.jks" };

    /// <inheritdoc />
    public override string[] AllowedKeys => DefaultAllowedKeys;

    /// <inheritdoc />
    public override string SecretTypeName => "jks";

    /// <inheritdoc />
    public override bool SupportsManagement => true;

    /// <summary>
    /// Initializes a new instance of the JksSecretHandler.
    /// </summary>
    public JksSecretHandler(
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
            return ReadKeystoreEntries().ToDictionary(e => e.Alias, e => e.Certificates);
        }
        finally
        {
            LogMethodExit(nameof(GetCertificatesWithAliases));
        }
    }

    /// <summary>
    /// Reads every keystore field in the secret and returns one entry per alias, recording whether the alias is a
    /// private-key entry or a trusted-certificate-only entry.
    /// </summary>
    private List<KeystoreAliasEntry> ReadKeystoreEntries()
    {
        try
        {
            var keys = BuildAllowedKeys(DefaultAllowedKeys);
            var k8sData = KubeClient.GetJksSecret(
                Context.KubeSecretName,
                Context.KubeNamespace,
                "", "",
                keys.ToList());

            var serializer = new JksCertificateStoreSerializer(null);
            var result = new Dictionary<string, KeystoreAliasEntry>();

            foreach (var (keyName, keyBytes) in k8sData.Inventory)
            {
                var password = ResolvePassword(k8sData.Secret);
                var store = serializer.DeserializeRemoteCertificateStore(keyBytes, keyName, password);

                foreach (var alias in store.Aliases)
                {
                    var certsList = new List<string>();
                    var isKeyEntry = store.IsKeyEntry(alias);

                    if (isKeyEntry)
                    {
                        var certChain = store.GetCertificateChain(alias);
                        if (certChain == null) continue;

                        foreach (var cert in certChain)
                            certsList.Add(ToPem(cert.Certificate.GetEncoded()));
                    }
                    else
                    {
                        // Trusted-certificate-only entry: no chain and no private key, report the single certificate
                        var certEntry = store.GetCertificate(alias);
                        if (certEntry == null)
                        {
                            Logger.LogDebug("Alias '{Alias}' has no key and no certificate, skipping", alias);
                            continue;
                        }

                        Logger.LogDebug("Alias '{Alias}' is a trusted certificate entry (no private key)", alias);
                        certsList.Add(ToPem(certEntry.Certificate.GetEncoded()));
                    }

                    var fullAlias = $"{keyName}/{alias}";
                    result[fullAlias] = new KeystoreAliasEntry(fullAlias, certsList, isKeyEntry);
                }
            }

            return result.Values.ToList();
        }
        catch (k8s.Autorest.HttpOperationException ex)
            when (ex.Response?.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            throw new StoreNotFoundException(
                $"JKS keystore secret '{Context.KubeSecretName}' was not found in namespace '{Context.KubeNamespace}'.");
        }
    }

    private static string ToPem(byte[] der)
    {
        var pem = new StringBuilder();
        pem.AppendLine("-----BEGIN CERTIFICATE-----");
        pem.AppendLine(Convert.ToBase64String(der));
        pem.AppendLine("-----END CERTIFICATE-----");
        return pem.ToString();
    }

    private sealed record KeystoreAliasEntry(string Alias, List<string> Certificates, bool HasPrivateKey);

    /// <inheritdoc />
    public override List<InventoryEntry> GetInventoryEntries(long jobId)
    {
        LogMethodEntry(nameof(GetInventoryEntries));

        try
        {
            return ReadKeystoreEntries().Select(e => new InventoryEntry
            {
                Alias = e.Alias,
                Certificates = e.Certificates,
                // Only private-key entries carry a key; trusted-certificate entries do not
                HasPrivateKey = e.HasPrivateKey
            }).ToList();
        }
        finally
        {
            LogMethodExit(nameof(GetInventoryEntries));
        }
    }

    /// <inheritdoc />
    public override bool HasPrivateKey()
    {
        // True when at least one alias in the keystore is a private-key entry
        return ReadKeystoreEntries().Any(e => e.HasPrivateKey);
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
            var serializer = new JksCertificateStoreSerializer(null);

            // Get existing keystore data (or create empty if not found)
            KubeCertificateManagerClient.JksSecret k8sData;
            try
            {
                k8sData = KubeClient.GetJksSecret(
                    Context.KubeSecretName,
                    Context.KubeNamespace,
                    Context.PasswordSecretPath ?? "",
                    Context.PasswordFieldName ?? "",
                    keys.ToList());
            }
            catch (StoreNotFoundException)
            {
                Logger.LogDebug("Secret not found, will create new JKS store");
                k8sData = new KubeCertificateManagerClient.JksSecret
                {
                    Secret = null,
                    Inventory = new Dictionary<string, byte[]>()
                };
            }

            // Get password
            var storePassword = ResolvePassword(k8sData.Secret);

            var (_, certAlias, existingData, existingKeyName) =
                ParseKeystoreAlias(alias, k8sData.Inventory, "keystore.jks");

            // Get certificate bytes for the serializer
            // Use PKCS12 if available (for certificates with private keys), otherwise use raw cert bytes
            // (for certificate-only entries like trusted CA certs)
            byte[] newCertBytes = certObj.Pkcs12 ?? certObj.CertBytes;

            // Use serializer to update the JKS store
            var newJksBytes = serializer.CreateOrUpdateJks(
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
            k8sData.Inventory[existingKeyName] = newJksBytes;

            // Persist to Kubernetes
            return KubeClient.CreateOrUpdateJksSecret(k8sData, Context.KubeSecretName, Context.KubeNamespace);
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
            var serializer = new JksCertificateStoreSerializer(null);

            // Get existing keystore data
            var k8sData = KubeClient.GetJksSecret(
                Context.KubeSecretName,
                Context.KubeNamespace,
                Context.PasswordSecretPath ?? "",
                Context.PasswordFieldName ?? "",
                keys.ToList());

            // Get password
            var storePassword = ResolvePassword(k8sData.Secret);

            var (_, certAlias, existingData, existingKeyName) =
                ParseKeystoreAlias(alias, k8sData.Inventory, "keystore.jks");

            if (existingData == null)
            {
                throw new InvalidOperationException($"Cannot remove from non-existent keystore field '{existingKeyName}'");
            }

            // Use serializer to remove from the JKS store
            var newJksBytes = serializer.CreateOrUpdateJks(
                null,
                null,
                certAlias,
                existingData,
                storePassword,
                remove: true,
                includeChain: false);

            // Update the k8sData inventory
            k8sData.Inventory[existingKeyName] = newJksBytes;

            // Persist to Kubernetes
            return KubeClient.CreateOrUpdateJksSecret(k8sData, Context.KubeSecretName, Context.KubeNamespace);
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
            // Create empty JKS keystore using BouncyCastle
            // Use ResolvePassword (not Context.StorePassword directly) so buddy-secret passwords are respected
            var jksStore = new JksStore();
            using var ms = new System.IO.MemoryStream();
            var password = ResolvePassword(null);
            jksStore.Save(ms, password.ToCharArray());
            var jksBytes = ms.ToArray();

            var k8sData = new KubeCertificateManagerClient.JksSecret
            {
                Secret = null,
                Inventory = new Dictionary<string, byte[]>
                {
                    { "keystore.jks", jksBytes }
                }
            };

            return KubeClient.CreateOrUpdateJksSecret(k8sData, Context.KubeSecretName, Context.KubeNamespace);
        }
        finally
        {
            LogMethodExit(nameof(CreateEmptyStore));
        }
    }

    #endregion

    #region Discovery Operations

    /// <inheritdoc />
    public override List<string> DiscoverStores(string[] allowedKeys, string namespacesCsv,
        IEnumerable<string> ignoredNamespaces = null)
    {
        LogMethodEntry(nameof(DiscoverStores));

        try
        {
            var keys = allowedKeys?.Length > 0 ? allowedKeys : AllowedKeys;
            return KubeClient.DiscoverSecrets(keys, "Opaque", namespacesCsv, ignoredNamespaces: ignoredNamespaces);
        }
        finally
        {
            LogMethodExit(nameof(DiscoverStores));
        }
    }

    #endregion
}
