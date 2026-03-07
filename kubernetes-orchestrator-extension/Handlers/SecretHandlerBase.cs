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
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Base class for secret handlers providing common functionality.
/// Subclasses implement store-type-specific logic.
/// </summary>
public abstract class SecretHandlerBase : ISecretHandler
{
    /// <summary>
    /// Kubernetes client for API operations.
    /// </summary>
    protected readonly KubeCertificateManagerClient KubeClient;

    /// <summary>
    /// Logger for diagnostic output.
    /// </summary>
    protected readonly ILogger Logger;

    /// <summary>
    /// Operation context with configuration and job parameters.
    /// </summary>
    protected readonly ISecretOperationContext Context;

    /// <summary>
    /// Certificate chain extractor service.
    /// </summary>
    protected readonly CertificateChainExtractor CertExtractor;

    /// <summary>
    /// Initializes a new instance of the handler.
    /// </summary>
    /// <param name="kubeClient">Kubernetes client.</param>
    /// <param name="logger">Logger instance.</param>
    /// <param name="context">Operation context.</param>
    protected SecretHandlerBase(
        KubeCertificateManagerClient kubeClient,
        ILogger logger,
        ISecretOperationContext context)
    {
        KubeClient = kubeClient ?? throw new ArgumentNullException(nameof(kubeClient));
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Context = context ?? throw new ArgumentNullException(nameof(context));
        CertExtractor = new CertificateChainExtractor(kubeClient, logger);
    }

    #region Abstract Members

    /// <inheritdoc />
    public abstract string[] AllowedKeys { get; }

    /// <inheritdoc />
    public abstract string SecretTypeName { get; }

    /// <inheritdoc />
    public abstract bool SupportsManagement { get; }

    /// <inheritdoc />
    public virtual List<string> GetCertificates(long jobId)
    {
        var aliasedCerts = GetCertificatesWithAliases(jobId);
        var allCerts = new List<string>();
        foreach (var kvp in aliasedCerts)
            allCerts.AddRange(kvp.Value);
        return allCerts;
    }

    /// <inheritdoc />
    public abstract Dictionary<string, List<string>> GetCertificatesWithAliases(long jobId);

    /// <inheritdoc />
    public abstract List<InventoryEntry> GetInventoryEntries(long jobId);

    /// <inheritdoc />
    public abstract bool HasPrivateKey();

    /// <inheritdoc />
    public abstract V1Secret HandleAdd(K8SJobCertificate certObj, string alias, bool overwrite);

    /// <inheritdoc />
    public abstract V1Secret HandleRemove(string alias);

    /// <inheritdoc />
    public abstract V1Secret CreateEmptyStore();

    /// <inheritdoc />
    public abstract List<string> DiscoverStores(string[] allowedKeys, string namespacesCsv);

    #endregion

    #region Protected Helpers

    /// <summary>
    /// Resolves the store password, checking a buddy secret first then falling back to the configured password.
    /// </summary>
    /// <param name="secret">The primary secret (unused, kept for signature compatibility).</param>
    /// <returns>The resolved password string.</returns>
    protected string ResolvePassword(V1Secret secret)
    {
        if (!string.IsNullOrEmpty(Context.PasswordSecretPath))
        {
            var pathParts = Context.PasswordSecretPath.Split('/');
            var passwordNamespace = pathParts.Length > 1 ? pathParts[0] : Context.KubeNamespace;
            var passwordSecretName = pathParts.Length > 1 ? pathParts[^1] : pathParts[0];

            var buddySecret = KubeClient.ReadBuddyPass(passwordSecretName, passwordNamespace);
            if (buddySecret?.Data != null)
            {
                var fieldName = Context.PasswordFieldName ?? "password";
                if (buddySecret.Data.TryGetValue(fieldName, out var passwordBytes) && passwordBytes != null)
                    return Encoding.UTF8.GetString(passwordBytes).TrimEnd('\n', '\r');
            }
        }

        return Context.StorePassword ?? "";
    }

    /// <summary>
    /// Returns true if the secret has no meaningful certificate data (e.g. created via "create if missing").
    /// An empty secret can be implicitly overwritten without the overwrite flag.
    /// </summary>
    public static bool IsSecretEmpty(V1Secret secret)
    {
        if (secret?.Data == null || secret.Data.Count == 0)
            return true;

        return secret.Data.Values.All(v => v == null || v.Length == 0);
    }

    /// <summary>
    /// Handles the "create store if missing" case: returns existing secret if present, otherwise creates an empty store.
    /// </summary>
    /// <returns>The existing or newly created secret.</returns>
    protected V1Secret HandleCreateIfMissing()
    {
        try
        {
            var existingSecret = GetSecret();
            Logger.LogInformation("Secret already exists, nothing to do for empty certificate data");
            return existingSecret;
        }
        catch (StoreNotFoundException)
        {
            Logger.LogDebug("Secret not found, creating empty {Type} store", SecretTypeName);
            return CreateEmptyStore();
        }
    }

    /// <summary>
    /// Gets the secret from Kubernetes.
    /// </summary>
    /// <returns>The V1Secret object.</returns>
    /// <exception cref="StoreNotFoundException">Thrown if secret doesn't exist.</exception>
    protected V1Secret GetSecret()
    {
        Logger.LogDebug("Getting secret {Name} from namespace {Namespace}",
            Context.KubeSecretName, Context.KubeNamespace);

        return KubeClient.GetCertificateStoreSecret(Context.KubeSecretName, Context.KubeNamespace);
    }

    /// <summary>
    /// Creates or updates a TLS or Opaque secret in Kubernetes.
    /// For JKS/PKCS12, use specialized KubeClient methods instead.
    /// </summary>
    /// <param name="keyPem">Private key in PEM format.</param>
    /// <param name="certPem">Certificate in PEM format.</param>
    /// <param name="chainPem">Certificate chain as list of PEM strings.</param>
    /// <param name="secretType">Secret type (tls or opaque).</param>
    /// <param name="separateChain">Whether to store chain separately.</param>
    /// <param name="includeChain">Whether to include chain.</param>
    /// <returns>The created/updated secret.</returns>
    protected V1Secret CreateOrUpdatePemSecret(
        string keyPem,
        string certPem,
        List<string> chainPem,
        string secretType,
        bool separateChain = true,
        bool includeChain = true)
    {
        Logger.LogDebug("Creating/updating {Type} secret {Name} in namespace {Namespace}",
            secretType, Context.KubeSecretName, Context.KubeNamespace);

        return KubeClient.CreateOrUpdateCertificateStoreSecret(
            keyPem,
            certPem,
            chainPem,
            Context.KubeSecretName,
            Context.KubeNamespace,
            secretType,
            append: false,
            overwrite: true,
            remove: false,
            separateChain: separateChain,
            includeChain: includeChain);
    }

    /// <summary>
    /// Deletes a secret from Kubernetes.
    /// </summary>
    /// <param name="alias">Optional alias for keystore entries.</param>
    protected void DeleteSecret(string alias = "")
    {
        Logger.LogDebug("Deleting secret {Name} from namespace {Namespace}",
            Context.KubeSecretName, Context.KubeNamespace);

        KubeClient.DeleteCertificateStoreSecret(
            Context.KubeSecretName,
            Context.KubeNamespace,
            SecretTypeName,
            alias);
    }

    /// <summary>
    /// Checks if the secret exists in Kubernetes.
    /// </summary>
    /// <returns>True if the secret exists.</returns>
    protected bool SecretExists()
    {
        try
        {
            GetSecret();
            return true;
        }
        catch (StoreNotFoundException)
        {
            return false;
        }
    }

    /// <summary>
    /// Builds allowed keys list from context and defaults.
    /// </summary>
    /// <param name="defaultKeys">Default keys for this handler type.</param>
    /// <returns>Combined list of allowed keys.</returns>
    protected string[] BuildAllowedKeys(string[] defaultKeys)
    {
        var keys = new List<string>();

        // Add custom field name if specified
        if (!string.IsNullOrEmpty(Context.CertificateDataFieldName))
        {
            keys.AddRange(Context.CertificateDataFieldName.Split(','));
        }

        // Add default keys
        keys.AddRange(defaultKeys);

        return keys.ToArray();
    }

    /// <summary>
    /// Parses a keystore alias of the form <c>&lt;fieldName&gt;/&lt;certAlias&gt;</c> and resolves the
    /// corresponding existing data and key name from the supplied inventory.
    /// </summary>
    /// <param name="alias">The raw alias string (e.g. <c>"keystore.jks/mycert"</c> or just <c>"mycert"</c>).</param>
    /// <param name="inventory">The current K8S secret inventory (field → bytes). May be null or empty.</param>
    /// <param name="defaultFieldName">Field name to use when no prefix is present and the inventory is empty.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    ///   <item><c>fieldName</c> — the K8S secret field name extracted from the alias, or <c>null</c> if no separator was found.</item>
    ///   <item><c>certAlias</c> — the alias inside the keystore file.</item>
    ///   <item><c>existingData</c> — the current bytes for the resolved field, or <c>null</c> if the field does not yet exist.</item>
    ///   <item><c>existingKeyName</c> — the resolved field name to write to.</item>
    /// </list>
    /// </returns>
    protected (string fieldName, string certAlias, byte[] existingData, string existingKeyName) ParseKeystoreAlias(
        string alias,
        Dictionary<string, byte[]> inventory,
        string defaultFieldName)
    {
        var separatorIdx = alias.IndexOf('/');
        var fieldName = separatorIdx > 0 ? alias[..separatorIdx] : null;
        var certAlias = separatorIdx > 0 ? alias[(separatorIdx + 1)..] : alias;

        Logger.LogDebug("Parsed alias '{Alias}' → field='{Field}', certAlias='{CertAlias}'",
            alias, fieldName ?? "(none)", certAlias);

        byte[] existingData = null;
        string existingKeyName = fieldName ?? defaultFieldName;

        if (inventory != null && inventory.Count > 0)
        {
            if (fieldName != null && inventory.TryGetValue(fieldName, out var fieldBytes))
            {
                existingData = fieldBytes;
            }
            else if (fieldName == null)
            {
                var firstKey = inventory.Keys.First();
                existingData = inventory[firstKey];
                existingKeyName = firstKey;
            }
            // else: fieldName specified but not yet in inventory → existingData stays null (new field)
        }

        return (fieldName, certAlias, existingData, existingKeyName);
    }

    /// <summary>
    /// Logs entry to a method.
    /// </summary>
    /// <param name="methodName">Name of the method.</param>
    protected void LogMethodEntry(string methodName)
    {
        Logger.MethodEntry(LogLevel.Debug);
        Logger.LogDebug("Entering {Method} for {Type} in {Namespace}/{Secret}",
            methodName, SecretTypeName, Context.KubeNamespace, Context.KubeSecretName);
    }

    /// <summary>
    /// Logs exit from a method.
    /// </summary>
    /// <param name="methodName">Name of the method.</param>
    protected void LogMethodExit(string methodName)
    {
        Logger.LogDebug("Exiting {Method}", methodName);
        Logger.MethodExit(LogLevel.Debug);
    }

    #endregion
}
