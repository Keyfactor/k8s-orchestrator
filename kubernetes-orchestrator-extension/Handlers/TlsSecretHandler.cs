// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using k8s.Autorest;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Handler for kubernetes.io/tls secrets.
/// TLS secrets contain tls.crt (certificate chain) and tls.key (private key) fields.
/// </summary>
public class TlsSecretHandler : SecretHandlerBase
{
    /// <summary>
    /// Default allowed data keys for TLS secrets.
    /// </summary>
    private static readonly string[] DefaultAllowedKeys = { "tls.crt", "tls.key", "ca.crt" };

    /// <inheritdoc />
    public override string[] AllowedKeys => DefaultAllowedKeys;

    /// <inheritdoc />
    public override string SecretTypeName => "tls";

    /// <inheritdoc />
    public override bool SupportsManagement => true;

    /// <summary>
    /// Initializes a new instance of the TlsSecretHandler.
    /// </summary>
    public TlsSecretHandler(
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
        LogMethodEntry(nameof(GetCertificates));

        try
        {
            var secret = GetSecret();
            return ExtractCertificatesFromSecret(secret);
        }
        catch (HttpOperationException)
        {
            Logger.LogError("Kubernetes TLS secret '{Name}' was not found in namespace '{Namespace}'",
                Context.KubeSecretName, Context.KubeNamespace);
            throw new StoreNotFoundException(
                $"Kubernetes TLS secret '{Context.KubeSecretName}' was not found in namespace '{Context.KubeNamespace}'.");
        }
        finally
        {
            LogMethodExit(nameof(GetCertificates));
        }
    }

    /// <inheritdoc />
    public override Dictionary<string, List<string>> GetCertificatesWithAliases(long jobId)
    {
        // TLS secrets don't use aliases - return single entry with secret name as alias
        var certs = GetCertificates(jobId);
        return new Dictionary<string, List<string>>
        {
            { Context.KubeSecretName, certs }
        };
    }

    /// <inheritdoc />
    public override List<InventoryEntry> GetInventoryEntries(long jobId)
    {
        var certs = GetCertificates(jobId);
        var hasKey = HasPrivateKey();

        return new List<InventoryEntry>
        {
            new InventoryEntry
            {
                Alias = Context.KubeSecretName,
                Certificates = certs,
                HasPrivateKey = hasKey
            }
        };
    }

    /// <inheritdoc />
    public override bool HasPrivateKey()
    {
        try
        {
            var secret = GetSecret();
            return secret.Data != null &&
                   secret.Data.TryGetValue("tls.key", out var keyBytes) &&
                   keyBytes != null &&
                   keyBytes.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    #endregion

    #region Management Operations

    /// <inheritdoc />
    public override V1Secret HandleAdd(K8SJobCertificate certObj, string alias, bool overwrite)
    {
        LogMethodEntry(nameof(HandleAdd));

        try
        {
            // Handle "create store if missing" - when no certificate data is provided
            if (string.IsNullOrEmpty(alias) && string.IsNullOrEmpty(certObj?.CertPem))
            {
                return HandleCreateIfMissing();
            }

            // Check if secret exists
            V1Secret existingSecret = null;
            try
            {
                existingSecret = GetSecret();
            }
            catch (StoreNotFoundException)
            {
                // Secret doesn't exist, will create new one
            }

            if (existingSecret != null && !overwrite)
            {
                if (IsSecretEmpty(existingSecret))
                {
                    Logger.LogDebug("Secret '{Name}' exists but is empty; overwriting implicitly", Context.KubeSecretName);
                }
                else
                {
                    Logger.LogWarning("Secret already exists and overwrite is false");
                    throw new InvalidOperationException(
                        $"Secret '{Context.KubeSecretName}' already exists. Set overwrite=true to replace.");
                }
            }

            // Validate cert-only updates: prevent deploying certificate without private key
            // to an existing secret that has a key (would cause key/cert mismatch)
            var incomingHasNoPrivateKey = string.IsNullOrEmpty(certObj?.PrivateKeyPem);
            if (existingSecret != null && overwrite && incomingHasNoPrivateKey)
            {
                ValidateCertOnlyUpdate(existingSecret);
            }

            // Create or update secret using the PEM helper
            return CreateOrUpdatePemSecret(
                certObj.PrivateKeyPem,
                certObj.CertPem,
                certObj.ChainPem ?? new List<string>(),
                "tls",
                Context.SeparateChain,
                Context.IncludeCertChain);
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
            // TLS secrets are single-entry, so remove means delete the whole secret
            DeleteSecret(alias);
            return null;
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
            // Create empty TLS secret
            return CreateOrUpdatePemSecret(
                "",
                "",
                new List<string>(),
                "tls",
                separateChain: false,
                includeChain: false);
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
            return KubeClient.DiscoverSecrets(keys, "kubernetes.io/tls", namespacesCsv);
        }
        finally
        {
            LogMethodExit(nameof(DiscoverStores));
        }
    }

    #endregion

    #region Private Helpers

    // ValidateCertOnlyUpdate is inherited from SecretHandlerBase.
    // TlsSecretHandler uses the default PrivateKeyFieldNames = { "tls.key" }.

    private List<string> ExtractCertificatesFromSecret(V1Secret secret)
    {
        // Check if tls.crt exists and has data
        if (secret.Data == null ||
            !secret.Data.TryGetValue("tls.crt", out var certBytes) ||
            certBytes == null ||
            certBytes.Length == 0)
        {
            Logger.LogWarning("Secret '{Name}' has no certificate data (tls.crt is empty or missing)",
                Context.KubeSecretName);
            return new List<string>();
        }

        // Extract certificates from tls.crt
        var sourceDesc = $"secret '{Context.KubeSecretName}' key 'tls.crt'";
        var certsList = CertExtractor.ExtractCertificates(certBytes, sourceDesc);

        if (certsList.Count == 0)
        {
            throw new InvalidOperationException(
                $"Failed to parse certificate from secret '{Context.KubeSecretName}'. " +
                "The certificate data could not be parsed as PEM or DER format.");
        }

        // Add CA chain certificates from ca.crt if present (avoiding duplicates)
        if (secret.Data.TryGetValue("ca.crt", out var caBytes))
        {
            CertExtractor.ExtractAndAppendUnique(
                caBytes,
                certsList,
                $"secret '{Context.KubeSecretName}' key 'ca.crt'");
        }

        return certsList;
    }

    #endregion
}
