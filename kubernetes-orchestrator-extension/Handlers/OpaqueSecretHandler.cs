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
/// Handler for Opaque secrets containing PEM-encoded certificates.
/// Opaque secrets can have various field names for certificate and key data.
/// </summary>
public class OpaqueSecretHandler : SecretHandlerBase
{
    /// <summary>
    /// Default allowed data keys for Opaque secrets containing certificates.
    /// </summary>
    private static readonly string[] DefaultAllowedKeys =
    {
        "tls.crt", "certificate", "cert", "crt", "cert.pem", "certificate.pem",
        "tls.key", "key", "private-key", "key.pem", "private-key.pem",
        "ca.crt", "ca", "ca-bundle", "ca-bundle.crt"
    };

    /// <inheritdoc />
    public override string[] AllowedKeys => DefaultAllowedKeys;

    /// <inheritdoc />
    public override string SecretTypeName => "opaque";

    /// <inheritdoc />
    public override bool SupportsManagement => true;

    /// <summary>
    /// Initializes a new instance of the OpaqueSecretHandler.
    /// </summary>
    public OpaqueSecretHandler(
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
        catch (HttpOperationException e)
        {
            Logger.LogError("Kubernetes Opaque secret '{Name}' was not found in namespace '{Namespace}'",
                Context.KubeSecretName, Context.KubeNamespace);
            throw new StoreNotFoundException(
                $"Kubernetes Opaque secret '{Context.KubeSecretName}' was not found in namespace '{Context.KubeNamespace}'.");
        }
        finally
        {
            LogMethodExit(nameof(GetCertificates));
        }
    }

    /// <inheritdoc />
    public override Dictionary<string, List<string>> GetCertificatesWithAliases(long jobId)
    {
        // Opaque secrets don't use aliases - return single entry with secret name as alias
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
            if (secret.Data == null) return false;

            // Check various key field names
            var keyFields = new[] { "tls.key", "key", "private-key", "key.pem", "private-key.pem" };
            foreach (var field in keyFields)
            {
                if (secret.Data.TryGetValue(field, out var keyBytes) &&
                    keyBytes != null &&
                    keyBytes.Length > 0)
                {
                    return true;
                }
            }

            return false;
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
                Logger.LogWarning("Secret already exists and overwrite is false");
                throw new InvalidOperationException(
                    $"Secret '{Context.KubeSecretName}' already exists. Set overwrite=true to replace.");
            }

            // Create or update secret using the PEM helper
            return CreateOrUpdatePemSecret(
                certObj.PrivateKeyPem,
                certObj.CertPem,
                certObj.ChainPem ?? new List<string>(),
                "opaque",
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
            // Opaque secrets are single-entry, so remove means delete the whole secret
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
            // Create empty Opaque secret
            return CreateOrUpdatePemSecret(
                "",
                "",
                new List<string>(),
                "opaque",
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
            return KubeClient.DiscoverSecrets(keys, "Opaque", namespacesCsv);
        }
        finally
        {
            LogMethodExit(nameof(DiscoverStores));
        }
    }

    #endregion

    #region Private Helpers

    private List<string> ExtractCertificatesFromSecret(V1Secret secret)
    {
        if (secret.Data == null)
        {
            Logger.LogWarning("Secret '{Name}' has no data", Context.KubeSecretName);
            return new List<string>();
        }

        var keys = BuildAllowedKeys(DefaultAllowedKeys);
        return CertExtractor.ExtractFromSecretData(
            secret.Data,
            keys,
            Context.KubeSecretName,
            Context.KubeNamespace);
    }

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
            Logger.LogDebug("Secret not found, creating empty Opaque secret");
            return CreateEmptyStore();
        }
    }

    #endregion
}
