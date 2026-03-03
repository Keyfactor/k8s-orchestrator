// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Handler for namespace-level certificate management.
/// Discovers and manages all TLS and Opaque secrets within a single namespace.
/// </summary>
public class NamespaceSecretHandler : SecretHandlerBase
{
    /// <summary>
    /// Allowed keys for both TLS and Opaque secrets.
    /// </summary>
    private static readonly string[] DefaultAllowedKeys =
    {
        "tls.crt", "tls.key", "ca.crt",
        "certificate", "cert", "crt", "cert.pem"
    };

    /// <inheritdoc />
    public override string[] AllowedKeys => DefaultAllowedKeys;

    /// <inheritdoc />
    public override string SecretTypeName => "namespace";

    /// <inheritdoc />
    public override bool SupportsManagement => true;

    /// <summary>
    /// Initializes a new instance of the NamespaceSecretHandler.
    /// </summary>
    public NamespaceSecretHandler(
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
        var entries = GetInventoryEntries(jobId);
        return entries.SelectMany(e => e.Certificates).ToList();
    }

    /// <inheritdoc />
    public override Dictionary<string, List<string>> GetCertificatesWithAliases(long jobId)
    {
        var entries = GetInventoryEntries(jobId);
        return entries.ToDictionary(e => e.Alias, e => e.Certificates);
    }

    /// <inheritdoc />
    public override List<InventoryEntry> GetInventoryEntries(long jobId)
    {
        LogMethodEntry(nameof(GetInventoryEntries));

        try
        {
            var entries = new List<InventoryEntry>();
            var errors = new List<string>();
            var targetNamespace = Context.KubeNamespace;

            // Discover TLS secrets in the namespace
            var tlsSecrets = KubeClient.DiscoverSecrets(
                new[] { "tls.crt" },
                "kubernetes.io/tls",
                targetNamespace);

            foreach (var secretPath in tlsSecrets)
            {
                ProcessSecretEntry(secretPath, "tls", entries, errors, jobId);
            }

            // Discover Opaque secrets in the namespace
            var opaqueSecrets = KubeClient.DiscoverSecrets(
                new[] { "tls.crt", "certificate", "cert", "crt" },
                "Opaque",
                targetNamespace);

            foreach (var secretPath in opaqueSecrets)
            {
                ProcessSecretEntry(secretPath, "opaque", entries, errors, jobId);
            }

            if (errors.Count > 0)
            {
                Logger.LogWarning("Errors processing {Count} secrets: {Errors}",
                    errors.Count, string.Join("; ", errors));
            }

            return entries;
        }
        finally
        {
            LogMethodExit(nameof(GetInventoryEntries));
        }
    }

    /// <inheritdoc />
    public override bool HasPrivateKey()
    {
        // Namespace-level handler - depends on individual secrets
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
            // Parse alias to determine target secret: type/name
            var (secretType, secretName) = ParseNamespaceAlias(alias);

            // Create context for inner handler
            var innerContext = CreateInnerContext(secretName);
            var handler = CreateInnerHandler(secretType, innerContext);

            return handler.HandleAdd(certObj, alias, overwrite);
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
            var (secretType, secretName) = ParseNamespaceAlias(alias);

            var innerContext = CreateInnerContext(secretName);
            var handler = CreateInnerHandler(secretType, innerContext);

            return handler.HandleRemove(alias);
        }
        finally
        {
            LogMethodExit(nameof(HandleRemove));
        }
    }

    /// <inheritdoc />
    public override V1Secret CreateEmptyStore()
    {
        throw new NotSupportedException(
            "Namespace-wide stores cannot be created as empty stores. " +
            "Create individual secrets instead.");
    }

    #endregion

    #region Discovery Operations

    /// <inheritdoc />
    public override List<string> DiscoverStores(string[] allowedKeys, string namespacesCsv)
    {
        LogMethodEntry(nameof(DiscoverStores));

        try
        {
            var targetNamespace = string.IsNullOrEmpty(namespacesCsv)
                ? Context.KubeNamespace
                : namespacesCsv;

            var stores = new List<string>();

            // Discover TLS secrets
            stores.AddRange(KubeClient.DiscoverSecrets(
                new[] { "tls.crt" },
                "kubernetes.io/tls",
                targetNamespace));

            // Discover Opaque secrets with cert data
            stores.AddRange(KubeClient.DiscoverSecrets(
                new[] { "tls.crt", "certificate", "cert", "crt" },
                "Opaque",
                targetNamespace));

            return stores.Distinct().ToList();
        }
        finally
        {
            LogMethodExit(nameof(DiscoverStores));
        }
    }

    #endregion

    #region Private Helpers

    private void ProcessSecretEntry(
        string secretPath,
        string secretType,
        List<InventoryEntry> entries,
        List<string> errors,
        long jobId)
    {
        try
        {
            // secretPath format: namespace/secretname
            var parts = secretPath.Split('/');
            var name = parts.Length >= 2 ? parts[^1] : secretPath;

            var innerContext = CreateInnerContext(name);
            var handler = CreateInnerHandler(secretType, innerContext);

            var innerEntries = handler.GetInventoryEntries(jobId);

            // Modify aliases for namespace view: type/name
            foreach (var entry in innerEntries)
            {
                entry.Alias = $"{secretType}/{name}";
                entries.Add(entry);
            }
        }
        catch (Exception ex)
        {
            errors.Add($"{secretPath}: {ex.Message}");
        }
    }

    private (string SecretType, string SecretName) ParseNamespaceAlias(string alias)
    {
        // Expected format: type/name
        var parts = alias.Split('/');
        if (parts.Length < 2)
        {
            throw new ArgumentException(
                $"Invalid namespace alias format: '{alias}'. Expected: type/name");
        }

        return (parts[0], parts[1]);
    }

    private ISecretOperationContext CreateInnerContext(string name)
    {
        return new SimpleSecretOperationContext
        {
            KubeNamespace = Context.KubeNamespace,
            KubeSecretName = name,
            StorePath = $"{Context.KubeNamespace}/{name}",
            StorePassword = Context.StorePassword,
            PasswordSecretPath = Context.PasswordSecretPath,
            PasswordFieldName = Context.PasswordFieldName,
            SeparateChain = Context.SeparateChain,
            IncludeCertChain = Context.IncludeCertChain,
            CertificateDataFieldName = Context.CertificateDataFieldName
        };
    }

    private ISecretHandler CreateInnerHandler(string secretType, ISecretOperationContext innerContext)
    {
        var normalizedType = SecretTypes.Normalize(secretType);

        return normalizedType switch
        {
            SecretTypes.Tls => new TlsSecretHandler(KubeClient, Logger, innerContext),
            SecretTypes.Opaque => new OpaqueSecretHandler(KubeClient, Logger, innerContext),
            _ => throw new NotSupportedException($"Inner secret type '{secretType}' not supported")
        };
    }

    #endregion
}
