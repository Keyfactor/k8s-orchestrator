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

            // One namespace list and one secret list for the namespace; the listed secrets (with data) are handed
            // to the inner handlers so no secret is read again (GitHub issue #104). TLS secrets come first, then
            // every Opaque secret (#101), exactly as the two separate discovery passes used to order them.
            foreach (var found in KubeClient.DiscoverNamespaceInventorySecrets(targetNamespace))
            {
                ProcessSecretEntry(found, entries, errors, jobId);
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
    public override List<string> DiscoverStores(string[] allowedKeys, string namespacesCsv,
        IEnumerable<string> ignoredNamespaces = null)
    {
        LogMethodEntry(nameof(DiscoverStores));

        try
        {
            // A K8SNS store IS a namespace (it manages every secret in it), so discovery returns one
            // "<cluster>/namespace/<ns>" location per namespace matched by 'Directories to search'
            // (a CSV of names, or "all") - the same shape 1.x returned and that StorePathResolver resolves for
            // K8SNS. namespacesCsv is never empty here (DiscoveryBase.GetNamespacesToSearch falls back to
            // "default"). Secrets inside the namespaces are deliberately not enumerated, so allowedKeys
            // (job patterns) do not apply and are not passed: every matched namespace is reported, as in 1.x.
            // DiscoverSecrets emits one entry per namespace, so no de-duplication is needed.
            return KubeClient.DiscoverSecrets(
                null,
                "namespace",
                namespacesCsv,
                ignoredNamespaces: ignoredNamespaces);
        }
        finally
        {
            LogMethodExit(nameof(DiscoverStores));
        }
    }

    #endregion

    #region Private Helpers

    private void ProcessSecretEntry(
        KubeCertificateManagerClient.DiscoveredSecret found,
        List<InventoryEntry> entries,
        List<string> errors,
        long jobId)
    {
        try
        {
            var name = found.Name;

            var innerContext = CreateInnerContext(name);
            var handler = CreateInnerHandler(found.Kind, innerContext);
            handler.UseSecret(found.Secret);

            var innerEntries = handler.GetInventoryEntries(jobId);

            // Modify aliases for namespace view: type/name
            foreach (var entry in innerEntries)
            {
                entry.Alias = $"{found.Kind}/{name}";
                entries.Add(entry);
            }
        }
        catch (Exception ex)
        {
            errors.Add($"{found.Location}: {ex.Message}");
        }
    }

    private (string SecretType, string SecretName) ParseNamespaceAlias(string alias)
    {
        // Expected format: [secrets/]<type>/<name> - uses last two parts
        // Examples: "opaque/my-secret" or "secrets/opaque/my-secret"
        var parts = alias.Split('/');
        if (parts.Length < 2)
        {
            throw new ArgumentException(
                $"Invalid namespace alias format: '{alias}'. Expected: <type>/<name> or secrets/<type>/<name>");
        }

        // Use ^2 and ^1 to get second-to-last (type) and last (name)
        return (parts[^2], parts[^1]);
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

    private SecretHandlerBase CreateInnerHandler(string secretType, ISecretOperationContext innerContext)
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
