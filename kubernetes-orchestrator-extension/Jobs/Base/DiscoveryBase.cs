// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;

/// <summary>
/// Base class for store-type-specific discovery jobs.
/// Handles common discovery workflow: initialize, discover stores via handler, return locations.
/// Store-type-specific classes inherit from this and may override methods as needed.
/// </summary>
public abstract class DiscoveryBase : K8SJobBase, IDiscoveryJobExtension
{
    /// <summary>
    /// Initializes a new instance with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    protected DiscoveryBase(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    /// <summary>
    /// Gets the allowed keys for this store type's discovery.
    /// Override in subclasses to specify store-type-specific keys.
    /// </summary>
    protected virtual string[] AllowedKeys => Handler?.AllowedKeys ?? Array.Empty<string>();

    /// <summary>
    /// Processes the discovery job by delegating to the appropriate handler.
    /// </summary>
    /// <param name="config">The discovery job configuration.</param>
    /// <param name="submitDiscovery">Callback to submit discovered stores.</param>
    /// <returns>Job result indicating success or failure.</returns>
    public virtual JobResult ProcessJob(DiscoveryJobConfiguration config, SubmitDiscoveryUpdate submitDiscovery)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(LogLevel.Debug);

        try
        {
            Logger.LogDebug("Initializing store for discovery job {JobId}", config.JobId);
            InitializeStore(config);

            Logger.LogInformation(
                "AUDIT store_access: JobType={JobType} Capability={Capability} StorePath={StorePath} " +
                "Namespace={Namespace} SecretName={SecretName} JobHistoryId={JobHistoryId} Outcome=STARTED",
                GetType().Name, Capability, StorePath, KubeNamespace, KubeSecretName, config.JobHistoryId);

            Logger.LogDebug("Initializing handler for discovery");
            InitializeHandler(config);

            if (Handler == null)
            {
                Logger.LogInformation(
                    "AUDIT store_access: JobType={JobType} Capability={Capability} StorePath={StorePath} " +
                    "Namespace={Namespace} SecretName={SecretName} JobHistoryId={JobHistoryId} Outcome=FAILED",
                    GetType().Name, Capability, StorePath, KubeNamespace, KubeSecretName, config.JobHistoryId);
                return FailJob($"No handler available for store type: {KubeSecretType}", config.JobHistoryId);
            }

            Logger.LogInformation("Begin DISCOVERY for {StoreType} job {JobId}", KubeSecretType, config.JobId);

            // Get namespaces to search from job properties
            var namespacesCsv = GetNamespacesToSearch(config);

            // Get custom allowed keys from job properties (additive to the handler defaults)
            var customKeys = MergeWithDefaultKeys(GetCustomAllowedKeys(config));
            Logger.LogDebug("Discovery namespaces: '{Namespaces}', custom allowed keys: [{Keys}]",
                namespacesCsv, string.Join(", ", customKeys ?? Array.Empty<string>()));

            var ignoredDirs = GetIgnoredNamespaces(config);

            // Discover stores via handler. The ignored namespaces are handed to the handler so they are excluded
            // BEFORE any secrets are listed: a service account that cannot list secrets in an ignored namespace
            // (e.g. kube-system) must not fail the job when the user asked to skip that namespace.
            var discoveredStores = Handler.DiscoverStores(customKeys, namespacesCsv, ignoredDirs);

            // Defense in depth: also post-filter the returned locations by namespace, so 'Directories to ignore'
            // holds for any handler that does not (fully) apply the ignore list itself.
            discoveredStores = FilterIgnoredNamespaces(discoveredStores, ignoredDirs, out var droppedStores);
            if (droppedStores.Count > 0)
                Logger.LogDebug(
                    "Dropped {Count} discovered location(s) in ignored namespaces [{IgnoredDirs}]: {Dropped}",
                    droppedStores.Count, string.Join(", ", ignoredDirs), string.Join(", ", droppedStores));

            Logger.LogInformation("Discovered {Count} stores", discoveredStores.Count);
            if (discoveredStores.Count == 0)
                Logger.LogWarning(
                    "Discovery found 0 stores. Namespaces searched: '{Namespaces}'; namespaces ignored: [{IgnoredDirs}]. " +
                    "Verify the 'Directories to search' value (use 'all' or a comma-separated list of existing " +
                    "namespaces), that it is not entirely covered by 'Directories to ignore', and that the service " +
                    "account can list namespaces and secrets",
                    namespacesCsv, string.Join(", ", ignoredDirs));

            // Submit discovered stores
            submitDiscovery.Invoke(discoveredStores);

            Logger.LogInformation(
                "AUDIT store_access: JobType={JobType} Capability={Capability} StorePath={StorePath} " +
                "Namespace={Namespace} SecretName={SecretName} JobHistoryId={JobHistoryId} Outcome=COMPLETED",
                GetType().Name, Capability, StorePath, KubeNamespace, KubeSecretName, config.JobHistoryId);
            return SuccessJob(config.JobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Discovery failed: {Message}", ex.Message);
            Logger.LogInformation(
                "AUDIT store_access: JobType={JobType} Capability={Capability} StorePath={StorePath} " +
                "Namespace={Namespace} SecretName={SecretName} JobHistoryId={JobHistoryId} Outcome=FAILED",
                GetType().Name, Capability, StorePath, KubeNamespace, KubeSecretName, config.JobHistoryId);
            return FailJob(ex, config.JobHistoryId);
        }
        finally
        {
            Logger.LogInformation("End DISCOVERY for job {JobId}", config.JobId);
            Logger.MethodExit(LogLevel.Debug);
        }
    }

    // Keys delivered by Keyfactor Command for a discovery job. The framework supplies
    // DiscoveryJobConfiguration.JobProperties as a plain dictionary keyed by the lower-case names
    // dirs, extensions, ignoreddirs and patterns. The "friendly" names are accepted as aliases.
    // Lookup is case-insensitive.
    private static readonly string[] DirectoriesKeys = { "dirs", "Directories" };
    private static readonly string[] ExtensionsKeys = { "extensions", "Extensions" };
    private static readonly string[] PatternsKeys = { "patterns", "Patterns" };
    private static readonly string[] IgnoredDirsKeys = { "ignoreddirs", "IgnoredDirectories", "IgnoredDirs" };

    private const string AllNamespaces = "all";
    private const string FallbackNamespace = "default";

    /// <summary>
    /// When true, the discovery <c>extensions</c> job property is also treated as a list of secret field
    /// names/extensions to look for (in addition to <c>patterns</c>). Mirrors the 1.x behaviour, where only the
    /// keystore store types (JKS, PKCS12) honoured <c>extensions</c>.
    /// </summary>
    protected virtual bool UseExtensionsAsAllowedKeys => false;

    /// <summary>
    /// Gets the namespaces to search from the job configuration (<c>dirs</c> job property).
    /// </summary>
    /// <param name="config">The discovery job configuration.</param>
    /// <returns>
    /// Comma-separated list of trimmed namespace names, or <c>all</c> if any entry is <c>all</c> (case-insensitive).
    /// Falls back to <c>default</c> (with a warning) if no directories were supplied.
    /// </returns>
    protected virtual string GetNamespacesToSearch(DiscoveryJobConfiguration config)
    {
        var raw = TryGetJobProperty(config?.JobProperties, DirectoriesKeys);
        Logger?.LogDebug("Discovery 'Directories to search' (dirs) raw value: '{Value}'", raw ?? "(not provided)");

        var namespaces = SplitList(raw, ',');
        if (namespaces.Any(n => n.Equals(AllNamespaces, StringComparison.OrdinalIgnoreCase)))
        {
            Logger?.LogDebug("Discovery will search all namespaces");
            return AllNamespaces;
        }

        if (namespaces.Length == 0)
        {
            Logger?.LogWarning(
                "No 'Directories to search' (dirs) value was provided for discovery job; falling back to the '{Fallback}' namespace. " +
                "Set 'Directories to search' to a comma-separated list of namespaces or 'all' to search every namespace",
                FallbackNamespace);
            return FallbackNamespace;
        }

        var csv = string.Join(",", namespaces.Distinct(StringComparer.Ordinal));
        Logger?.LogDebug("Discovery will search namespaces: {Namespaces}", csv);
        return csv;
    }

    /// <summary>
    /// Gets custom allowed keys from the job configuration (<c>patterns</c> job property, plus
    /// <c>extensions</c> when <see cref="UseExtensionsAsAllowedKeys"/> is true).
    /// </summary>
    /// <param name="config">The discovery job configuration.</param>
    /// <returns>Array of custom allowed keys, or null to use defaults.</returns>
    protected virtual string[] GetCustomAllowedKeys(DiscoveryJobConfiguration config)
    {
        var props = config?.JobProperties;
        var keys = SplitList(TryGetJobProperty(props, PatternsKeys), ',', ';').AsEnumerable();

        if (UseExtensionsAsAllowedKeys)
            keys = keys.Concat(SplitList(TryGetJobProperty(props, ExtensionsKeys), ',', ';'));

        var result = keys.Distinct(StringComparer.Ordinal).ToArray();
        return result.Length == 0 ? null : result;
    }

    /// <summary>
    /// Merges job-supplied keys with the handler's default keys (job-supplied keys are additive, as documented).
    /// </summary>
    private string[] MergeWithDefaultKeys(string[] customKeys)
    {
        if (customKeys == null || customKeys.Length == 0) return null;
        return customKeys.Concat(Handler?.AllowedKeys ?? Array.Empty<string>())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>
    /// Gets the namespaces to exclude from discovery results (<c>ignoreddirs</c> job property).
    /// </summary>
    /// <param name="config">The discovery job configuration.</param>
    /// <returns>Trimmed, de-duplicated namespace names (empty when none were supplied).</returns>
    protected virtual string[] GetIgnoredNamespaces(DiscoveryJobConfiguration config)
    {
        var raw = TryGetJobProperty(config?.JobProperties, IgnoredDirsKeys);
        var ignored = SplitList(raw, ',', ';').Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        Logger?.LogDebug("Discovery 'Directories to ignore' (ignoreddirs): [{IgnoredDirs}]",
            string.Join(", ", ignored));
        return ignored;
    }

    /// <summary>
    /// Removes discovered locations whose namespace is in <paramref name="ignoredNamespaces"/>
    /// (case-insensitive, whitespace-tolerant). Locations from which no namespace can be extracted
    /// (e.g. a bare cluster name) are always kept.
    /// </summary>
    /// <param name="locations">Locations returned by the handler.</param>
    /// <param name="ignoredNamespaces">Namespaces to exclude.</param>
    /// <param name="dropped">The locations that were removed.</param>
    /// <returns>The remaining locations, in their original order.</returns>
    protected static List<string> FilterIgnoredNamespaces(
        IEnumerable<string> locations, IEnumerable<string> ignoredNamespaces, out List<string> dropped)
    {
        dropped = new List<string>();
        var kept = new List<string>();
        var ignored = new HashSet<string>(
            (ignoredNamespaces ?? Array.Empty<string>()).Select(n => n?.Trim()).Where(n => !string.IsNullOrEmpty(n)),
            StringComparer.OrdinalIgnoreCase);

        foreach (var location in locations ?? Enumerable.Empty<string>())
        {
            var ns = ignored.Count == 0 ? null : ExtractNamespace(location);
            if (ns != null && ignored.Contains(ns))
                dropped.Add(location);
            else
                kept.Add(location);
        }

        return kept;
    }

    /// <summary>
    /// Extracts the namespace from a discovered location. Formats produced by
    /// <c>KubeCertificateManagerClient.DiscoverSecrets</c>:
    /// <list type="bullet">
    /// <item><c>{cluster}/{namespace}/secrets/{secretName}</c> (per-secret path)</item>
    /// <item><c>{cluster}/namespace/{namespace}</c> (namespace-level path)</item>
    /// <item><c>{cluster}</c> (cluster-level; no namespace)</item>
    /// </list>
    /// The cluster name may itself contain <c>/</c> (e.g. an EKS ARN), so segments are read from the end.
    /// </summary>
    /// <param name="location">The discovered location.</param>
    /// <returns>The trimmed namespace, or null if the location carries no namespace.</returns>
    protected static string ExtractNamespace(string location)
    {
        if (string.IsNullOrWhiteSpace(location)) return null;

        var parts = location.Trim().Split('/');
        string ns = null;

        if (parts.Length >= 4 && parts[^2].Equals("secrets", StringComparison.Ordinal))
            ns = parts[^3];
        else if (parts.Length >= 3 && parts[^2].Equals("namespace", StringComparison.Ordinal))
            ns = parts[^1];

        ns = ns?.Trim();
        return string.IsNullOrEmpty(ns) ? null : ns;
    }

    private static string[] SplitList(string value, params char[] separators)
    {
        if (string.IsNullOrWhiteSpace(value)) return Array.Empty<string>();
        return value.Split(separators, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .ToArray();
    }

    /// <summary>
    /// Case-insensitive lookup of a job property, tolerating the value shapes the framework may produce
    /// (string, JValue/JToken, JArray, other enumerables). Returns null when absent or null.
    /// </summary>
    private static string TryGetJobProperty(IDictionary<string, object> props, string[] keys)
    {
        if (props == null) return null;

        foreach (var key in keys)
        foreach (var kvp in props)
            if (string.Equals(kvp.Key, key, StringComparison.OrdinalIgnoreCase))
                return JobPropertyValueToString(kvp.Value);

        return null;
    }

    private static string JobPropertyValueToString(object value)
    {
        switch (value)
        {
            case null:
                return null;
            case string s:
                return s;
            case JValue jv:
                return jv.Type == JTokenType.Null ? null : jv.ToString(CultureInfo.InvariantCulture);
            case JArray ja:
                return string.Join(",", ja.Select(JobPropertyValueToString).Where(v => !string.IsNullOrWhiteSpace(v)));
            case JToken jt:
                return jt.ToString(Formatting.None);
            case IEnumerable<object> items:
                return string.Join(",",
                    items.Select(JobPropertyValueToString).Where(v => !string.IsNullOrWhiteSpace(v)));
            default:
                return Convert.ToString(value, CultureInfo.InvariantCulture);
        }
    }
}
