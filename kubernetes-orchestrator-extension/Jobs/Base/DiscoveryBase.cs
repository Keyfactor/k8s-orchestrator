// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;

/// <summary>
/// Base class for store-type-specific discovery job implementations.
/// Provides shared infrastructure for discovering certificate stores in Kubernetes.
/// </summary>
public abstract class DiscoveryBase : K8SJobBase, IDiscoveryJobExtension
{
    /// <summary>
    /// Creates a new DiscoveryBase with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    protected DiscoveryBase(IPAMSecretResolver resolver) : base(resolver)
    {
    }

    /// <summary>
    /// Main entry point for the discovery job.
    /// Discovers certificate stores in Kubernetes based on the job configuration.
    /// </summary>
    /// <param name="config">Discovery job configuration containing search parameters.</param>
    /// <param name="submitDiscovery">Callback delegate to submit discovered store locations.</param>
    /// <returns>JobResult indicating success or failure of the discovery operation.</returns>
    public JobResult ProcessJob(DiscoveryJobConfiguration config, SubmitDiscoveryUpdate submitDiscovery)
    {
        InitializeInfrastructure();
        Logger.MethodEntry(MsLogLevel.Debug);

        try
        {
            Logger.LogInformation("Begin DISCOVERY for {StoreType} job {JobId}",
                GetStoreType(), config.JobId);

            // Initialize Kubernetes client
            InitializeKubeClient(config.ServerPassword, config.UseSSL);

            // Parse namespaces to search
            var namespaces = ParseNamespaces(config);
            Logger.LogDebug("Searching namespaces: {Namespaces}", string.Join(",", namespaces));

            // Get allowed keys from configuration and merge with defaults
            var allowedKeys = GetAllowedKeys(config);
            Logger.LogDebug("Using allowed keys: {AllowedKeys}", string.Join(",", allowedKeys));

            // Get the secret type filter for this store type
            var secretTypeFilter = GetSecretTypeFilter();
            Logger.LogDebug("Using secret type filter: {Filter}", secretTypeFilter);

            // Discover secrets
            var locations = KubeClient.DiscoverSecrets(
                allowedKeys,
                secretTypeFilter,
                string.Join(",", namespaces));

            Logger.LogInformation("Discovered {Count} store locations", locations.Count);

            // Submit discoveries
            var distinctLocations = locations.Distinct().ToArray();
            submitDiscovery.Invoke(distinctLocations);

            Logger.MethodExit(MsLogLevel.Debug);
            return SuccessJob(config.JobHistoryId,
                $"Discovered the following locations: {string.Join(",\n", distinctLocations)}");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Discovery failed: {Message}", ex.Message);
            Logger.MethodExit(MsLogLevel.Debug);
            return FailJob(ex.Message, config.JobHistoryId);
        }
        finally
        {
            Logger.LogInformation("End DISCOVERY for {StoreType} job {JobId}",
                GetStoreType(), config.JobId);
        }
    }

    /// <summary>
    /// Parses the namespaces to search from the job configuration.
    /// </summary>
    /// <param name="config">The discovery job configuration.</param>
    /// <returns>Array of namespace names to search.</returns>
    protected virtual string[] ParseNamespaces(DiscoveryJobConfiguration config)
    {
        var dirsValue = config.JobProperties?["dirs"]?.ToString();
        var namespaces = dirsValue?.Split(',') ?? Array.Empty<string>();

        if (namespaces == null || namespaces.Length == 0)
        {
            Logger.LogDebug("No namespaces specified, using 'default'");
            namespaces = new[] { "default" };
        }

        return namespaces;
    }

    /// <summary>
    /// Gets the allowed keys to search for, combining configuration with defaults.
    /// Store types can override this to provide their specific allowed keys.
    /// </summary>
    /// <param name="config">The discovery job configuration.</param>
    /// <returns>Array of allowed key names.</returns>
    protected virtual string[] GetAllowedKeys(DiscoveryJobConfiguration config)
    {
        var configuredKeys = config.JobProperties?["patterns"]?.ToString()?.Split(',')
            ?? Array.Empty<string>();

        var defaultKeys = GetDefaultAllowedKeys();

        return configuredKeys.Concat(defaultKeys).Distinct().ToArray();
    }

    /// <summary>
    /// Gets the default allowed keys for this store type.
    /// Store types override this to return their specific keys.
    /// </summary>
    /// <returns>Array of default allowed key names.</returns>
    protected abstract string[] GetDefaultAllowedKeys();

    /// <summary>
    /// Gets the Kubernetes secret type filter for discovery.
    /// Store types override this to return their specific filter (e.g., "kubernetes.io/tls", "Opaque").
    /// </summary>
    /// <returns>The secret type filter string.</returns>
    protected abstract string GetSecretTypeFilter();
}
