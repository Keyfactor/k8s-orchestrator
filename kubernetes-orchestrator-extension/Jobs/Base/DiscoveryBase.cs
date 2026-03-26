// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

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

            Logger.LogDebug("Initializing handler for discovery");
            InitializeHandler(config);

            if (Handler == null)
            {
                return FailJob($"No handler available for store type: {KubeSecretType}", config.JobHistoryId);
            }

            Logger.LogInformation("Begin DISCOVERY for {StoreType} job {JobId}", KubeSecretType, config.JobId);

            // Get namespaces to search from job properties
            var namespacesCsv = GetNamespacesToSearch(config);

            // Get custom allowed keys from job properties
            var customKeys = GetCustomAllowedKeys(config);

            // Discover stores via handler
            var discoveredStores = Handler.DiscoverStores(customKeys, namespacesCsv);

            Logger.LogInformation("Discovered {Count} stores", discoveredStores.Count);

            // Submit discovered stores
            submitDiscovery.Invoke(discoveredStores);

            return SuccessJob(config.JobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Discovery failed: {Message}", ex.Message);
            return FailJob(ex, config.JobHistoryId);
        }
        finally
        {
            Logger.LogInformation("End DISCOVERY for job {JobId}", config.JobId);
            Logger.MethodExit(LogLevel.Debug);
        }
    }

    /// <summary>
    /// Gets the namespaces to search from the job configuration.
    /// </summary>
    /// <param name="config">The discovery job configuration.</param>
    /// <returns>Comma-separated list of namespaces, or empty for all.</returns>
    protected virtual string GetNamespacesToSearch(DiscoveryJobConfiguration config)
    {
        if (config.JobProperties == null)
            return "";

        try
        {
            var props = JsonConvert.DeserializeObject<Dictionary<string, object>>(config.JobProperties.ToString());
            if (props != null && props.TryGetValue("Directories", out var dirs))
            {
                return dirs?.ToString() ?? "";
            }
        }
        catch (Exception ex)
        {
            Logger.LogWarning("Failed to parse discovery directories: {Message}", ex.Message);
        }

        return "";
    }

    /// <summary>
    /// Gets custom allowed keys from the job configuration.
    /// </summary>
    /// <param name="config">The discovery job configuration.</param>
    /// <returns>Array of custom allowed keys, or null to use defaults.</returns>
    protected virtual string[] GetCustomAllowedKeys(DiscoveryJobConfiguration config)
    {
        if (config.JobProperties == null)
            return null;

        try
        {
            var props = JsonConvert.DeserializeObject<Dictionary<string, object>>(config.JobProperties.ToString());
            if (props != null && props.TryGetValue("Extensions", out var extensions))
            {
                var extString = extensions?.ToString();
                if (!string.IsNullOrEmpty(extString))
                {
                    return extString.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(s => s.Trim())
                        .ToArray();
                }
            }
        }
        catch (Exception ex)
        {
            Logger.LogWarning("Failed to parse discovery extensions: {Message}", ex.Message);
        }

        return null;
    }
}
