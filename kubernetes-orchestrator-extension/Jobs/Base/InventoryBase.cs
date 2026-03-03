// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;

/// <summary>
/// Base class for store-type-specific inventory jobs.
/// Handles common inventory workflow: initialize, get certificates via handler, submit to Keyfactor.
/// Store-type-specific classes inherit from this and may override methods as needed.
/// </summary>
public abstract class InventoryBase : K8SJobBase, IInventoryJobExtension
{
    /// <summary>
    /// Initializes a new instance with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    protected InventoryBase(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    /// <summary>
    /// Processes the inventory job by delegating to the appropriate handler.
    /// </summary>
    /// <param name="config">The inventory job configuration.</param>
    /// <param name="submitInventory">Callback to submit inventory to Keyfactor.</param>
    /// <returns>The job result indicating success or failure.</returns>
    public virtual JobResult ProcessJob(InventoryJobConfiguration config, SubmitInventoryUpdate submitInventory)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(LogLevel.Debug);

        try
        {
            Logger.LogDebug("Initializing store for inventory job {JobId}", config.JobId);
            InitializeStore(config);

            Logger.LogDebug("Initializing handler for store type: {StoreType}", KubeSecretType);
            InitializeHandler(config);

            if (Handler == null)
            {
                return FailJob($"No handler available for store type: {KubeSecretType}", config.JobHistoryId);
            }

            Logger.LogInformation("Begin INVENTORY for {StoreType} job {JobId}", KubeSecretType, config.JobId);

            // Get inventory entries from handler
            // JobHistoryId is the long identifier used by Keyfactor
            var entries = GetInventoryEntries(config.JobHistoryId);

            // Submit to Keyfactor
            return SubmitInventory(config.JobHistoryId, submitInventory, entries);
        }
        catch (StoreNotFoundException ex)
        {
            Logger.LogWarning("Store not found: {Message}", ex.Message);
            // Return empty inventory for not found stores (common during initial setup)
            submitInventory.Invoke(new List<CurrentInventoryItem>());
            return SuccessJob(config.JobHistoryId, $"Store not found: {ex.Message}");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Inventory failed: {Message}", ex.Message);
            return FailJob(ex, config.JobHistoryId);
        }
        finally
        {
            Logger.LogInformation("End INVENTORY for job {JobId}", config.JobId);
            Logger.MethodExit(LogLevel.Debug);
        }
    }

    /// <summary>
    /// Gets inventory entries from the handler.
    /// Override in subclasses to customize inventory retrieval logic.
    /// </summary>
    /// <param name="jobId">The job ID for logging.</param>
    /// <returns>List of inventory entries.</returns>
    protected virtual List<InventoryEntry> GetInventoryEntries(long jobId)
    {
        Logger.LogDebug("Getting inventory entries via handler");
        return Handler.GetInventoryEntries(jobId);
    }

    /// <summary>
    /// Submits inventory entries to Keyfactor.
    /// </summary>
    /// <param name="jobHistoryId">The job history ID.</param>
    /// <param name="submitInventory">The submission callback.</param>
    /// <param name="entries">The inventory entries to submit.</param>
    /// <returns>The job result.</returns>
    protected virtual JobResult SubmitInventory(
        long jobHistoryId,
        SubmitInventoryUpdate submitInventory,
        List<InventoryEntry> entries)
    {
        Logger.LogDebug("Submitting {Count} inventory entries to Keyfactor", entries.Count);

        var inventoryItems = entries
            .Where(e => e.Certificates != null && e.Certificates.Count > 0)
            .Select(e => new CurrentInventoryItem
            {
                Alias = e.Alias,
                Certificates = e.Certificates,
                PrivateKeyEntry = e.HasPrivateKey,
                UseChainLevel = e.Certificates.Count > 1
            })
            .ToList();

        Logger.LogInformation("Submitting {Count} certificates to Keyfactor", inventoryItems.Count);

        try
        {
            submitInventory.Invoke(inventoryItems);
            Logger.LogInformation("Successfully submitted inventory");
            return SuccessJob(jobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Failed to submit inventory: {Message}", ex.Message);
            return FailJob($"Failed to submit inventory: {ex.Message}", jobHistoryId);
        }
    }

    /// <summary>
    /// Determines if this inventory job has a private key.
    /// Delegates to the handler.
    /// </summary>
    /// <returns>True if the store has a private key.</returns>
    protected bool HasPrivateKey()
    {
        return Handler?.HasPrivateKey() ?? false;
    }
}
