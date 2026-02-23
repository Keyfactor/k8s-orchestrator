// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Exceptions;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;

/// <summary>
/// Base class for store-type-specific inventory job implementations.
/// Provides shared infrastructure for processing inventory using the handler pattern.
/// </summary>
public abstract class InventoryBase : K8SJobBase, IInventoryJobExtension
{
    /// <summary>
    /// Service for submitting inventory to Keyfactor Command.
    /// </summary>
    protected InventorySubmitter Submitter;

    /// <summary>
    /// Creates a new InventoryBase with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    protected InventoryBase(IPAMSecretResolver resolver) : base(resolver)
    {
    }

    /// <summary>
    /// Gets whether to use lenient behavior for missing stores.
    /// When true, returns Success with empty inventory for missing stores.
    /// When false, returns Failure for missing stores.
    /// Default is true for TLS/Opaque, override to false for JKS/PKCS12.
    /// </summary>
    protected virtual bool UseLenientBehaviorForMissingStore => true;

    /// <summary>
    /// Main entry point for the inventory job.
    /// Processes the job configuration and returns all certificates found in the store.
    /// </summary>
    /// <param name="config">Inventory job configuration containing store details and credentials.</param>
    /// <param name="submitInventory">Callback delegate to submit discovered certificates.</param>
    /// <returns>JobResult indicating success or failure of the inventory operation.</returns>
    public JobResult ProcessJob(InventoryJobConfiguration config, SubmitInventoryUpdate submitInventory)
    {
        InitializeInfrastructure();
        Logger.MethodEntry(MsLogLevel.Debug);

        try
        {
            Logger.LogInformation("Begin INVENTORY for {StoreType} job {JobId}",
                GetStoreType(), config.JobId);

            // Initialize services
            Submitter ??= new InventorySubmitter(Logger);

            // Parse configuration
            var context = ConfigParser.ParseConfig(config);
            Logger.LogDebug("Parsed config - Namespace: {Namespace}, SecretName: {SecretName}, StoreType: {StoreType}",
                context.Namespace, context.SecretName, context.StoreType);

            // Initialize Kubernetes client
            InitializeKubeClient(config.ServerPassword, config.UseSSL);

            // Initialize handler factory with job properties
            InitializeHandlerFactory(config.CertificateStoreDetails?.Properties);

            // Get the handler and process inventory
            var handler = GetHandler(GetSecretType());
            var result = handler.ProcessInventory(context, KubeClient);

            // Convert handler result to job result
            return ProcessInventoryResult(result, config.JobHistoryId, submitInventory);
        }
        catch (StoreNotFoundException ex)
        {
            Logger.LogWarning("Store not found: {Message}", ex.Message);

            if (UseLenientBehaviorForMissingStore)
            {
                // Return empty inventory with success (lenient behavior for missing stores)
                submitInventory.Invoke(new List<CurrentInventoryItem>());
                return SuccessJob(config.JobHistoryId, $"{ex.Message} - returned empty inventory");
            }

            // Return failure for store types that require existing stores (JKS, PKCS12)
            return FailJob(ex.Message, config.JobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Inventory failed: {Message}", ex.Message);
            return FailJob(ex.Message, config.JobHistoryId);
        }
        finally
        {
            Logger.LogInformation("End INVENTORY for {StoreType} job {JobId}",
                GetStoreType(), config.JobId);
            Logger.MethodExit(MsLogLevel.Debug);
        }
    }

    /// <summary>
    /// Processes the inventory result from the handler and submits it to Keyfactor Command.
    /// </summary>
    /// <param name="result">The inventory result from the handler.</param>
    /// <param name="jobHistoryId">The job history ID.</param>
    /// <param name="submitInventory">Callback to submit inventory.</param>
    /// <returns>JobResult indicating success or failure.</returns>
    protected virtual JobResult ProcessInventoryResult(
        InventoryResult result,
        long jobHistoryId,
        SubmitInventoryUpdate submitInventory)
    {
        if (!result.Success)
        {
            return FailJob(result.ErrorMessage, jobHistoryId);
        }

        List<CurrentInventoryItem> inventoryItems;

        switch (result.ResultType)
        {
            case InventoryResultType.CertificateList:
                var (items, error) = Submitter.BuildInventoryFromPemList(
                    result.Certificates, result.HasPrivateKey);
                if (error != null)
                {
                    return FailJob(error, jobHistoryId);
                }
                inventoryItems = items ?? new List<CurrentInventoryItem>();
                break;

            case InventoryResultType.CertificateChains:
                inventoryItems = Submitter.BuildInventoryFromChainDictionary(
                    result.CertificateChains, result.HasPrivateKey);
                break;

            case InventoryResultType.CertificatesByPath:
                inventoryItems = Submitter.BuildInventoryFromDictionary(
                    result.CertificatesByPath, result.HasPrivateKey);
                break;

            default:
                inventoryItems = new List<CurrentInventoryItem>();
                break;
        }

        Logger.LogDebug("Submitting {Count} inventory items", inventoryItems.Count);

        var jobMessage = string.IsNullOrEmpty(result.WarningMessage) ? null : result.WarningMessage;
        return Submitter.SubmitInventory(inventoryItems, jobHistoryId, submitInventory, jobMessage);
    }
}
