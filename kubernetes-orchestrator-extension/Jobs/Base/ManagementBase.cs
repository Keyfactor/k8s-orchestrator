// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;

/// <summary>
/// Base class for store-type-specific management jobs (Add/Remove certificates).
/// Handles common management workflow: initialize, validate, delegate to handler.
/// Store-type-specific classes inherit from this and may override methods as needed.
/// </summary>
public abstract class ManagementBase : K8SJobBase, IManagementJobExtension
{
    /// <summary>
    /// Initializes a new instance with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    protected ManagementBase(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    /// <summary>
    /// Processes the management job by delegating to the appropriate handler.
    /// </summary>
    /// <param name="config">The management job configuration.</param>
    /// <returns>The job result indicating success or failure.</returns>
    public virtual JobResult ProcessJob(ManagementJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(LogLevel.Debug);

        try
        {
            Logger.LogDebug("Initializing store for management job {JobId}", config.JobId);
            InitializeStore(config);

            Logger.LogInformation(
                "AUDIT store_access: JobType={JobType} Capability={Capability} StorePath={StorePath} " +
                "Namespace={Namespace} SecretName={SecretName} JobHistoryId={JobHistoryId} Outcome=STARTED",
                GetType().Name, Capability, StorePath, KubeNamespace, KubeSecretName, config.JobHistoryId);

            // Ensure StorePassword is set from config (Management jobs need this for keystore types)
            if (!string.IsNullOrEmpty(config.CertificateStoreDetails?.StorePassword))
            {
                StorePassword = config.CertificateStoreDetails.StorePassword;
            }

            Logger.LogDebug("Initializing handler for store type: {StoreType}", KubeSecretType);
            InitializeHandler(config);

            if (Handler == null)
            {
                Logger.LogInformation(
                    "AUDIT store_access: JobType={JobType} Capability={Capability} StorePath={StorePath} " +
                    "Namespace={Namespace} SecretName={SecretName} JobHistoryId={JobHistoryId} Outcome=FAILED",
                    GetType().Name, Capability, StorePath, KubeNamespace, KubeSecretName, config.JobHistoryId);
                return FailJob($"No handler available for store type: {KubeSecretType}", config.JobHistoryId);
            }

            if (!Handler.SupportsManagement)
            {
                Logger.LogInformation(
                    "AUDIT store_access: JobType={JobType} Capability={Capability} StorePath={StorePath} " +
                    "Namespace={Namespace} SecretName={SecretName} JobHistoryId={JobHistoryId} Outcome=FAILED",
                    GetType().Name, Capability, StorePath, KubeNamespace, KubeSecretName, config.JobHistoryId);
                return FailJob($"Management operations are not supported for store type: {KubeSecretType}", config.JobHistoryId);
            }

            Logger.LogInformation("Begin MANAGEMENT ({OperationType}) for {StoreType} job {JobId}",
                config.OperationType, KubeSecretType, config.JobId);

            // Route to appropriate operation
            var result = RouteOperation(config);
            Logger.LogInformation(
                "AUDIT store_access: JobType={JobType} Capability={Capability} StorePath={StorePath} " +
                "Namespace={Namespace} SecretName={SecretName} JobHistoryId={JobHistoryId} Outcome=COMPLETED",
                GetType().Name, Capability, StorePath, KubeNamespace, KubeSecretName, config.JobHistoryId);
            return result;
        }
        catch (StoreNotFoundException ex)
        {
            Logger.LogError("Store not found: {Message}", ex.Message);
            Logger.LogInformation(
                "AUDIT store_access: JobType={JobType} Capability={Capability} StorePath={StorePath} " +
                "Namespace={Namespace} SecretName={SecretName} JobHistoryId={JobHistoryId} Outcome=FAILED",
                GetType().Name, Capability, StorePath, KubeNamespace, KubeSecretName, config.JobHistoryId);
            return FailJob($"Store not found: {ex.Message}", config.JobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Management job failed: {Message}", ex.Message);
            Logger.LogInformation(
                "AUDIT store_access: JobType={JobType} Capability={Capability} StorePath={StorePath} " +
                "Namespace={Namespace} SecretName={SecretName} JobHistoryId={JobHistoryId} Outcome=FAILED",
                GetType().Name, Capability, StorePath, KubeNamespace, KubeSecretName, config.JobHistoryId);
            return FailJob(ex, config.JobHistoryId);
        }
        finally
        {
            Logger.LogInformation("End MANAGEMENT for job {JobId}", config.JobId);
            Logger.MethodExit(LogLevel.Debug);
        }
    }

    /// <summary>
    /// Routes the management job to the appropriate handler method based on OperationType.
    /// <c>Create</c> is treated identically to <c>Add</c> — both add a certificate to the store.
    /// Extracted as an internal method to allow direct unit testing without K8S infrastructure.
    /// </summary>
    internal JobResult RouteOperation(ManagementJobConfiguration config)
    {
        return config.OperationType switch
        {
            CertStoreOperationType.Add or CertStoreOperationType.Create => HandleAdd(config),
            CertStoreOperationType.Remove => HandleRemove(config),
            _ => FailJob($"Unknown operation type: {config.OperationType}", config.JobHistoryId)
        };
    }

    /// <summary>
    /// Handles the Add operation by delegating to the handler.
    /// Override in subclasses to customize add logic.
    /// </summary>
    /// <param name="config">The management job configuration.</param>
    /// <returns>The job result.</returns>
    protected virtual JobResult HandleAdd(ManagementJobConfiguration config)
    {
        Logger.LogDebug("Processing Add operation");

        // Initialize certificate from job configuration (parses PKCS12, extracts keys, etc.)
        K8SCertificate = InitJobCertificate(config);
        var alias = config.JobCertificate?.Alias ?? "";
        var overwrite = config.Overwrite;

        Logger.LogDebug("Adding certificate with alias: {Alias}, overwrite: {Overwrite}", alias, overwrite);

        Handler.HandleAdd(K8SCertificate, alias, overwrite);
        Logger.LogInformation("Successfully added certificate to {SecretName}", KubeSecretName);
        return SuccessJob(config.JobHistoryId);
    }

    /// <summary>
    /// Handles the Remove operation by delegating to the handler.
    /// Override in subclasses to customize remove logic.
    /// </summary>
    /// <param name="config">The management job configuration.</param>
    /// <returns>The job result.</returns>
    protected virtual JobResult HandleRemove(ManagementJobConfiguration config)
    {
        Logger.LogDebug("Processing Remove operation");

        var alias = config.JobCertificate?.Alias ?? "";

        Logger.LogDebug("Removing certificate with alias: {Alias}", alias);

        try
        {
            Handler.HandleRemove(alias);
            Logger.LogInformation("Successfully removed certificate from {SecretName}", KubeSecretName);
            return SuccessJob(config.JobHistoryId);
        }
        catch (StoreNotFoundException)
        {
            // Store doesn't exist - nothing to remove
            Logger.LogWarning("Store not found, nothing to remove");
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Warning,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = $"Store '{KubeNamespace}/{KubeSecretName}' was not found; no removal action was taken."
            };
        }
    }
}
