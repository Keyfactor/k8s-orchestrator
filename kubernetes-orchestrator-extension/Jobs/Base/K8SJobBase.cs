// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;

/// <summary>
/// Simplified base class for store-type-specific jobs.
/// Provides common infrastructure for Kubernetes client access, handler creation, and job results.
/// Store-type-specific jobs inherit from this to get shared functionality while implementing
/// their own ProcessJob methods.
/// </summary>
public abstract class K8SJobBase : JobBase
{
    /// <summary>
    /// Gets or sets the secret handler for the current store type.
    /// Lazily initialized based on the store configuration.
    /// </summary>
    protected ISecretHandler Handler { get; set; }

    /// <summary>
    /// Creates the operation context from the current job configuration.
    /// Override in subclasses to provide store-type-specific context.
    /// </summary>
    /// <returns>The operation context for the handler.</returns>
    protected virtual ISecretOperationContext CreateOperationContext()
    {
        return new SecretOperationContext
        {
            KubeNamespace = KubeNamespace,
            KubeSecretName = KubeSecretName,
            KubeSecretType = KubeSecretType,
            StorePath = StorePath,
            StorePassword = StorePassword,
            CertificateDataFieldName = CertificateDataFieldName,
            PasswordFieldName = PasswordFieldName,
            PasswordSecretPath = StorePasswordPath,
            SeparateChain = SeparateChain,
            IncludeCertChain = IncludeCertChain
        };
    }

    /// <summary>
    /// Initializes the handler for inventory operations.
    /// Call this after InitializeStore() in ProcessJob.
    /// </summary>
    /// <param name="config">The inventory job configuration.</param>
    protected void InitializeHandler(InventoryJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.LogDebug("Creating handler for store type: {StoreType}", KubeSecretType);

        var context = CreateOperationContext();
        Handler = SecretHandlerFactory.Create(KubeSecretType, KubeClient, Logger, context);

        Logger.LogDebug("Handler created: {HandlerType}", Handler?.GetType().Name ?? "null");
    }

    /// <summary>
    /// Initializes the handler for management operations.
    /// Call this after InitializeStore() in ProcessJob.
    /// </summary>
    /// <param name="config">The management job configuration.</param>
    protected void InitializeHandler(ManagementJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.LogDebug("Creating handler for store type: {StoreType}", KubeSecretType);

        var context = CreateOperationContext();
        Handler = SecretHandlerFactory.Create(KubeSecretType, KubeClient, Logger, context);

        Logger.LogDebug("Handler created: {HandlerType}", Handler?.GetType().Name ?? "null");
    }

    /// <summary>
    /// Initializes the handler for discovery operations.
    /// Call this after InitializeStore() in ProcessJob.
    /// </summary>
    /// <param name="config">The discovery job configuration.</param>
    protected void InitializeHandler(DiscoveryJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.LogDebug("Creating handler for discovery");

        // For discovery, we may not have full store context yet
        var context = new SecretOperationContext
        {
            KubeNamespace = KubeNamespace ?? "",
            KubeSecretName = KubeSecretName ?? "",
            KubeSecretType = KubeSecretType ?? "secret"
        };

        Handler = SecretHandlerFactory.Create(KubeSecretType ?? "secret", KubeClient, Logger, context);

        Logger.LogDebug("Handler created: {HandlerType}", Handler?.GetType().Name ?? "null");
    }

    /// <summary>
    /// Creates a success job result.
    /// </summary>
    /// <param name="jobHistoryId">The job history ID.</param>
    /// <returns>A successful JobResult.</returns>
    protected JobResult SuccessJob(long jobHistoryId)
    {
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Success,
            JobHistoryId = jobHistoryId
        };
    }

    /// <summary>
    /// Creates a success job result with a warning message.
    /// </summary>
    /// <param name="message">The warning message.</param>
    /// <param name="jobHistoryId">The job history ID.</param>
    /// <returns>A warning JobResult.</returns>
    protected JobResult WarningJob(string message, long jobHistoryId)
    {
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Warning,
            JobHistoryId = jobHistoryId,
            FailureMessage = message
        };
    }

    /// <summary>
    /// Creates a failure job result.
    /// </summary>
    /// <param name="message">The failure message.</param>
    /// <param name="jobHistoryId">The job history ID.</param>
    /// <returns>A failed JobResult.</returns>
    protected new JobResult FailJob(string message, long jobHistoryId)
    {
        Logger?.LogError("Job failed: {Message}", message);
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Failure,
            JobHistoryId = jobHistoryId,
            FailureMessage = message
        };
    }

    /// <summary>
    /// Creates a failure job result from an exception.
    /// </summary>
    /// <param name="ex">The exception that caused the failure.</param>
    /// <param name="jobHistoryId">The job history ID.</param>
    /// <returns>A failed JobResult.</returns>
    protected JobResult FailJob(Exception ex, long jobHistoryId)
    {
        Logger?.LogError(ex, "Job failed with exception: {Message}", ex.Message);
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Failure,
            JobHistoryId = jobHistoryId,
            FailureMessage = ex.Message
        };
    }
}

/// <summary>
/// Simple implementation of ISecretOperationContext for handler initialization.
/// </summary>
internal class SecretOperationContext : ISecretOperationContext
{
    public string KubeNamespace { get; set; } = "";
    public string KubeSecretName { get; set; } = "";
    public string KubeSecretType { get; set; } = "";
    public string StorePath { get; set; } = "";
    public string StorePassword { get; set; }
    public string CertificateDataFieldName { get; set; }
    public string PasswordFieldName { get; set; }
    public string PasswordSecretPath { get; set; }
    public bool SeparateChain { get; set; }
    public bool IncludeCertChain { get; set; } = true;
}
