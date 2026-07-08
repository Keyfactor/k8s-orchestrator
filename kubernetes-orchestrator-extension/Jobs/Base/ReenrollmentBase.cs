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
/// Base class for store-type-specific reenrollment jobs.
/// Reenrollment generates a new key pair and CSR for an existing certificate entry.
/// Currently not implemented for Kubernetes stores - subclasses can override to add support.
/// </summary>
public abstract class ReenrollmentBase : K8SJobBase, IReenrollmentJobExtension
{
    /// <summary>
    /// Initializes a new instance with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    protected ReenrollmentBase(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    /// <summary>
    /// Processes the reenrollment job.
    /// Default implementation returns "not implemented" - override in store types that support reenrollment.
    /// </summary>
    /// <param name="config">The reenrollment job configuration.</param>
    /// <param name="submitReenrollment">Callback to submit the CSR.</param>
    /// <returns>The job result indicating success or failure.</returns>
    public virtual JobResult ProcessJob(ReenrollmentJobConfiguration config, SubmitReenrollmentCSR submitReenrollment)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(LogLevel.Debug);

        try
        {
            Logger.LogDebug("Processing reenrollment job {JobId} for capability {Capability}",
                config.JobId, config.Capability);

            // Reenrollment is not implemented for most Kubernetes store types
            // Subclasses can override PerformReenrollment to provide implementation
            return PerformReenrollment(config, submitReenrollment);
        }
        catch (NotSupportedException ex)
        {
            Logger.LogWarning("Reenrollment not supported: {Message}", ex.Message);
            return FailJob(ex.Message, config.JobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Reenrollment failed: {Message}", ex.Message);
            return FailJob(ex, config.JobHistoryId);
        }
        finally
        {
            Logger.MethodExit(LogLevel.Debug);
        }
    }

    /// <summary>
    /// Performs the actual reenrollment operation.
    /// Override in store types that support reenrollment (JKS, PKCS12).
    /// Default implementation returns "not implemented".
    /// </summary>
    /// <param name="config">The reenrollment job configuration.</param>
    /// <param name="submitReenrollment">Callback to submit the CSR.</param>
    /// <returns>The job result.</returns>
    protected virtual JobResult PerformReenrollment(ReenrollmentJobConfiguration config, SubmitReenrollmentCSR submitReenrollment)
    {
        Logger.LogWarning("Re-enrollment not implemented for {Capability}", config.Capability);
        return FailJob($"Re-enrollment not implemented for {config.Capability}", config.JobHistoryId);
    }
}
