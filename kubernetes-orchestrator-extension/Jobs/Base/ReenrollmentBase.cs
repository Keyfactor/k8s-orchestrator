// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;

/// <summary>
/// Base class for store-type-specific reenrollment job implementations.
/// Reenrollment is currently not implemented for Kubernetes stores.
/// </summary>
/// <remarks>
/// Future implementation should:
/// 1. Generate keypair using BouncyCastle
/// 2. Create CSR with appropriate subject and extensions
/// 3. Submit CSR via submitReenrollment callback
/// 4. Receive enrolled certificate and deploy to store
/// </remarks>
public abstract class ReenrollmentBase : K8SJobBase, IReenrollmentJobExtension
{
    /// <summary>
    /// Creates a new ReenrollmentBase with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    protected ReenrollmentBase(IPAMSecretResolver resolver) : base(resolver)
    {
    }

    /// <summary>
    /// Main entry point for the reenrollment job.
    /// Currently not implemented - returns a failure result.
    /// </summary>
    /// <param name="config">Reenrollment job configuration.</param>
    /// <param name="submitReenrollment">Callback delegate to submit CSR for enrollment.</param>
    /// <returns>JobResult indicating failure (not implemented).</returns>
    public JobResult ProcessJob(ReenrollmentJobConfiguration config, SubmitReenrollmentCSR submitReenrollment)
    {
        InitializeInfrastructure();
        Logger.MethodEntry(MsLogLevel.Debug);

        Logger.LogDebug("Processing reenrollment job {JobId} for {StoreType}",
            config.JobId, GetStoreType());

        Logger.LogTrace("Server: {Server}", config.CertificateStoreDetails.ClientMachine);
        Logger.LogTrace("Store Path: {StorePath}", config.CertificateStoreDetails.StorePath);

        // Check if reenrollment is supported for this store type
        if (!SupportsReenrollment())
        {
            Logger.LogWarning("Re-enrollment not implemented for {StoreType}", GetStoreType());
            Logger.MethodExit(MsLogLevel.Debug);
            return FailJob($"Re-enrollment not implemented for {GetStoreType()}", config.JobHistoryId);
        }

        // Future: Implement reenrollment logic here
        Logger.MethodExit(MsLogLevel.Debug);
        return FailJob($"Re-enrollment not yet implemented for {GetStoreType()}", config.JobHistoryId);
    }

    /// <summary>
    /// Indicates whether this store type supports reenrollment.
    /// Store types can override this to enable reenrollment when implemented.
    /// </summary>
    /// <returns>True if reenrollment is supported; otherwise, false.</returns>
    protected virtual bool SupportsReenrollment()
    {
        return false;
    }
}
