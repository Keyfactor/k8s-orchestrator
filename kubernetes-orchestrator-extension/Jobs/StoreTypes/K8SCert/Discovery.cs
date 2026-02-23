// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Constants;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SCert;

/// <summary>
/// Discovery job for Kubernetes Certificate Signing Requests (CSRs).
/// Discovers signed CSRs in the Kubernetes cluster.
/// </summary>
public class Discovery : DiscoveryBase
{
    /// <summary>
    /// Creates a new CSR discovery job with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    public Discovery(IPAMSecretResolver resolver) : base(resolver)
    {
    }

    /// <inheritdoc />
    protected override SecretType GetSecretType() => SecretType.Certificate;

    /// <inheritdoc />
    protected override StoreType GetStoreType() => StoreType.K8SCert;

    /// <inheritdoc />
    protected override string[] GetDefaultAllowedKeys() => AllowedKeys.CertKeys;

    /// <inheritdoc />
    protected override string GetSecretTypeFilter() => "certificate";

    /// <summary>
    /// Discovers signed Certificate Signing Requests (CSRs) in the Kubernetes cluster.
    /// </summary>
    public new JobResult ProcessJob(DiscoveryJobConfiguration config, SubmitDiscoveryUpdate submitDiscovery)
    {
        InitializeInfrastructure();
        Logger.MethodEntry(MsLogLevel.Debug);

        try
        {
            Logger.LogInformation("Begin CSR DISCOVERY for job {JobId}", config.JobId);

            // Initialize Kubernetes client
            InitializeKubeClient(config.ServerPassword, config.UseSSL);

            // Discover CSRs
            var locations = KubeClient.DiscoverCertificates();
            Logger.LogInformation("Discovered {Count} CSR locations", locations.Count);

            // Submit discoveries
            var distinctLocations = locations.Distinct().ToArray();
            submitDiscovery.Invoke(distinctLocations);

            Logger.MethodExit(MsLogLevel.Debug);
            return SuccessJob(config.JobHistoryId,
                $"Discovered the following CSR locations: {string.Join(", ", distinctLocations)}");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "CSR Discovery failed: {Message}", ex.Message);
            Logger.MethodExit(MsLogLevel.Debug);
            return FailJob(ex.Message, config.JobHistoryId);
        }
    }
}
