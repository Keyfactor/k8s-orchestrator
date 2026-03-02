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

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

/// <summary>
/// Discovery job implementation for Kubernetes certificate stores.
/// Finds all certificate stores (secrets, JKS, PKCS12) in specified namespaces
/// based on job configuration and returns them to Keyfactor Command for approval.
/// </summary>
/// <remarks>
/// Supports discovery for the following store types:
/// - K8SCluster: Cluster-wide secret discovery
/// - K8SNS: Namespace-level secret discovery
/// - K8STLSSecr: TLS secrets (kubernetes.io/tls)
/// - K8SSecret: Opaque secrets
/// - K8SPKCS12/K8SPFX: PKCS12 keystores
/// - K8SJKS: JKS keystores
///
/// Discovery parameters from job properties:
/// - dirs: Namespaces to search (comma-separated)
/// - extensions: Secret data keys to check
/// - ignoreddirs: Namespaces to ignore
/// - patterns: File name patterns to match
/// </remarks>
public class Discovery : JobBase, IDiscoveryJobExtension
{
    /// <summary>
    /// Initializes a new instance of the Discovery job with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    public Discovery(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    /// <summary>
    /// Executes discovery for a specific secret type with the given parameters.
    /// </summary>
    private List<string> DiscoverSecretsForType(
        string secretType,
        string[] baseAllowedKeys,
        string[] additionalAllowedKeys,
        string namespacesCsv)
    {
        var combinedKeys = baseAllowedKeys.Concat(additionalAllowedKeys).Distinct().ToArray();
        Logger.LogInformation("Discovering secrets with allowed keys: {AllowedKeys} and type: {SecretType}",
            string.Join(",", combinedKeys), secretType);
        return KubeClient.DiscoverSecrets(combinedKeys, secretType, namespacesCsv);
    }

    /// <summary>
    /// Builds the allowed keys array for keystore discovery (JKS/PKCS12).
    /// </summary>
    private string[] BuildKeystoreAllowedKeys(
        DiscoveryJobConfiguration config,
        string[] defaultKeys,
        string[] keystoreKeys)
    {
        var extensionsStr = config.JobProperties["extensions"].ToString();
        var patternsStr = config.JobProperties["patterns"].ToString();

        var patterns = string.IsNullOrEmpty(patternsStr)
            ? defaultKeys
            : patternsStr.Split(',');

        var extensions = string.IsNullOrEmpty(extensionsStr)
            ? defaultKeys
            : extensionsStr.Split(',');

        return extensions
            .Concat(patterns)
            .Concat(keystoreKeys)
            .Distinct()
            .ToArray();
    }

    /// <summary>
    /// Main entry point for the discovery job. Searches for certificate stores
    /// in Kubernetes based on the job configuration.
    /// </summary>
    /// <param name="config">Discovery job configuration containing search parameters.</param>
    /// <param name="submitDiscovery">Callback delegate to submit discovered store locations to Keyfactor Command.</param>
    /// <returns>JobResult indicating success or failure of the discovery operation.</returns>
    /// <remarks>
    /// Configuration parameters available in config:
    /// - config.ServerUsername, config.ServerPassword - credentials for K8S API authentication
    /// - config.JobProperties["dirs"] - Namespaces to search (comma-separated, defaults to "default")
    /// - config.JobProperties["extensions"] - Secret data keys to check for certificate data
    /// - config.JobProperties["ignoreddirs"] - Namespaces to ignore
    /// - config.JobProperties["patterns"] - File name patterns to match
    /// </remarks>
    public JobResult ProcessJob(DiscoveryJobConfiguration config, SubmitDiscoveryUpdate submitDiscovery)
    {
        Logger = LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogInformation("Begin Discovery for K8S Orchestrator Extension for job {JobID}", config.JobId);
        Logger.LogInformation("Discovery for store type: {Capability}", config.Capability);
        try
        {
            Logger.LogDebug("Calling InitializeStore()");
            InitializeStore(config);
            Logger.LogDebug("Store initialized successfully");
        }
        catch (Exception ex)
        {
            Logger.LogError("Failed to initialize store: {Error}", ex.Message);
            return FailJob("Failed to initialize store: " + ex.Message, config.JobHistoryId);
        }


        var locations = new List<string>();

        KubeSvcCreds = ServerPassword;
        Logger.LogDebug("Calling KubeCertificateManagerClient()");
        KubeClient = new KubeCertificateManagerClient(KubeSvcCreds, config.UseSSL); //todo does this throw an exception?
        Logger.LogDebug("Returned from KubeCertificateManagerClient()");
        if (KubeClient == null)
        {
            Logger.LogError("Failed to create KubeCertificateManagerClient");
            return FailJob("Failed to create KubeCertificateManagerClient", config.JobHistoryId);
        }

        var namespaces = config.JobProperties["dirs"].ToString()?.Split(',') ?? Array.Empty<string>();
        if (namespaces is null or { Length: 0 })
        {
            Logger.LogDebug("No namespaces provided, using `default` namespace");
            namespaces = new[] { "default" };
        }

        Logger.LogDebug("Namespaces: {Namespaces}", string.Join(",", namespaces));

        var ignoreNamespace = config.JobProperties["ignoreddirs"].ToString()?.Split(',') ?? Array.Empty<string>();
        Logger.LogDebug("Ignored Namespaces: {Namespaces}", string.Join(",", ignoreNamespace));

        var secretAllowedKeys = config.JobProperties["patterns"].ToString()?.Split(',') ?? Array.Empty<string>();
        Logger.LogDebug("Secret Allowed Keys: {AllowedKeys}", string.Join(",", secretAllowedKeys));

        Logger.LogTrace("Discovery entering switch block based on capability {Capability}", config.Capability);
        try
        {
            //Code logic to:
            // 1) Connect to the orchestrated server if necessary (config.CertificateStoreDetails.ClientMachine)
            // 2) Custom logic to search for valid certificate stores based on passed in:
            //      a) Directories to search
            //      b) Extensions
            //      c) Directories to ignore
            //      d) File name patterns to match
            // 3) Place found and validated store locations (path and file name) in "locations" collection instantiated above
            var namespacesCsv = string.Join(",", namespaces);
            switch (config.Capability)
            {
                case "CertStores.K8SCluster.Discovery":
                    locations = DiscoverSecretsForType("cluster", secretAllowedKeys, TLSAllowedKeys, namespacesCsv);
                    break;
                case "CertStores.K8SNS.Discovery":
                    locations = DiscoverSecretsForType("namespace", secretAllowedKeys, TLSAllowedKeys, namespacesCsv);
                    break;
                case "CertStores.K8STLSSecr.Discovery":
                    locations = DiscoverSecretsForType("kubernetes.io/tls", secretAllowedKeys, TLSAllowedKeys, namespacesCsv);
                    break;
                case "CertStores.K8SSecret.Discovery":
                    locations = DiscoverSecretsForType("Opaque", secretAllowedKeys, OpaqueAllowedKeys, namespacesCsv);
                    break;
                case "CertStores.K8SPFX.Discovery":
                case "CertStores.K8SPKCS12.Discovery":
                    var pkcs12Keys = BuildKeystoreAllowedKeys(config, new[] { "p12" }, Pkcs12AllowedKeys);
                    locations = DiscoverSecretsForType("pkcs12", pkcs12Keys, Array.Empty<string>(), namespacesCsv);
                    break;
                case "CertStores.K8SJKS.Discovery":
                    var jksKeys = BuildKeystoreAllowedKeys(config, new[] { "jks" }, JksAllowedKeys);
                    locations = DiscoverSecretsForType("jks", jksKeys, Array.Empty<string>(), namespacesCsv);
                    break;
                case "CertStores.K8SCert.Discovery":
                    Logger.LogError("Capability not supported: CertStores.K8SCert.Discovery");
                    return FailJob("Discovery not supported for store type `K8SCert`", config.JobHistoryId);
            }
        }
        catch (Exception ex)
        {
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogError("Discovery job has failed due to an unknown error");
            Logger.LogError("{Message}", ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            // iterate through the inner exceptions
            var inner = ex.InnerException;
            while (inner != null)
            {
                Logger.LogError("Inner Exception: {Message}", inner.Message);
                Logger.LogTrace("{Message}", inner.ToString());
                inner = inner.InnerException;
            }

            Logger.LogInformation("End DISCOVERY for K8S Orchestrator Extension for job '{JobID}' with failure",
                config.JobId);
            return FailJob(ex.Message, config.JobHistoryId);
        }

        try
        {
            //Sends store locations back to KF command where they can be approved or rejected
            Logger.LogInformation("Submitting discovered locations to Keyfactor Command...");
            Logger.LogTrace("Discovery locations: {Locations}", string.Join(",", locations));
            Logger.LogDebug("Calling submitDiscovery.Invoke()");
            submitDiscovery.Invoke(locations.Distinct().ToArray());
            Logger.LogDebug("Returned from submitDiscovery.Invoke()");
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogInformation("Discovery job {JobId} completed successfully with {Count} locations", config.JobId, locations.Count);
            Logger.MethodExit(MsLogLevel.Debug);
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Success,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = "Discovered the following locations: " + string.Join(",\n", locations)
            };
        }
        catch (Exception ex)
        {
            // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
            //  may not be reflected in Keyfactor Command.
            Logger.LogError("Discovery job has failed due to an unknown error: {Error}", ex.Message);
            Logger.LogTrace("Exception details: {Details}", ex.ToString());
            var inner = ex.InnerException;
            while (inner != null)
            {
                Logger.LogError("Inner Exception: {Message}", inner.Message);
                Logger.LogTrace("Inner exception details: {Details}", inner.ToString());
                inner = inner.InnerException;
            }

            Logger.LogInformation("End DISCOVERY for K8S Orchestrator Extension for job '{JobID}' with failure",
                config.JobId);
            Logger.MethodExit(MsLogLevel.Debug);
            return FailJob(ex.Message, config.JobHistoryId);
        }
    }
}