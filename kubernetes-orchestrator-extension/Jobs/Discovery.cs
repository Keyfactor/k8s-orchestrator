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
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

// The Discovery class implements IAgentJobExtension and is meant to find all certificate stores based on the information passed when creating the job in KF Command 
public class Discovery : JobBase, IDiscoveryJobExtension
{
    public Discovery(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    //Job Entry Point
    public JobResult ProcessJob(DiscoveryJobConfiguration config, SubmitDiscoveryUpdate submitDiscovery)
    {
        //METHOD ARGUMENTS...
        //config - contains context information passed from KF Command to this job run:
        //
        // config.ServerUsername, config.ServerPassword - credentials for orchestrated server - use to authenticate to certificate store server.
        // config.ClientMachine - server name or IP address of orchestrated server
        //
        // config.JobProperties["dirs"] - Directories to search
        // config.JobProperties["extensions"] - Extensions to search
        // config.JobProperties["ignoreddirs"] - Directories to ignore
        // config.JobProperties["patterns"] - File name patterns to match


        //NLog Logging to c:\CMS\Logs\CMS_Agent_Log.txt
        Logger = LogHandler.GetClassLogger(GetType());
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
            switch (config.Capability)
            {
                case "CertStores.K8SCluster.Discovery":
                    // Combine the allowed keys with the default keys
                    Logger.LogTrace("Entering case: {Capability}", config.Capability);
                    secretAllowedKeys = secretAllowedKeys.Concat(TLSAllowedKeys).ToArray();

                    Logger.LogInformation(
                        "Discovering k8s secrets for cluster `{ClusterName}` with allowed keys: `{AllowedKeys}` and secret types: `kubernetes.io/tls, Opaque`",
                        KubeHost, string.Join(",", secretAllowedKeys));
                    Logger.LogDebug("Calling KubeClient.DiscoverSecrets()");
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "cluster", string.Join(",", namespaces));
                    Logger.LogDebug("Returned from KubeClient.DiscoverSecrets()");

                    break;
                case "CertStores.K8SNS.Discovery":
                    // Combine the allowed keys with the default keys
                    Logger.LogTrace("Entering case: {Capability}", config.Capability);
                    secretAllowedKeys = secretAllowedKeys.Concat(TLSAllowedKeys).ToArray();
                    Logger.LogInformation(
                        "Discovering k8s secrets in k8s namespaces `{Namespaces}` with allowed keys: `{AllowedKeys}` and secret types: `kubernetes.io/tls, Opaque`",
                        string.Join(",", namespaces), string.Join(",", secretAllowedKeys));
                    Logger.LogDebug("Calling KubeClient.DiscoverSecrets()");
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "namespace",
                        string.Join(",", namespaces));
                    Logger.LogDebug("Returned from KubeClient.DiscoverSecrets()");
                    break;
                case "CertStores.K8STLSSecr.Discovery":
                    // Combine the allowed keys with the default keys
                    Logger.LogTrace("Entering case: {Capability}", config.Capability);
                    secretAllowedKeys = secretAllowedKeys.Concat(TLSAllowedKeys).ToArray();
                    Logger.LogInformation(
                        "Discovering k8s secrets in k8s namespaces `{Namespaces}` with allowed keys: `{AllowedKeys}` and secret type: `kubernetes.io/tls`",
                        string.Join(",", namespaces), string.Join(",", secretAllowedKeys));
                    Logger.LogDebug("Calling KubeClient.DiscoverSecrets()");
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "kubernetes.io/tls",
                        string.Join(",", namespaces));
                    Logger.LogDebug("Returned from KubeClient.DiscoverSecrets()");
                    break;
                case "CertStores.K8SSecret.Discovery":
                    Logger.LogTrace("Entering case: {Capability}", config.Capability);
                    secretAllowedKeys = secretAllowedKeys.Concat(OpaqueAllowedKeys).ToArray();
                    Logger.LogInformation("Discovering secrets with allowed keys: `{AllowedKeys}` and type: `Opaque`",
                        string.Join(",", secretAllowedKeys));
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "Opaque", string.Join(",", namespaces));
                    break;
                case "CertStores.K8SPFX.Discovery":
                case "CertStores.K8SPKCS12.Discovery":
                    // config.JobProperties["dirs"] - Directories to search
                    // config.JobProperties["extensions"] - Extensions to search
                    // config.JobProperties["ignoreddirs"] - Directories to ignore
                    // config.JobProperties["patterns"] - File name patterns to match
                    Logger.LogTrace("Entering case: {Capability}", config.Capability);

                    var secretAllowedKeysStr = config.JobProperties["extensions"].ToString();
                    var allowedPatterns = config.JobProperties["patterns"].ToString();

                    var additionalKeyPatterns = string.IsNullOrEmpty(allowedPatterns)
                        ? new[] { "p12" }
                        : allowedPatterns.Split(',');
                    secretAllowedKeys = string.IsNullOrEmpty(secretAllowedKeysStr)
                        ? new[] { "p12" }
                        : secretAllowedKeysStr.Split(',');

                    //append pkcs12AllowedKeys to secretAllowedKeys
                    secretAllowedKeys = secretAllowedKeys.Concat(additionalKeyPatterns).ToArray();
                    secretAllowedKeys = secretAllowedKeys.Concat(Pkcs12AllowedKeys).ToArray();

                    //make secretAllowedKeys unique
                    secretAllowedKeys = secretAllowedKeys.Distinct().ToArray();

                    Logger.LogInformation("Discovering k8s secrets with allowed keys: `{AllowedKeys}` and type: `pkcs12`",
                        string.Join(",", secretAllowedKeys));
                    Logger.LogDebug("Calling KubeClient.DiscoverSecrets()");
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "pkcs12",
                        string.Join(",", namespaces));
                    Logger.LogDebug("Returned from KubeClient.DiscoverSecrets()");
                    break;
                case "CertStores.K8SJKS.Discovery":
                    // config.JobProperties["dirs"] - Directories to search
                    // config.JobProperties["extensions"] - Extensions to search
                    // config.JobProperties["ignoreddirs"] - Directories to ignore
                    // config.JobProperties["patterns"] - File name patterns to match

                    Logger.LogTrace("Entering case: {Capability}", config.Capability);
                    var jksSecretAllowedKeysStr = config.JobProperties["extensions"].ToString();
                    var jksAllowedPatterns = config.JobProperties["patterns"].ToString();

                    var jksAdditionalKeyPatterns = string.IsNullOrEmpty(jksAllowedPatterns)
                        ? new[] { "jks" }
                        : jksAllowedPatterns.Split(',');
                    secretAllowedKeys = string.IsNullOrEmpty(jksSecretAllowedKeysStr)
                        ? new[] { "jks" }
                        : jksSecretAllowedKeysStr.Split(',');

                    //append pkcs12AllowedKeys to secretAllowedKeys
                    secretAllowedKeys = secretAllowedKeys.Concat(jksAdditionalKeyPatterns).ToArray();
                    secretAllowedKeys = secretAllowedKeys.Concat(JksAllowedKeys).ToArray();

                    //make secretAllowedKeys unique
                    secretAllowedKeys = secretAllowedKeys.Distinct().ToArray();

                    Logger.LogInformation("Discovering k8s secrets with allowed keys: `{AllowedKeys}` and type: `jks`",
                        string.Join(",", secretAllowedKeys));
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "jks", string.Join(",", namespaces));
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
            Logger.LogTrace("{Message}", ex.StackTrace);
            Logger.LogTrace("{Ex}",ex.ToString());
            // iterate through the inner exceptions
            var inner = ex.InnerException;
            while (inner != null)
            {
                Logger.LogError("Inner Exception: {Message}", inner.Message);
                Logger.LogTrace("{Message}", inner.ToString());
                Logger.LogTrace("{Message}", inner.StackTrace);
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
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Success,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = "Discovered the following locations: " + string.Join(",\n", locations),
            };
        }
        catch (Exception ex)
        {
            // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
            //  may not be reflected in Keyfactor Command.
            Logger.LogError("Discovery job has failed due to an unknown error: `{Error}`", ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            Logger.LogTrace("{Message}", ex.StackTrace);
            var inner = ex.InnerException;
            while (inner != null)
            {
                Logger.LogError("Inner Exception: {Message}", inner.Message);
                Logger.LogTrace("{Message}", inner.ToString());
                Logger.LogTrace("{Message}", inner.StackTrace);
                inner = inner.InnerException;
            }
            Logger.LogInformation("End DISCOVERY for K8S Orchestrator Extension for job '{JobID}' with failure",
                config.JobId);
            return FailJob(ex.Message, config.JobHistoryId);
        }
    }
}