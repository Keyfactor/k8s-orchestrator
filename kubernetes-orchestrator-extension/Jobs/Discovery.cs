// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

// The Discovery class implements IAgentJobExtension and is meant to find all certificate stores based on the information passed when creating the job in KF Command 
public class Discovery : JobBase, IDiscoveryJobExtension
{
    public Discovery(IPAMSecretResolver resolver)
    {
        Resolver = resolver;
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
        InitializeStore(config);
        Logger.LogInformation("Begin Discovery for K8S Orchestrator Extension for job " + config.JobId);
        Logger.LogInformation($"Discovery for store type: {config.Capability}");

        var locations = new List<string>();

        KubeSvcCreds = ServerPassword;
        KubeClient = new KubeCertificateManagerClient(KubeSvcCreds);
        
        var namespaces = config.JobProperties["dirs"].ToString()?.Split(',');
        if (namespaces is { Length: 0 })
        {
            namespaces = new[] { "default" };
        }
        Logger.LogDebug("Namespaces: " + string.Join(",", namespaces));

        var ignoreNamespace = config.JobProperties["ignoreddirs"].ToString()?.Split(',');
        Logger.LogDebug("Ignored Namespaces: " + string.Join(",", ignoreNamespace));

        var secretAllowedKeys = config.JobProperties["patterns"].ToString()?.Split(',');
        Logger.LogDebug("Secret Allowed Keys: " + string.Join(",", secretAllowedKeys));

        Logger.LogTrace("Discovery entering switch block based on capability: " + config.Capability);
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
                    Logger.LogTrace("Entering case: CertStores.K8SCluster.Discovery");
                    secretAllowedKeys = secretAllowedKeys.Concat(TLSAllowedKeys).ToArray();
                    Logger.LogInformation("Discovering secrets with allowed keys: " + string.Join(",", secretAllowedKeys) + " and type: tls");
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "cluster", string.Join(",", namespaces));
                    break;
                case "CertStores.K8SNS.Discovery":
                    // Combine the allowed keys with the default keys
                    Logger.LogTrace("Entering case: CertStores.K8SNamespace.Discovery");
                    secretAllowedKeys = secretAllowedKeys.Concat(TLSAllowedKeys).ToArray();
                    Logger.LogInformation("Discovering secrets with allowed keys: " + string.Join(",", secretAllowedKeys) + " and type: tls");
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "namespace", string.Join(",", namespaces));
                    break;
                case "CertStores.K8STLSSecr.Discovery":
                    // Combine the allowed keys with the default keys
                    Logger.LogTrace("Entering case: CertStores.K8STLSSecr.Discovery");
                    secretAllowedKeys = secretAllowedKeys.Concat(TLSAllowedKeys).ToArray();
                    Logger.LogInformation("Discovering secrets with allowed keys: " + string.Join(",", secretAllowedKeys) + " and type: tls");
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "kubernetes.io/tls", string.Join(",", namespaces));
                    break;
                case "CertStores.K8SSecret.Discovery":
                    Logger.LogTrace("Entering case: CertStores.K8SSecret.Discovery");
                    secretAllowedKeys = secretAllowedKeys.Concat(OpaqueAllowedKeys).ToArray();
                    Logger.LogInformation("Discovering secrets with allowed keys: " + string.Join(",", secretAllowedKeys) + " and type: opaque");
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "Opaque", string.Join(",", namespaces));
                    break;
                case "CertStores.K8SPFX.Discovery":
                case "CertStores.K8SPKCS12.Discovery":
                    // config.JobProperties["dirs"] - Directories to search
                    // config.JobProperties["extensions"] - Extensions to search
                    // config.JobProperties["ignoreddirs"] - Directories to ignore
                    // config.JobProperties["patterns"] - File name patterns to match
                    
                    var pfxNamespaces = config.JobProperties["dirs"].ToString();
                    if (pfxNamespaces.Length == 0)
                    {
                        pfxNamespaces = "default";
                    }
                    var secretAllowedKeysStr = config.JobProperties["extensions"].ToString();
                    var allowedPatterns = config.JobProperties["patterns"].ToString();

                    var additionalKeyPatterns = string.IsNullOrEmpty(allowedPatterns) ? new [] {"p12"} : allowedPatterns.Split(',');
                    secretAllowedKeys = string.IsNullOrEmpty(secretAllowedKeysStr) ? new[] { "p12" } : secretAllowedKeysStr.Split(',');

                    Logger.LogTrace("Entering case: CertStores.K8SCert.Discovery");
                    Logger.LogInformation("Discovering secrets with allowed keys: " + string.Join(",", secretAllowedKeys) + " and type: pkcs12");
                    
                    //append pkcs12AllowedKeys to secretAllowedKeys
                    secretAllowedKeys = secretAllowedKeys.Concat(additionalKeyPatterns).ToArray();
                    secretAllowedKeys = secretAllowedKeys.Concat(Pkcs12AllowedKeys).ToArray();
                    
                    //make secretAllowedKeys unique
                    secretAllowedKeys = secretAllowedKeys.Distinct().ToArray();
                    
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "pkcs12", string.Join(",", pfxNamespaces));
                    break;
                case "CertStores.K8SJKS.Discovery":
                    // config.JobProperties["dirs"] - Directories to search
                    // config.JobProperties["extensions"] - Extensions to search
                    // config.JobProperties["ignoreddirs"] - Directories to ignore
                    // config.JobProperties["patterns"] - File name patterns to match
                    
                    var jksNamespaces = config.JobProperties["dirs"].ToString();
                    if (jksNamespaces.Length == 0)
                    {
                        jksNamespaces = "default";
                    }
                    var jksSecretAllowedKeysStr = config.JobProperties["extensions"].ToString();
                    var jksAllowedPatterns = config.JobProperties["patterns"].ToString();

                    var jksAdditionalKeyPatterns = string.IsNullOrEmpty(jksAllowedPatterns) ? new [] {"jks"} : jksAllowedPatterns.Split(',');
                    secretAllowedKeys = string.IsNullOrEmpty(jksSecretAllowedKeysStr) ? new[] { "jks" } : jksSecretAllowedKeysStr.Split(',');

                    Logger.LogTrace("Entering case: CertStores.K8SCert.Discovery");
                    Logger.LogInformation("Discovering secrets with allowed keys: " + string.Join(",", secretAllowedKeys) + " and type: cert");
                    
                    //append pkcs12AllowedKeys to secretAllowedKeys
                    secretAllowedKeys = secretAllowedKeys.Concat(jksAdditionalKeyPatterns).ToArray();
                    secretAllowedKeys = secretAllowedKeys.Concat(JksAllowedKeys).ToArray();
                    
                    //make secretAllowedKeys unique
                    secretAllowedKeys = secretAllowedKeys.Distinct().ToArray();
                    
                    Logger.LogInformation("Discovering secrets with allowed keys: " + string.Join(",", secretAllowedKeys) + " and type: jks");
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "jks", string.Join(",", jksNamespaces));
                    break;
                case "CertStores.K8SCert.Discovery":
                    break;
            }

        }
        catch (Exception ex)
        {
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogError("Discovery job has failed due to an unknown error.");
            Logger.LogError(ex.Message);
            Logger.LogTrace(ex.StackTrace);
            Logger.LogInformation("End DISCOVERY for K8S Orchestrator Extension for job " + config.JobId + " with failure.");
            return FailJob(ex.Message, config.JobHistoryId);
        }

        try
        {
            //Sends store locations back to KF command where they can be approved or rejected
            Logger.LogInformation("Submitting discovered locations to Keyfactor Command...");
            Logger.LogDebug("Discovery locations: " + string.Join(",", locations));
            submitDiscovery.Invoke(locations.Distinct().ToArray());
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
            Logger.LogError("Discovery job invoke has failed due to an unknown error." + ex.Message);
            Logger.LogTrace(ex.ToString());
            Logger.LogTrace(ex.StackTrace);
            Logger.LogInformation("End DISCOVERY for K8S Orchestrator Extension for job " + config.JobId + " with failure.");
            return FailJob(ex.Message, config.JobHistoryId);
        }
    }
}
