// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8STLSSecr;

// The Discovery class implements IAgentJobExtension and is meant to find all certificate stores based on the information passed when creating the job in KF Command 
public class Discovery : DiscoveryBase, IDiscoveryJobExtension
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

        try
        {
            Init(config: config);
            Logger.LogDebug("Enter ProcessJob()");
            SecretType = "kubernetes.io/tls";
            Logger.LogTrace("SecretType: {SecretType}", SecretType);
            Logger.LogTrace("Job capability: {Capability}", config.Capability);
            
            SecretAllowedKeys = SecretAllowedKeys.Concat(TlsAllowedKeys).ToArray();
            Logger.LogInformation(
                "Discovering k8s secrets in k8s namespaces `{Namespaces}` with allowed keys: `{AllowedKeys}` and secret type: `{SecretType}`",
                string.Join(",", SearchNamespaces), string.Join(",", SecretAllowedKeys), SecretType);
            Logger.LogDebug("Calling KubeClient.DiscoverSecrets()");
            DiscoveredLocations = KubeClient.DiscoverSecrets(SecretAllowedKeys, SecretType,
                string.Join(",", SearchNamespaces));
            Logger.LogDebug("Returned from KubeClient.DiscoverSecrets()");
            //Sends store locations back to KF command where they can be approved or rejected
            Logger.LogInformation("Submitting discovered locations to Keyfactor Command...");
            Logger.LogTrace("Discovery locations: {Locations}", string.Join(",", DiscoveredLocations));
            Logger.LogDebug("Calling submitDiscovery.Invoke()");
            submitDiscovery.Invoke(DiscoveredLocations.Distinct().ToArray());
            Logger.LogDebug("Returned from submitDiscovery.Invoke()");
            Logger.LogDebug("Returning successful JobResult");
            Logger.LogInformation("Discovery completed successfully for {JobId}", config.JobId);
            //Status: 2=Success, 3=Warning, 4=Error
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Success,
                JobHistoryId = config.JobHistoryId,
                FailureMessage =
                    "Discovered the following locations: " +
                    string.Join(",\n", DiscoveredLocations), // This is what gets written to the Command UI job log.
            };
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
    }
}