// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
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
        Logger.LogDebug("Begin Discovery...");

        Logger.LogInformation($"Discovery for store type: {config.Capability}");

        var locations = new List<string>();

        KubeSvcCreds = ServerPassword;
        KubeClient = new KubeCertificateManagerClient(KubeSvcCreds);
        var namespaces = config.JobProperties["dirs"].ToString().Split(',');
        if (namespaces.Length == 0)
        {
            namespaces = new[] { "default" };
        }
        var ignoreNamespace = config.JobProperties["ignoreddirs"].ToString().Split(',');
        var secretAllowedKeys = config.JobProperties["patterns"].ToString().Split(',');
        if (secretAllowedKeys.Length == 0)
        {
            // secretAllowedKeys = new string[] { "tls.crt", "tls.key", "ca.crt", "ca.key", "key", "crt" };
            
        }

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
                case "CertStores.K8STLSSecr.Discovery":
                    secretAllowedKeys = new[] { "tls.crt", "tls.key"};
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys, "tls");
                    break;
                case "CertStores.K8SSecret.Discovery":
                    secretAllowedKeys = new[] { "tls.crts", "cert", "certs", "certificate", "certificates", "crt", "crts" };
                    locations = KubeClient.DiscoverSecrets(secretAllowedKeys,"opaque");
                    break;
                case "CertStores.K8SCert.Discovery":
                    locations = KubeClient.DiscoverCertificates();
                    break;
            }

        }
        catch (Exception ex)
        {
            //Status: 2=Success, 3=Warning, 4=Error
            return FailJob(ex.Message, config.JobHistoryId);
        }

        try
        {
            //Sends store locations back to KF command where they can be approved or rejected
            submitDiscovery.Invoke(locations);
            //Status: 2=Success, 3=Warning, 4=Error
            return SuccessJob(config.JobHistoryId);
        }
        catch (Exception ex)
        {
            // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
            //  may not be reflected in Keyfactor Command.
            return FailJob(ex.Message, config.JobHistoryId);
        }
    }
}
