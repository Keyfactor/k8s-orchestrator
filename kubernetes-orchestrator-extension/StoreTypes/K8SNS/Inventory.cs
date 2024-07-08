using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SNS;

public class Inventory : InventoryBase, IInventoryJobExtension
{
    public Inventory(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    //Job Entry Point
    public JobResult ProcessJob(InventoryJobConfiguration config, SubmitInventoryUpdate submitInventory)
    {
        //METHOD ARGUMENTS...
        //config - contains context information passed from KF Command to this job run:
        //
        // config.Server.Username, config.Server.Password - credentials for orchestrated server - use to authenticate to certificate store server.
        //
        // config.ServerUsername, config.ServerPassword - credentials for orchestrated server - use to authenticate to certificate store server.
        // config.CertificateStoreDetails.ClientMachine - server name or IP address of orchestrated server
        // config.CertificateStoreDetails.StorePath - location path of certificate store on orchestrated server
        // config.CertificateStoreDetails.StorePassword - if the certificate store has a password, it would be passed here
        // config.CertificateStoreDetails.Properties - JSON string containing custom store properties for this specific store type

        //NLog Logging to c:\CMS\Logs\CMS_Agent_Log.txt

        Init(config);

        try
        {
            Logger.LogDebug("Calling KubeClient.DiscoverSecrets() for Opaque secrets");
            var namespaceOpaqueSecrets = KubeClient.DiscoverSecrets(OpaqueAllowedKeys, "Opaque", KubeNamespace);
            Logger.LogDebug("Returned from KubeClient.DiscoverSecrets() for Opaque secrets");

            Logger.LogDebug("Calling KubeClient.DiscoverSecrets() for TLS secrets");
            var namespaceTlsSecrets = KubeClient.DiscoverSecrets(TlsAllowedKeys, "tls", KubeNamespace);
            Logger.LogDebug("Returned from KubeClient.DiscoverSecrets() for TLS secrets");

            var namespaceInventoryDict = new Dictionary<string, List<string>>();
            Logger.LogDebug("Calling HandleK8SSecret() for Opaque secrets");
            var opaqueSecrets = HandleK8SSecret(namespaceOpaqueSecrets, "opaque");
            Logger.LogDebug("Finished processing Opaque secrets");

            Logger.LogDebug("Calling HandleK8SSecret() for TLS secrets");
            var tlsSecrets = HandleK8SSecret(namespaceTlsSecrets, "tls");
            Logger.LogDebug("Finished processing TLS secrets");
            
            Logger.LogDebug("Merging Opaque and TLS secrets into namespace inventory dictionary");
            namespaceInventoryDict = namespaceInventoryDict.Concat(opaqueSecrets).ToDictionary(x => x.Key, x => x.Value);
            
            Logger.LogDebug("Merging Opaque and TLS secrets into namespace inventory dictionary");
            namespaceInventoryDict = namespaceInventoryDict.Concat(tlsSecrets).ToDictionary(x => x.Key, x => x.Value);

            Logger.LogDebug("Calling PushInventory for job id '{JobId}'", config.JobHistoryId);
            return PushInventory(namespaceInventoryDict, config.JobHistoryId, submitInventory, HasPrivateKey);
        }
        catch (Exception ex)
        {
            Logger.LogError("{Message}", ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job {JobId} with failure",
                config.JobHistoryId);
            return FailJob(ex.Message, config.JobHistoryId);
        }
    }

    
}