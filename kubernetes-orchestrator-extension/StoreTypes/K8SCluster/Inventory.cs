using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SCluster;

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
            var clusterOpaqueSecrets = KubeClient.DiscoverSecrets(OpaqueAllowedKeys, "Opaque", "all");
            Logger.LogDebug("Returned from KubeClient.DiscoverSecrets() for Opaque secrets");

            Logger.LogDebug("Calling KubeClient.DiscoverSecrets() for TLS secrets");
            var clusterTlsSecrets = KubeClient.DiscoverSecrets(TlsAllowedKeys, "tls", "all");
            Logger.LogDebug("Returned from KubeClient.DiscoverSecrets() for TLS secrets");

            var clusterInventoryDict = new Dictionary<string, List<string>>();
            Logger.LogDebug("Processing Opaque secrets");
            var opaqueSecrets = HandleK8SSecret(clusterOpaqueSecrets, "opaque");
            Logger.LogDebug("Finished processing Opaque secrets");

            Logger.LogDebug("Processing TLS secrets");
            var tlsSecrets = HandleK8SSecret(clusterTlsSecrets, "tls");
            Logger.LogDebug("Finished processing TLS secrets");

            Logger.LogDebug("Merging Opaque and TLS secrets into cluster inventory dictionary");
            clusterInventoryDict = clusterInventoryDict.Concat(opaqueSecrets).ToDictionary(x => x.Key, x => x.Value);

            Logger.LogDebug("Merging Opaque and TLS secrets into cluster inventory dictionary");
            clusterInventoryDict = clusterInventoryDict.Concat(tlsSecrets).ToDictionary(x => x.Key, x => x.Value);

            Logger.LogDebug("Calling PushInventory for job id '{JobId}'", config.JobHistoryId);
            return PushInventory(clusterInventoryDict, config.JobHistoryId, submitInventory, HasPrivateKey);
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