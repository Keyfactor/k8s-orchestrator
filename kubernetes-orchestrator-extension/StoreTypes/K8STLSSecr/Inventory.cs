using System;
using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;


namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8STLSSecr;

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
        HasPrivateKey = true; //This is a k8s TLS secret, so it should have a private key
        Logger.LogInformation("Inventorying TLS secrets using the following allowed keys: {Keys}",
            TlsAllowedKeys?.ToString());
        try
        {
            var tlsCertsInv = HandleTlsSecret();
            Logger.LogDebug("Returned inventory count: {Count}", tlsCertsInv.Count.ToString());
            return PushInventory(tlsCertsInv, config.JobHistoryId, submitInventory, true);
        }
        catch (StoreNotFoundException)
        {
            Logger.LogWarning("Unable to locate tls secret {Namespace}/{Name}. Sending empty inventory",
                KubeNamespace, KubeSecretName);
            return PushInventory(new List<string>(), config.JobHistoryId, submitInventory, false,
                "WARNING: Store not found on Kubernetes cluster, assuming empty inventory");
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