using System;
using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SCert;

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
        HasPrivateKey = false; //A k8s certificate signing request does not have a private key to recover
        Logger.LogInformation("Inventorying TLS secrets using the following allowed keys: {Keys}",
            TlsAllowedKeys?.ToString());
        var jobId = config.JobHistoryId;
        try
        {
            Logger.LogInformation("Inventorying k8s certificate resources using the following allowed keys: {Keys}",
                CertAllowedKeys?.ToString());
            try
            {
                Logger.LogDebug("Calling KubeClient.GetCertificateSigningRequestStatus()");
                var certificates = KubeClient.GetCertificateSigningRequestStatus(KubeSecretName);
                Logger.LogDebug("Returned from KubeClient.GetCertificateSigningRequestStatus()");
                Logger.LogDebug(
                    "GetCertificateSigningRequestStatus returned '{Count}' certificates for job id '{JobId}'",
                    certificates.Length, jobId);
                Logger.LogTrace("{Certs}", string.Join("\r\n", certificates));
                Logger.LogDebug("Calling PushInventory for job id '{JobId}'", jobId);
                return PushInventory(certificates, jobId, submitInventory, HasPrivateKey);
            }
            catch (Exception e)
            {
                Logger.LogError("{Message}", e.Message);
                Logger.LogTrace("{Message}", e.ToString());
                var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
                Logger.LogError("{Message}", certDataErrorMsg);
                Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job '{JobId}' with failure",
                    jobId);
                return FailJob(certDataErrorMsg, jobId);
            }
        }
        catch (StoreNotFoundException)
        {
            Logger.LogWarning("Unable to locate certificates on Kubernetes cluster {Host}, sending empty inventory", KubeHost);
            return PushInventory(new List<string>(), config.JobHistoryId, submitInventory, HasPrivateKey,
                "WARNING: No certificates returned from Kubernetes cluster, assuming empty inventory.");
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