// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using k8s.Autorest;
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SJKS;
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SPKCS12;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

// The Inventory class implements IAgentJobExtension and is meant to find all of the certificates in a given certificate store on a given server
//  and return those certificates back to Keyfactor for storing in its database.  Private keys will NOT be passed back to Keyfactor Command 
public class Inventory : JobBase, IInventoryJobExtension
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
        try
        {
            InitializeStore(config);
            Logger.LogInformation("Begin INVENTORY for K8S Orchestrator Extension for job " + config.JobId);
            Logger.LogInformation($"Inventory for store type: {config.Capability}");

            Logger.LogDebug($"Server: {KubeClient.GetHost()}");
            Logger.LogDebug($"Store Path: {StorePath}");
            Logger.LogDebug("KubeSecretType: " + KubeSecretType);
            Logger.LogDebug("KubeSecretName: " + KubeSecretName);
            Logger.LogDebug("KubeNamespace: " + KubeNamespace);
            Logger.LogDebug("Host: " + KubeClient.GetHost());

            Logger.LogTrace("Inventory entering switch based on KubeSecretType: " + KubeSecretType + "...");
            
            var hasPrivateKey = false;
            Logger.LogTrace("Inventory entering switch based on KubeSecretType: " + KubeSecretType + "...");

            if (Capability.Contains("Cluster")) KubeSecretType = "cluster";
            if (Capability.Contains("NS")) KubeSecretType = "namespace";

            var allowedKeys = new List<string>();
            if (!string.IsNullOrEmpty(CertificateDataFieldName))
                allowedKeys = CertificateDataFieldName.Split(',').ToList();

            switch (KubeSecretType.ToLower())
            {

                default:
                    Logger.LogError("Inventory failed with exception: " + KubeSecretType + " not supported.");
                    var errorMsg = $"{KubeSecretType} not supported.";
                    Logger.LogError(errorMsg);
                    Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + config.JobId +
                                          " with failure.");
                    return new JobResult
                    {
                        Result = OrchestratorJobStatusJobResult.Failure,
                        JobHistoryId = config.JobHistoryId,
                        FailureMessage = errorMsg
                    };
            }
        }
        catch (Exception ex)
        {
            Logger.LogError("Inventory failed with exception: " + ex.Message);
            Logger.LogTrace(ex.ToString());
            Logger.LogTrace(ex.StackTrace);
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + config.JobId +
                                  " with failure.");
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = ex.Message
            };
        }
    }

    

    private JobResult HandleCertificate(long jobId, SubmitInventoryUpdate submitInventory)
    {
        Logger.LogDebug("Entering HandleCertificate for job id " + jobId + "...");
        Logger.LogTrace("submitInventory: " + submitInventory);

        const bool hasPrivateKey = false;
        Logger.LogTrace("Calling GetCertificateSigningRequestStatus for job id " + jobId + "...");
        try
        {
            var certificates = KubeClient.GetCertificateSigningRequestStatus(KubeSecretName);
            Logger.LogDebug("GetCertificateSigningRequestStatus returned " + certificates.Count() + " certificates.");
            Logger.LogTrace(string.Join(",", certificates));
            Logger.LogDebug("Calling PushInventory for job id " + jobId + "...");
            return PushInventory(certificates, jobId, submitInventory);
        }
        catch (HttpOperationException e)
        {
            Logger.LogError("HttpOperationException: " + e.Message);
            Logger.LogTrace(e.ToString());
            Logger.LogTrace(e.StackTrace);
            var certDataErrorMsg =
                $"Kubernetes {KubeSecretType} '{KubeSecretName}' was not found in namespace '{KubeNamespace}' on host '{KubeClient.GetHost()}'.";
            Logger.LogError(certDataErrorMsg);
            var inventoryItems = new List<CurrentInventoryItem>();
            submitInventory.Invoke(inventoryItems);
            Logger.LogTrace("Exiting HandleCertificate for job id " + jobId + "...");
            // return FailJob(certDataErrorMsg, jobId);
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Success,
                JobHistoryId = jobId,
                FailureMessage = certDataErrorMsg
            };
        }
        catch (Exception e)
        {
            Logger.LogError("HttpOperationException: " + e.Message);
            Logger.LogTrace(e.ToString());
            Logger.LogTrace(e.StackTrace);
            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
            Logger.LogError(certDataErrorMsg);
            Logger.LogTrace("Exiting HandleCertificate for job id " + jobId + "...");
            return FailJob(certDataErrorMsg, jobId);
        }
    }

    private JobResult PushInventory(IEnumerable<string> certsList, long jobId, SubmitInventoryUpdate submitInventory,
        bool hasPrivateKey = false, string jobMessage = null)
    {
        Logger.LogDebug("Entering PushInventory for job id " + jobId + "...");
        Logger.LogTrace("submitInventory: " + submitInventory);
        Logger.LogTrace("certsList: " + certsList);
        var inventoryItems = new List<CurrentInventoryItem>();
        foreach (var cert in certsList)
        {
            Logger.LogTrace($"Cert:\n{cert}");
            // load as x509
            string alias;
            if (string.IsNullOrEmpty(cert))
            {
                Logger.LogWarning(
                    $"Kubernetes returned an empty inventory for store {KubeSecretName} in namespace {KubeNamespace} on host {KubeClient.GetHost()}.");
                continue;
            }

            try
            {
                Logger.LogDebug("Attempting to load cert as X509Certificate2...");
                var certFormatted = cert.Contains("BEGIN CERTIFICATE")
                    ? new X509Certificate2(Encoding.UTF8.GetBytes(cert))
                    : new X509Certificate2(Convert.FromBase64String(cert));
                Logger.LogTrace("Cert loaded as X509Certificate2: " + certFormatted);
                Logger.LogDebug("Attempting to get cert thumbprint...");
                alias = certFormatted.Thumbprint;
                Logger.LogDebug("Cert thumbprint: " + alias);
            }
            catch (Exception e)
            {
                Logger.LogError(e.Message);
                Logger.LogTrace(e.ToString());
                Logger.LogTrace(e.StackTrace);
                Logger.LogInformation(
                    "End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
                return FailJob(e.Message, jobId);
            }

            Logger.LogDebug("Adding cert to inventoryItems...");
            inventoryItems.Add(new CurrentInventoryItem
            {
                ItemStatus = OrchestratorInventoryItemStatus
                    .Unknown, //There are other statuses, but Command can determine how to handle new vs modified certificates
                Alias = alias,
                PrivateKeyEntry =
                    hasPrivateKey, //You will not pass the private key back, but you can identify if the main certificate of the chain contains a private key in the store
                UseChainLevel =
                    true, //true if Certificates will contain > 1 certificate, main cert => intermediate CA cert => root CA cert.  false if Certificates will contain an array of 1 certificate
                Certificates =
                    certsList //Array of single X509 certificates in Base64 string format (certificates if chain, single cert if not), something like:
            });
            break;
        }

        try
        {
            Logger.LogDebug("Submitting inventoryItems to Keyfactor Command...");
            //Sends inventoried certificates back to KF Command
            submitInventory.Invoke(inventoryItems);
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogInformation("End INVENTORY completed successfully for job id " + jobId + ".");
            return SuccessJob(jobId, jobMessage);
        }
        catch (Exception ex)
        {
            // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
            //  may not be reflected in Keyfactor Command.
            Logger.LogError("Unable to submit inventory to Keyfactor Command for job id " + jobId + ".");
            Logger.LogError(ex.Message);
            Logger.LogTrace(ex.ToString());
            Logger.LogTrace(ex.StackTrace);
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
            return FailJob(ex.Message, jobId);
        }
    }

    private JobResult PushInventory(Dictionary<string, string> certsList, long jobId,
        SubmitInventoryUpdate submitInventory, bool hasPrivateKey = false)
    {
        Logger.LogDebug("Entering PushInventory for job id " + jobId + "...");
        Logger.LogTrace("submitInventory: " + submitInventory);
        Logger.LogTrace("certsList: " + certsList);
        var inventoryItems = new List<CurrentInventoryItem>();
        foreach (var certObj in certsList)
        {
            var cert = certObj.Value;
            Logger.LogTrace($"Cert:\n{cert}");
            // load as x509
            var alias = certObj.Key;
            Logger.LogDebug("Cert alias: " + alias);

            if (string.IsNullOrEmpty(cert))
            {
                Logger.LogWarning(
                    $"Kubernetes returned an empty inventory for store {KubeSecretName} in namespace {KubeNamespace} on host {KubeClient.GetHost()}.");
                continue;
            }

            try
            {
                Logger.LogDebug("Attempting to load cert as X509Certificate2...");
                var certFormatted = cert.Contains("BEGIN CERTIFICATE")
                    ? new X509Certificate2(Encoding.UTF8.GetBytes(cert))
                    : new X509Certificate2(Convert.FromBase64String(cert));
                Logger.LogTrace("Cert loaded as X509Certificate2: " + certFormatted);
            }
            catch (Exception e)
            {
                Logger.LogError(e.Message);
                Logger.LogTrace(e.ToString());
                Logger.LogTrace(e.StackTrace);
                Logger.LogInformation(
                    "End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
                // return FailJob(e.Message, jobId);
            }

            var certs = new[] { cert };
            Logger.LogDebug("Adding cert to inventoryItems...");
            inventoryItems.Add(new CurrentInventoryItem
            {
                ItemStatus = OrchestratorInventoryItemStatus
                    .Unknown, //There are other statuses, but Command can determine how to handle new vs modified certificates
                Alias = alias,
                PrivateKeyEntry =
                    hasPrivateKey, //You will not pass the private key back, but you can identify if the main certificate of the chain contains a private key in the store
                UseChainLevel =
                    true, //true if Certificates will contain > 1 certificate, main cert => intermediate CA cert => root CA cert.  false if Certificates will contain an array of 1 certificate
                Certificates =
                    certs //Array of single X509 certificates in Base64 string format (certificates if chain, single cert if not), something like:
            });
        }

        try
        {
            Logger.LogDebug("Submitting inventoryItems to Keyfactor Command...");
            //Sends inventoried certificates back to KF Command
            submitInventory.Invoke(inventoryItems);
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogInformation("End INVENTORY completed successfully for job id " + jobId + ".");
            return SuccessJob(jobId);
        }
        catch (Exception ex)
        {
            // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
            //  may not be reflected in Keyfactor Command.
            Logger.LogError("Unable to submit inventory to Keyfactor Command for job id " + jobId + ".");
            Logger.LogError(ex.Message);
            Logger.LogTrace(ex.ToString());
            Logger.LogTrace(ex.StackTrace);
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
            return FailJob(ex.Message, jobId);
        }
    }

    private JobResult PushInventory(Dictionary<string, List<string>> certsList, long jobId,
        SubmitInventoryUpdate submitInventory, bool hasPrivateKey = false)
    {
        Logger.LogDebug("Entering PushInventory for job id " + jobId + "...");
        Logger.LogTrace("submitInventory: " + submitInventory);
        Logger.LogTrace("certsList: " + certsList);
        var inventoryItems = new List<CurrentInventoryItem>();
        foreach (var certObj in certsList)
        {
            var certs = certObj.Value;


            // load as x509
            var alias = certObj.Key;
            Logger.LogDebug("Cert alias: " + alias);

            if (certs.Count == 0)
            {
                Logger.LogWarning(
                    $"Kubernetes returned an empty inventory for store {KubeSecretName} in namespace {KubeNamespace} on host {KubeClient.GetHost()}.");
                continue;
            }

            Logger.LogDebug("Adding cert to inventoryItems...");
            inventoryItems.Add(new CurrentInventoryItem
            {
                ItemStatus = OrchestratorInventoryItemStatus
                    .Unknown, //There are other statuses, but Command can determine how to handle new vs modified certificates
                Alias = alias,
                PrivateKeyEntry =
                    hasPrivateKey, //You will not pass the private key back, but you can identify if the main certificate of the chain contains a private key in the store
                UseChainLevel =
                    true, //true if Certificates will contain > 1 certificate, main cert => intermediate CA cert => root CA cert.  false if Certificates will contain an array of 1 certificate
                Certificates =
                    certs //Array of single X509 certificates in Base64 string format (certificates if chain, single cert if not), something like:
            });
        }

        try
        {
            Logger.LogDebug("Submitting inventoryItems to Keyfactor Command...");
            //Sends inventoried certificates back to KF Command
            submitInventory.Invoke(inventoryItems);
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogInformation("End INVENTORY completed successfully for job id " + jobId + ".");
            return SuccessJob(jobId);
        }
        catch (Exception ex)
        {
            // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
            //  may not be reflected in Keyfactor Command.
            Logger.LogError("Unable to submit inventory to Keyfactor Command for job id " + jobId + ".");
            Logger.LogError(ex.Message);
            Logger.LogTrace(ex.ToString());
            Logger.LogTrace(ex.StackTrace);
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
            return FailJob(ex.Message, jobId);
        }
    }

    private JobResult HandleOpaqueSecret(long jobId, SubmitInventoryUpdate submitInventory, string[] secretManagedKeys,
        string secretPath = "")
    {
        Logger.LogDebug("Inventory entering HandleOpaqueSecret for job id " + jobId + "...");
        const bool hasPrivateKey = true;
        //check if secretAllowedKeys is null or empty
        if (secretManagedKeys == null || secretManagedKeys.Length == 0) secretManagedKeys = new[] { "certificates" };
        Logger.LogTrace("secretManagedKeys: " + secretManagedKeys);
        Logger.LogDebug(
            $"Querying Kubernetes secrets of type '{KubeSecretType}' for {KubeSecretName} in namespace {KubeNamespace} on host {KubeClient.GetHost()}...");
        Logger.LogTrace("Entering try block for HandleOpaqueSecret...");
        try
        {
            var certData = KubeClient.GetCertificateStoreSecret(
                KubeSecretName,
                KubeNamespace
            );
            var certsList = new string[] { }; //empty array
            Logger.LogTrace("certData: " + certData);
            Logger.LogTrace("certList: " + certsList);
            foreach (var managedKey in secretManagedKeys)
            {
                Logger.LogDebug("Checking if certData contains key " + managedKey + "...");
                if (!certData.Data.ContainsKey(managedKey)) continue;

                Logger.LogDebug("certData contains key " + managedKey + ".");
                Logger.LogTrace("Getting cert data for key " + managedKey + "...");
                var certificatesBytes = certData.Data[managedKey];
                Logger.LogTrace("certificatesBytes: " + certificatesBytes);
                var certificates = Encoding.UTF8.GetString(certificatesBytes);
                Logger.LogTrace("certificates: " + certificates);
                Logger.LogDebug("Splitting certificates by separator " + CertChainSeparator + "...");
                //split the certificates by the separator
                var splitCerts = certificates.Split(CertChainSeparator);
                Logger.LogTrace("splitCerts: " + splitCerts);
                //add the split certs to the list
                Logger.LogDebug("Adding split certs to certsList...");
                certsList = certsList.Concat(splitCerts).ToArray();
                Logger.LogTrace("certsList: " + certsList);
                // certsList.Concat(certificates.Split(CertChainSeparator));
            }

            Logger.LogInformation("Submitting inventoryItems to Keyfactor Command for job id " + jobId + "...");
            return PushInventory(certsList, jobId, submitInventory, hasPrivateKey);
        }
        catch (HttpOperationException e)
        {
            Logger.LogError(e.Message);
            Logger.LogTrace(e.ToString());
            Logger.LogTrace(e.StackTrace);
            var certDataErrorMsg =
                $"Kubernetes {KubeSecretType} '{KubeSecretName}' was not found in namespace '{KubeNamespace}' on host '{KubeClient.GetHost()}'.";
            Logger.LogError(certDataErrorMsg);
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
            // return FailJob(certDataErrorMsg, jobId);
            var inventoryItems = new List<CurrentInventoryItem>();
            submitInventory.Invoke(inventoryItems);
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Success,
                JobHistoryId = jobId,
                FailureMessage = certDataErrorMsg
            };
        }
        catch (Exception e)
        {
            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
            Logger.LogError(certDataErrorMsg);
            Logger.LogTrace(e.ToString());
            Logger.LogTrace(e.StackTrace);
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
            return FailJob(certDataErrorMsg, jobId);
        }
    }


    

    
}