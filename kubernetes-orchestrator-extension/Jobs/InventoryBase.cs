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
public abstract class InventoryBase : JobBase
{
    protected string[] SecretAllowedKeys = Array.Empty<string>();
    
    //Job Entry Point
    public void Init(InventoryJobConfiguration config, SubmitInventoryUpdate submitInventory)
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


        InitializeStore(config);
        Logger.LogInformation("Begin INVENTORY for K8S Orchestrator Extension for job '{JobId}", config.JobId);
        Logger.LogInformation("Inventory for store type: {Capability}", config.Capability);

        K8SHostName = KubeClient.GetHost();
        Logger.LogDebug("Server: {Host}", K8SHostName);
        Logger.LogDebug("Store Path: {StorePath}", StorePath);
        Logger.LogDebug("KubeSecretType: {SecretType}", KubeSecretType);
        Logger.LogDebug("KubeSecretName: {SecretName}", KubeSecretName);
        Logger.LogDebug("KubeNamespace: {Namespace}", KubeNamespace);

        var hasPrivateKey = false;

        if (Capability.Contains("Cluster")) KubeSecretType = "cluster";
        if (Capability.Contains("NS")) KubeSecretType = "namespace";

        if (!string.IsNullOrEmpty(CertificateDataFieldName))
            SecretAllowedKeys = CertificateDataFieldName.Split(',');
    }

    private bool validInvCert(string cert, string alias = "")
    {
        try
        {
            Logger.LogDebug("Attempting to load cert '{Alias}' as X509Certificate2", alias);
            var certFormatted = cert.Contains("BEGIN CERTIFICATE")
                ? new X509Certificate2(Encoding.UTF8.GetBytes(cert))
                : new X509Certificate2(Convert.FromBase64String(cert));
            Logger.LogTrace("Cert loaded as X509Certificate2:\n{Formatted}", certFormatted);
            Logger.LogDebug("Attempting to get cert thumbprint");
            alias = certFormatted.Thumbprint;
            Logger.LogDebug("Cert thumbprint: {TP}", alias);
        }
        catch (Exception e)
        {
            Logger.LogError("{Message}", e.Message);
            Logger.LogTrace("{Message}", e.ToString());
            return false;
        }

        return true;
    } 
    
    private JobResult PushInventory(IEnumerable<string> certsList, long jobId, SubmitInventoryUpdate submitInventory,
        bool hasPrivateKey = false, string jobMessage = null)
    {
        Logger.LogDebug("Entering PushInventory for job id '{JobId}'", jobId);
        Logger.LogTrace("submitInventory: {Inv}", submitInventory.ToString());
        Logger.LogTrace("certsList: {Certs}", certsList.ToString());
        var inventoryItems = new List<CurrentInventoryItem>();
        var certificates = certsList as string[] ?? certsList.ToArray();
        foreach (var cert in certificates)
        {
            Logger.LogTrace("Cert:\n{Cert}", cert);
            // load as x509
            string alias;
            if (string.IsNullOrEmpty(cert))
            {
                Logger.LogWarning(
                    "Kubernetes returned an empty inventory for store {KubeSecretName} in namespace {KubeNamespace} on host {HostName}",
                    KubeSecretName, KubeNamespace, K8SHostName);
                continue;
            }

            if (!validInvCert(cert, ""))
            {
                Logger.LogWarning("Invalid certificate '{Cert}' will not be inventoried", cert);
                continue;
            }

            Logger.LogDebug("Adding cert to inventoryItems");
            inventoryItems.Add(new CurrentInventoryItem
            {
                ItemStatus = OrchestratorInventoryItemStatus
                    .Unknown, //There are other statuses, but Command can determine how to handle new vs modified certificates
                Alias = "",
                PrivateKeyEntry =
                    hasPrivateKey, //You will not pass the private key back, but you can identify if the main certificate of the chain contains a private key in the store
                UseChainLevel =
                    true, //true if Certificates will contain > 1 certificate, main cert => intermediate CA cert => root CA cert.  false if Certificates will contain an array of 1 certificate
                Certificates =
                    certificates //Array of single X509 certificates in Base64 string format (certificates if chain, single cert if not), something like:
            });
            break;
        }

        try
        {
            Logger.LogDebug("Submitting inventoryItems to Keyfactor Command...");
            //Sends inventoried certificates back to KF Command
            submitInventory.Invoke(inventoryItems);
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogInformation("End INVENTORY completed successfully for job id '{JobId}'", jobId);
            return SuccessJob(jobId, jobMessage);
        }
        catch (Exception ex)
        {
            // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
            //  may not be reflected in Keyfactor Command.
            Logger.LogError("Unable to submit inventory to Keyfactor Command for job id '{JobId}'", jobId);
            Logger.LogError("{Message}", ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job {JobId} with failure", jobId);
            return FailJob(ex.Message, jobId);
        }
    }

    private JobResult PushInventory(Dictionary<string, string> certsList, long jobId,
        SubmitInventoryUpdate submitInventory, bool hasPrivateKey = false)
    {
        Logger.LogDebug("Entering PushInventory for job id '{JobId}'", jobId);
        Logger.LogTrace("submitInventory: {Inv}", submitInventory);
        Logger.LogTrace("certsList: {Certs}", certsList);
        var inventoryItems = new List<CurrentInventoryItem>();
        foreach (var (alias, cert) in certsList)
        {
            Logger.LogTrace("Cert:\n{Cert}", cert);
            // load as x509
            Logger.LogDebug("Cert alias: {Alias}", alias);

            if (string.IsNullOrEmpty(cert))
            {
                Logger.LogWarning(
                    "Kubernetes returned an empty inventory for store {KubeSecretName} in namespace {KubeNamespace} on host {HostName}",
                    KubeSecretName, KubeNamespace, K8SHostName);
                continue;
            }

            try
            {
                Logger.LogDebug("Attempting to load cert '{Alias}' as X509Certificate2", alias);
                var certFormatted = cert.Contains("BEGIN CERTIFICATE")
                    ? new X509Certificate2(Encoding.UTF8.GetBytes(cert))
                    : new X509Certificate2(Convert.FromBase64String(cert));
                Logger.LogDebug("Cert loaded as X509Certificate2: {Alias}", alias);
                Logger.LogTrace("Formatted X509Certificate2:\n{Formatted}", certFormatted);
            }
            catch (Exception e)
            {
                Logger.LogError("Unable to load certificate '{Alias}' as X509Certificate2, this will not ", alias);
                Logger.LogError("{Message}", e.Message);
                Logger.LogTrace("{Message}", e.ToString());
                continue;
            }

            var certs = new[] { cert };
            Logger.LogDebug("Adding cert to inventoryItems");
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
            Logger.LogDebug("Submitting inventoryItems to Keyfactor Command");
            Logger.LogTrace("InventoryItems: {Items}", inventoryItems.ToString());
            //Sends inventoried certificates back to KF Command
            submitInventory.Invoke(inventoryItems);
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogInformation("End INVENTORY completed successfully for job id '{JobId}'", jobId);
            return SuccessJob(jobId);
        }
        catch (Exception ex)
        {
            // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
            //  may not be reflected in Keyfactor Command.
            Logger.LogError("Unable to submit inventory to Keyfactor Command for job id '{JobId}'", jobId);
            Logger.LogError("{Message}", ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job {JobId} with failure", jobId);
            return FailJob(ex.Message, jobId);
        }
    }

    private JobResult PushInventory(Dictionary<string, List<string>> certsList, long jobId,
        SubmitInventoryUpdate submitInventory, bool hasPrivateKey = false)
    {
        Logger.LogDebug("Entering PushInventory for job id '{JobId}'", jobId);
        Logger.LogTrace("submitInventory: {Inv}", submitInventory);
        Logger.LogTrace("certsList: {Certs}", certsList);
        var inventoryItems = new List<CurrentInventoryItem>();
        foreach (var (alias, certs) in certsList)
        {
            // load as x509
            Logger.LogDebug("Cert alias: {Alias}", alias);

            if (certs.Count == 0)
            {
                Logger.LogWarning(
                    "Kubernetes returned an empty inventory for store {KubeSecretName} in namespace {KubeNamespace} on host {HostName}",
                    KubeSecretName, KubeNamespace, K8SHostName);
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
}