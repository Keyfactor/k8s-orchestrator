// Copyright 2023 Keyfactor
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
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

// The Inventory class implements IAgentJobExtension and is meant to find all of the certificates in a given certificate store on a given server
//  and return those certificates back to Keyfactor for storing in its database.  Private keys will NOT be passed back to Keyfactor Command 
public class Inventory : JobBase, IInventoryJobExtension
{
    public Inventory(IPAMSecretResolver resolver)
    {
        Resolver = resolver;
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
        InitializeStore(config);
        Logger.LogDebug("Begin Inventory...");

        Logger.LogDebug($"Begin {config.Capability} for job id {config.JobId.ToString()}...");
        Logger.LogTrace($"Server: {KubeClient.GetHost()}");
        Logger.LogTrace($"Store Path: {StorePath}");

        try
        {

            var hasPrivateKey = false;

            switch (KubeSecretType)
            {
                case "secret":
                case "secrets":
                    var secretAllowedKeys = new[] { "tls.crts", "cert", "certs", "certificate", "certificates", "crt", "crts", "ca.crt", "tls.crt", "tls.key" };
                    return HandleOpaqueSecret(config.JobHistoryId, submitInventory, secretAllowedKeys);
                case "tls_secret":
                case "tls":
                case "tlssecret":
                case "tls_secrets":
                    return HandleTlsSecret(config.JobHistoryId, submitInventory);
                case "certificate":
                case "cert":
                case "csr":
                case "csrs":
                case "certs":
                case "certificates":
                    return HandleCertificate(config.JobHistoryId, submitInventory);
                default:
                    var errorMsg = $"{KubeSecretType} not supported.";
                    Logger.LogError(errorMsg);
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
            //Status: 2=Success, 3=Warning, 4=Error
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = ex.ToString()
            };
        }
    }

    private JobResult HandleCertificate(long jobId, SubmitInventoryUpdate submitInventory)
    {
        const bool hasPrivateKey = false;
        try
        {
            var certificates = KubeClient.GetCertificateSigningRequestStatus(KubeSecretName);
            return PushInventory(certificates, jobId, submitInventory);
        }
        catch (HttpOperationException e)
        {
            Logger.LogError(e.Message);
            var certDataErrorMsg =
                $"Kubernetes {KubeSecretType} '{KubeSecretName}' was not found in namespace '{KubeNamespace}'.";
            Logger.LogError(certDataErrorMsg);
            return FailJob(certDataErrorMsg, jobId);
        }
        catch (Exception e)
        {
            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
            Logger.LogError(certDataErrorMsg);
            return FailJob(certDataErrorMsg, jobId);
        }
    }

    private JobResult PushInventory(IEnumerable<string> certsList, long jobId, SubmitInventoryUpdate submitInventory, bool hasPrivateKey = false)
    {
        var inventoryItems = new List<CurrentInventoryItem>();
        foreach (var cert in certsList)
        {
            Logger.LogTrace($"Cert:\n{cert}");
            // load as x509
            string alias;
            if (string.IsNullOrEmpty(cert))
            {
                Logger.LogInformation($"Kubernetes returned an empty inventory for store {KubeSecretName}");
                continue;
            }
            try
            {
                var certFormatted = cert.Contains("BEGIN CERTIFICATE")
                    ? new X509Certificate2(Encoding.UTF8.GetBytes(cert))
                    : new X509Certificate2(Convert.FromBase64String(cert));
                alias = certFormatted.Thumbprint;
            }
            catch (Exception e)
            {
                Logger.LogError(e.Message);
                return FailJob(e.Message, jobId);
            }

            var certs = new[] { cert };
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
            //Sends inventoried certificates back to KF Command
            submitInventory.Invoke(inventoryItems);
            //Status: 2=Success, 3=Warning, 4=Error
            return SuccessJob(jobId);
        }
        catch (Exception ex)
        {
            // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
            //  may not be reflected in Keyfactor Command.
            return FailJob(ex.Message, jobId);
        }
    }

    private JobResult HandleOpaqueSecret(long jobId, SubmitInventoryUpdate submitInventory, string [] secretAllowedKeys)
    {
        const bool hasPrivateKey = true;
        //check if secretAllowedKeys is null or empty
        if (secretAllowedKeys == null || secretAllowedKeys.Length == 0)
        {
            secretAllowedKeys = new[] { "certificates" };
        }

        Logger.LogDebug(
            $"Querying Kubernetes {KubeSecretType} API for {KubeSecretName} in namespace {KubeNamespace}");
        try
        {
            var certData = KubeClient.GetCertificateStoreSecret(
                KubeSecretName,
                KubeNamespace
            );
            var certsList = new string[]{}; //empty array
            foreach (var allowedKey in secretAllowedKeys)
            {
                if (certData.Data.ContainsKey(allowedKey))
                {
                    var certificatesBytes = certData.Data[allowedKey];
                    var certificates = Encoding.UTF8.GetString(certificatesBytes);
                    //split the certificates by the separator
                    var splitCerts = certificates.Split(CertChainSeparator);
                    //add the split certs to the list
                    certsList = certsList.Concat(splitCerts).ToArray();
                    // certsList.Concat(certificates.Split(CertChainSeparator));
                }
            }
            return PushInventory(certsList, jobId, submitInventory, hasPrivateKey);
            
        }
        catch (HttpOperationException e)
        {
            Logger.LogError(e.Message);
            var certDataErrorMsg =
                $"Kubernetes {KubeSecretType} '{KubeSecretName}' was not found in namespace '{KubeNamespace}'.";
            Logger.LogError(certDataErrorMsg);
            return FailJob(certDataErrorMsg, jobId);
        }
        catch (Exception e)
        {
            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
            Logger.LogError(certDataErrorMsg);
            return FailJob(certDataErrorMsg, jobId);
        }
    }

    private JobResult HandleTlsSecret(long jobId, SubmitInventoryUpdate submitInventory)
    {
        if (string.IsNullOrEmpty(KubeNamespace))
        {
            if (!string.IsNullOrEmpty(StorePath))
            {
                KubeNamespace = StorePath.Split("/").First();
                if (KubeNamespace == KubeSecretName)
                {
                    KubeNamespace = "default";
                }
            }
            else
            {
                KubeNamespace = "default";                
            }
        }

        if (string.IsNullOrEmpty(KubeSecretName) && !string.IsNullOrEmpty(StorePath))
        {
            KubeSecretName = StorePath.Split("/").Last();
        }
        
        Logger.LogDebug(
            $"Querying Kubernetes {KubeSecretType} API for {KubeSecretName} in namespace {KubeNamespace}");
        var hasPrivateKey = true;
        try
        {
            var certData = KubeClient.GetCertificateStoreSecret(
                KubeSecretName,
                KubeNamespace
            );
            var certificatesBytes = certData.Data["tls.crt"];
            var privateKeyBytes = certData.Data["tls.key"];
            if (privateKeyBytes == null)
            {
                hasPrivateKey = false;
            }
            var certificates = Encoding.UTF8.GetString(certificatesBytes);
            var certsList = certificates.Split(CertChainSeparator);
            return PushInventory(certsList, jobId, submitInventory, hasPrivateKey);
        }
        catch (HttpOperationException e)
        {
            Logger.LogError(e.Message);
            var certDataErrorMsg =
                $"Kubernetes {KubeSecretType} '{KubeSecretName}' was not found in namespace '{KubeNamespace}'.";
            Logger.LogError(certDataErrorMsg);
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = jobId,
                FailureMessage = certDataErrorMsg
            };
        }
        catch (Exception e)
        {
            Logger.LogError(e.Message);
            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
            Logger.LogError(certDataErrorMsg);
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = jobId,
                FailureMessage = certDataErrorMsg
            };
        }
    }
}
