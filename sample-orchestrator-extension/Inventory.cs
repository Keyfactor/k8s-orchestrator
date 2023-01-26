// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Common.Enums;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.Orchestrator.Kube;

// The Inventory class implements IAgentJobExtension and is meant to find all of the certificates in a given certificate store on a given server
//  and return those certificates back to Keyfactor for storing in its database.  Private keys will NOT be passed back to Keyfactor Command 
public class Inventory : IInventoryJobExtension
{
    private static readonly string[] SupportedKubeStoreTypes = { "secret", "certificate" };
    private static readonly string[] RequiredProperties = { "kube_namespace", "kube_secret_name", "kube_secret_type", "kube_svc_creds" };

    public class KubernetesCertStore
    {
        public string KubeNamespace { get; set; } = "";

        public string KubeSecretName { get; set; } = "";

        public string KubeSecretType { get; set; } = "";

        public string KubeSvcCreds { get; set; } = "";

        public Cert[] Certs { get; set; }
    }

    public class KubeCreds
    {
        public string KubeServer { get; set; } = "";

        public string KubeToken { get; set; } = "";

        public string KubeCert { get; set; } = "";
    }

    public class Cert
    {
        public string Alias { get; set; } = "";

        public string CertData { get; set; } = "";

        public string PrivateKey { get; set; } = "";

    }

    //Necessary to implement IInventoryJobExtension but not used.  Leave as empty string.
    // public string ExtensionName => "Kubernetes";
    public string ExtensionName => "Kube";

    public static string CertChainSeparator = ",";

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
        var logger = LogHandler.GetClassLogger(GetType());
        logger.LogDebug($"Begin Inventory...");

        logger.LogDebug($"Following info received from command:");
        logger.LogDebug(JsonConvert.SerializeObject(config));

        var storepath = config.CertificateStoreDetails.StorePath;
        var properties = config.CertificateStoreDetails.Properties;
        var storepassword = config.CertificateStoreDetails.StorePassword;

        logger.LogDebug($"Begin {config.Capability} for job id {config.JobId.ToString()}...");
        logger.LogInformation($"Processing store path: {storepath}");
        logger.LogTrace($"Store properties: {properties}");
        logger.LogTrace($"Store password: {storepassword}"); // TODO: Remove this before production
        logger.LogDebug($"Server: {config.CertificateStoreDetails.ClientMachine}");
        logger.LogDebug($"Store Path: {config.CertificateStoreDetails.StorePath}");
        logger.LogDebug($"Job Properties:");
        foreach (var keyValue in config.JobProperties ?? new Dictionary<string, object>())
        {
            logger.LogDebug($"    {keyValue.Key}: {keyValue.Value}");
        }

        //List<AgentCertStoreInventoryItem> is the collection that the interface expects to return from this job.  It will contain a collection of certificates found in the store along with other information about those certificates
        var inventoryItems = new List<CurrentInventoryItem>();

        try
        {
            //Code logic to:
            // 1) Connect to the orchestrated server (config.CertificateStoreDetails.ClientMachine) containing the certificate store to be inventoried (config.CertificateStoreDetails.StorePath)

            // 2) Custom logic to retrieve certificates from certificate store.
            // read file into a string and deserialize JSON to a type
            // string storetypename = "Kubernetes";

            // Load credentials file from localCertStore.KubeSvcCreds // TODO: Implement config passed from store params or password input
            // var kubeCreds = JsonConvert.DeserializeObject<KubeCreds>(File.ReadAllText(localCertStore.KubeSvcCreds));
            var c = new KubeCertificateManagerClient("", "default");

            if (config.CertificateStoreDetails.Properties != "")
            {
                var localCertStore = JsonConvert.DeserializeObject<KubernetesCertStore>(config.CertificateStoreDetails.Properties);
                logger.LogDebug($"KubernetesCertStore: {localCertStore}");
                logger.LogDebug($"KubernetesCertStore: {localCertStore.KubeNamespace}");
                logger.LogDebug($"KubernetesCertStore: {localCertStore.KubeSecretName}");
                logger.LogDebug($"KubernetesCertStore: {localCertStore.KubeSecretType}");
                logger.LogTrace($"KubernetesCertStore: {localCertStore.KubeSvcCreds}");
                logger.LogTrace($"KubernetesCertStore: {localCertStore.Certs}");

                var hasPrivateKey = false;
                // TODO: What is _resolver?
                // string userName = PAMUtilities.ResolvePAMField(_resolver, logger, "Server User Name", config.ServerUsername);
                // string userPassword = PAMUtilities.ResolvePAMField(_resolver, logger, "Server Password", config.ServerPassword);
                // string storePassword = PAMUtilities.ResolvePAMField(_resolver, logger, "Store Password", config.CertificateStoreDetails.StorePassword);

                switch (localCertStore.KubeSecretType)
                {
                    case "secret":
                        // To prevents the screen from 
                        // running and closing quickly
                        // Console.ReadKey();
                        logger.LogDebug(
                            $"Querying Kubernetes {localCertStore.KubeSecretType} API for {localCertStore.KubeSecretName} in namespace {localCertStore.KubeNamespace}");
                        try
                        {
                            var certData = c.GetCertificateStoreSecret(
                                localCertStore.KubeSecretName,
                                localCertStore.KubeNamespace
                            );
                            var certificatesBytes = certData.Data["certificates"];
                            var certificates = Encoding.UTF8.GetString(certificatesBytes);
                            var certsList = certificates.Split(CertChainSeparator);
                            foreach (var cert in certsList)
                            {
                                logger.LogInformation(cert);
                                // load as x509
                                string alias;
                                try
                                {
                                    var certFormatted = cert.Contains("BEGIN CERTIFICATE")
                                        ? new X509Certificate2(Encoding.UTF8.GetBytes(cert))
                                        : new X509Certificate2(Convert.FromBase64String(cert));
                                    alias = certFormatted.Thumbprint;
                                }
                                catch (Exception e)
                                {
                                    logger.LogError(e.Message);
                                    return new JobResult()
                                    {
                                        Result = OrchestratorJobStatusJobResult.Failure,
                                        JobHistoryId = config.JobHistoryId,
                                        FailureMessage = e.Message
                                    };
                                }


                                string[] certs = { cert };
                                inventoryItems.Add(new CurrentInventoryItem()
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
                                return new JobResult() { Result = OrchestratorJobStatusJobResult.Success, JobHistoryId = config.JobHistoryId };
                            }
                            catch (Exception ex)
                            {
                                // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
                                //  may not be reflected in Keyfactor Command.
                                return new JobResult()
                                {
                                    Result = OrchestratorJobStatusJobResult.Failure, JobHistoryId = config.JobHistoryId,
                                    FailureMessage = ex.Message
                                };
                            }
                        }
                        catch (k8s.Autorest.HttpOperationException e)
                        {
                            logger.LogError(e.Message);
                            var certDataErrorMsg =
                                $"Kubernetes {localCertStore.KubeSecretType} '{localCertStore.KubeSecretName}' was not found in namespace '{localCertStore.KubeNamespace}'.";
                            logger.LogError(certDataErrorMsg);
                            return new JobResult()
                            {
                                Result = OrchestratorJobStatusJobResult.Failure,
                                JobHistoryId = config.JobHistoryId,
                                FailureMessage = certDataErrorMsg
                            };
                        }
                        catch (Exception e)
                        {
                            logger.LogError(e.Message);
                            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
                            logger.LogError(certDataErrorMsg);
                            return new JobResult()
                            {
                                Result = OrchestratorJobStatusJobResult.Failure,
                                JobHistoryId = config.JobHistoryId,
                                FailureMessage = certDataErrorMsg
                            };
                        }

                    // 3) Add certificates (no private keys) to the collection below.  If multiple certs in a store comprise a chain, the Certificates array will house multiple certs per InventoryItem.  If multiple certs
                    //     in a store comprise separate unrelated certs, there will be one InventoryItem object created per certificate.

                    //**** Will need to uncomment the block below and code to the extension's specific needs.  This builds the collection of certificates and related information that will be passed back to the KF Orchestrator service and then Command.
                    case "tls_secret":
                        logger.LogDebug(
                            $"Querying Kubernetes {localCertStore.KubeSecretType} API for {localCertStore.KubeSecretName} in namespace {localCertStore.KubeNamespace}");
                        try
                        {
                            hasPrivateKey = true;
                            var certData = c.GetCertificateStoreSecret(
                                localCertStore.KubeSecretName,
                                localCertStore.KubeNamespace
                            );
                            var certificatesBytes = certData.Data["tls.crt"];
                            var privateKeyBytes = certData.Data["tls.key"];
                            if (privateKeyBytes == null)
                            {
                                hasPrivateKey = false;
                            }
                            var certificates = Encoding.UTF8.GetString(certificatesBytes);
                            var certsList = certificates.Split(CertChainSeparator);
                            foreach (var cert in certsList)
                            {
                                logger.LogInformation(cert);
                                // load as x509
                                string alias;
                                try
                                {
                                    var certFormatted = cert.Contains("BEGIN CERTIFICATE")
                                        ? new X509Certificate2(Encoding.UTF8.GetBytes(cert))
                                        : new X509Certificate2(Convert.FromBase64String(cert));
                                    alias = certFormatted.Thumbprint;
                                }
                                catch (Exception e)
                                {
                                    logger.LogError(e.Message);
                                    return new JobResult()
                                    {
                                        Result = OrchestratorJobStatusJobResult.Failure,
                                        JobHistoryId = config.JobHistoryId,
                                        FailureMessage = e.Message
                                    };
                                }


                                string[] certs = { cert };
                                inventoryItems.Add(new CurrentInventoryItem()
                                {
                                    ItemStatus = OrchestratorInventoryItemStatus
                                        .Unknown, //There are other statuses, but Command can determine how to handle new vs modified certificates
                                    Alias = alias,
                                    PrivateKeyEntry =
                                        hasPrivateKey, //You will not pass the private key back, but you can identify if the main certificate of the chain contains a private key in the store
                                    UseChainLevel =
                                        false, //true if Certificates will contain > 1 certificate, main cert => intermediate CA cert => root CA cert.  false if Certificates will contain an array of 1 certificate
                                    Certificates =
                                        certs //Array of single X509 certificates in Base64 string format (certificates if chain, single cert if not), something like:
                                });
                            }
                            try
                            {
                                //Sends inventoried certificates back to KF Command
                                submitInventory.Invoke(inventoryItems);
                                //Status: 2=Success, 3=Warning, 4=Error
                                return new JobResult() { Result = OrchestratorJobStatusJobResult.Success, JobHistoryId = config.JobHistoryId };
                            }
                            catch (Exception ex)
                            {
                                // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
                                //  may not be reflected in Keyfactor Command.
                                return new JobResult()
                                {
                                    Result = OrchestratorJobStatusJobResult.Failure, JobHistoryId = config.JobHistoryId,
                                    FailureMessage = ex.Message
                                };
                            }
                        }
                        catch (k8s.Autorest.HttpOperationException e)
                        {
                            logger.LogError(e.Message);
                            var certDataErrorMsg =
                                $"Kubernetes {localCertStore.KubeSecretType} '{localCertStore.KubeSecretName}' was not found in namespace '{localCertStore.KubeNamespace}'.";
                            logger.LogError(certDataErrorMsg);
                            return new JobResult()
                            {
                                Result = OrchestratorJobStatusJobResult.Failure,
                                JobHistoryId = config.JobHistoryId,
                                FailureMessage = certDataErrorMsg
                            };
                        }
                        catch (Exception e)
                        {
                            logger.LogError(e.Message);
                            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
                            logger.LogError(certDataErrorMsg);
                            return new JobResult()
                            {
                                Result = OrchestratorJobStatusJobResult.Failure,
                                JobHistoryId = config.JobHistoryId,
                                FailureMessage = certDataErrorMsg
                            };
                        }
                    case "certificate":
                        logger.LogError("Certificate type not implemented yet...");
                        return new JobResult()
                        {
                            Result = OrchestratorJobStatusJobResult.Failure,
                            JobHistoryId = config.JobHistoryId,
                            FailureMessage = $"kube_secret_type: {localCertStore.KubeSecretType} not implemented yet..."
                        };
                    default:
                        var errorMsg = $"{localCertStore.KubeSecretType} not supported.";
                        logger.LogError(errorMsg);
                        return new JobResult()
                        {
                            Result = OrchestratorJobStatusJobResult.Failure,
                            JobHistoryId = config.JobHistoryId,
                            FailureMessage = errorMsg
                        };
                }
            }
            else
            {
                return new JobResult()
                {
                    Result = OrchestratorJobStatusJobResult.Failure,
                    JobHistoryId = config.JobHistoryId,
                    FailureMessage =
                        $"Invalid configuration. A KubernetesCertStore type must have addition properties: {string.Join(", ", RequiredProperties)}, {string.Join(", ", SupportedKubeStoreTypes)}"
                };
            }

        }
        catch (Exception ex)
        {
            //Status: 2=Success, 3=Warning, 4=Error
            return new JobResult()
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = ex.ToString()
            };
        }
    }
}
