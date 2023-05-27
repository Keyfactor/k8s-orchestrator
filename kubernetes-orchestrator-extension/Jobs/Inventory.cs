// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using k8s.Autorest;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.RemoteFile.JKS;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.PKI.PrivateKeys;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;

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
        Logger.LogInformation("Begin INVENTORY for K8S Orchestrator Extension for job " + config.JobId);
        Logger.LogInformation($"Inventory for store type: {config.Capability}");

        Logger.LogDebug($"Server: {KubeClient.GetHost()}");
        Logger.LogDebug($"Store Path: {StorePath}");
        Logger.LogDebug("KubeSecretType: " + KubeSecretType);
        Logger.LogDebug("KubeSecretName: " + KubeSecretName);
        Logger.LogDebug("KubeNamespace: " + KubeNamespace);
        Logger.LogDebug("Host: " + KubeClient.GetHost());

        Logger.LogTrace("Inventory entering switch based on KubeSecretType: " + KubeSecretType + "...");
        try
        {
            var hasPrivateKey = false;
            Logger.LogTrace("Inventory entering switch based on KubeSecretType: " + KubeSecretType + "...");

            if (Capability.Contains("Cluster"))
            {
                KubeSecretType = "cluster";
            }
            if (Capability.Contains("NS"))
            {
                KubeSecretType = "namespace";
            }

            switch (KubeSecretType)
            {
                case "secret":
                case "secrets":
                case "opaque":
                    Logger.LogInformation("Inventorying opaque secrets using " + OpaqueAllowedKeys);
                    return HandleOpaqueSecret(config.JobHistoryId, submitInventory, OpaqueAllowedKeys);
                case "tls_secret":
                case "tls":
                case "tlssecret":
                case "tls_secrets":
                    Logger.LogInformation("Inventorying TLS secrets using " + TLSAllowedKeys);
                    var tlsCertsInv = HandleTlsSecret(config.JobHistoryId, submitInventory);
                    return PushInventory(tlsCertsInv, config.JobHistoryId, submitInventory, true);
                case "certificate":
                case "cert":
                case "csr":
                case "csrs":
                case "certs":
                case "certificates":
                    Logger.LogInformation("Inventorying certificates using " + CertAllowedKeys);
                    return HandleCertificate(config.JobHistoryId, submitInventory);
                case "pkcs12":
                case "p12":
                case "pfx":
                    Logger.LogInformation("Inventorying PKCS12 using " + Pkcs12AllowedKeys);
                    return HandlePkcs12Secret(config.JobHistoryId, submitInventory);
                case "jks":
                    var jksInventory = HandleJKSSecret(config);
                    
                    return PushInventory(jksInventory, config.JobHistoryId, submitInventory, true);

                case "cluster":
                    var clusterOpaqueSecrets = KubeClient.DiscoverSecrets(OpaqueAllowedKeys, "Opaque", "all", false);
                    var clusterTlsSecrets = KubeClient.DiscoverSecrets(TLSAllowedKeys, "tls", "all", false);
                    var errors = new List<string>();

                    Dictionary<string, string> clusterInventoryDict = new Dictionary<string, string>();
                    foreach (var opaqueSecret in clusterOpaqueSecrets)
                    {
                        KubeSecretName = "";
                        KubeNamespace = "";
                        KubeSecretType = "secret";
                        try
                        {
                            resolveStorePath(opaqueSecret);
                            StorePath = opaqueSecret.Replace("secrets", "secrets/opaque");
                            //Split storepath by / and remove first 1 elements
                            var storePathSplit = StorePath.Split('/');
                            var storePathSplitList = storePathSplit.ToList();
                            storePathSplitList.RemoveAt(0);
                            StorePath = string.Join("/", storePathSplitList);

                            var opaqueObj = HandleTlsSecret(config.JobHistoryId, submitInventory);
                            clusterInventoryDict[StorePath] = opaqueObj[0]; //todo: fix this    
                        }
                        catch (Exception ex)
                        {
                            Logger.LogError("Error processing TLS Secret: " + opaqueSecret + " - " + ex.Message + "\n\t" + ex.StackTrace);
                            errors.Add(ex.Message);
                        }

                    }

                    foreach (var tlsSecret in clusterTlsSecrets)
                    {
                        KubeSecretName = "";
                        KubeNamespace = "";
                        KubeSecretType = "tls_secret";
                        try
                        {
                            resolveStorePath(tlsSecret);
                            StorePath = tlsSecret.Replace("secrets", "secrets/tls");
                            //Split storepath by / and remove first 1 elements
                            var storePathSplit = StorePath.Split('/');
                            var storePathSplitList = storePathSplit.ToList();
                            storePathSplitList.RemoveAt(0);
                            StorePath = string.Join("/", storePathSplitList);

                            var tlsObj = HandleTlsSecret(config.JobHistoryId, submitInventory);
                            clusterInventoryDict[StorePath] = tlsObj[0]; //todo: fix this  
                        }
                        catch (Exception ex)
                        {
                            Logger.LogError("Error processing TLS Secret: " + tlsSecret + " - " + ex.Message + "\n\t" + ex.StackTrace);
                            errors.Add(ex.Message);
                        }

                    }

                    return PushInventory(clusterInventoryDict, config.JobHistoryId, submitInventory, true);
                case "namespace":
                    var namespaceOpaqueSecrets = KubeClient.DiscoverSecrets(OpaqueAllowedKeys, "Opaque", KubeNamespace, false);
                    var namespaceTlsSecrets = KubeClient.DiscoverSecrets(TLSAllowedKeys, "tls", KubeNamespace, false);
                    var namespaceErrors = new List<string>();

                    Dictionary<string, string> namespaceInventoryDict = new Dictionary<string, string>();
                    foreach (var opaqueSecret in namespaceOpaqueSecrets)
                    {
                        KubeSecretName = "";
                        // KubeNamespace = "";
                        KubeSecretType = "secret";
                        try
                        {
                            resolveStorePath(opaqueSecret);
                            StorePath = opaqueSecret.Replace("secrets", "secrets/opaque");
                            //Split storepath by / and remove first 2 elements
                            var storePathSplit = StorePath.Split('/');
                            var storePathSplitList = storePathSplit.ToList();
                            storePathSplitList.RemoveAt(0);
                            storePathSplitList.RemoveAt(0);
                            StorePath = string.Join("/", storePathSplitList);

                            var opaqueObj = HandleTlsSecret(config.JobHistoryId, submitInventory);
                            namespaceInventoryDict[StorePath] = opaqueObj[0]; //todo: fix this    
                        }
                        catch (Exception ex)
                        {
                            Logger.LogError("Error processing TLS Secret: " + opaqueSecret + " - " + ex.Message + "\n\t" + ex.StackTrace);
                            namespaceErrors.Add(ex.Message);
                        }

                    }

                    foreach (var tlsSecret in namespaceTlsSecrets)
                    {
                        KubeSecretName = "";
                        // KubeNamespace = "";
                        KubeSecretType = "tls_secret";
                        try
                        {
                            resolveStorePath(tlsSecret);
                            StorePath = tlsSecret.Replace("secrets", "secrets/tls");

                            //Split storepath by / and remove first 2 elements
                            var storePathSplit = StorePath.Split('/');
                            var storePathSplitList = storePathSplit.ToList();
                            storePathSplitList.RemoveAt(0);
                            storePathSplitList.RemoveAt(0);
                            StorePath = string.Join("/", storePathSplitList);


                            var tlsObj = HandleTlsSecret(config.JobHistoryId, submitInventory);
                            namespaceInventoryDict[StorePath] = tlsObj[0]; //todo: fix this  
                        }
                        catch (Exception ex)
                        {
                            Logger.LogError("Error processing TLS Secret: " + tlsSecret + " - " + ex.Message + "\n\t" + ex.StackTrace);
                            namespaceErrors.Add(ex.Message);
                        }

                    }

                    return PushInventory(namespaceInventoryDict, config.JobHistoryId, submitInventory, true);

                default:
                    Logger.LogError("Inventory failed with exception: " + KubeSecretType + " not supported.");
                    var errorMsg = $"{KubeSecretType} not supported.";
                    Logger.LogError(errorMsg);
                    Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + config.JobId + " with failure.");
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
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + config.JobId + " with failure.");
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = ex.ToString()
            };
        }
    } 
    private Dictionary<string,string> HandleJKSSecret(InventoryJobConfiguration config)
    {
        var hasPrivateKeyJks = false;
        var jksStore = new JKSCertificateStoreSerializer(config.JobProperties?.ToString());
        //getJksBytesFromKubeSecret
        var k8sData = KubeClient.GetJKSSecret(KubeSecretName, KubeNamespace);
        

        Dictionary<string, string> jksInventoryDict = new Dictionary<string, string>();
        // iterate through the keys in the secret and add them to the jks store
        foreach (var jStore in k8sData.JksInventory)
        {
            var keyName = jStore.Key;
            var keyBytes = jStore.Value;
            var keyPassword = getK8SStorePassword(k8sData.Secret);
            var keyAlias = keyName;
            var jStoreDs = jksStore.DeserializeRemoteCertificateStore(keyBytes, keyName, keyPassword);
            // create a list of certificate chains in PEM format
            
            foreach (var certAlias in jStoreDs.Aliases)
            {
                var certChainList = new List<string>();
                var certChain = jStoreDs.GetCertificateChain(certAlias);
                var certChainPem = new StringBuilder();
                var fullAlias = keyAlias + "/" + certAlias;
                //check if the alias is a private key
                if (jStoreDs.IsKeyEntry(certAlias))
                {
                    hasPrivateKeyJks = true;
                }
                var pKey = jStoreDs.GetKey(certAlias);
                if (pKey != null)
                {
                    hasPrivateKeyJks = true;
                }
               
                var leaf = jStoreDs.GetCertificate(certAlias);
                if (leaf != null)
                {
                    certChainPem.AppendLine("-----BEGIN CERTIFICATE-----");
                    certChainPem.AppendLine(Convert.ToBase64String(leaf.Certificate.GetEncoded()));
                    certChainPem.AppendLine("-----END CERTIFICATE-----");
                    certChainList.Add(certChainPem.ToString());
                }
                 
                if (certChain == null)
                {
                    jksInventoryDict[fullAlias] = string.Join("", certChainList);
                    continue;
                }
                
                foreach (var cert in certChain)
                {
                    certChainPem.AppendLine("-----BEGIN CERTIFICATE-----");
                    certChainPem.AppendLine(Convert.ToBase64String(cert.Certificate.GetEncoded()));
                    certChainPem.AppendLine("-----END CERTIFICATE-----");
                }
                // certChainList.Add(certChainPem.ToString());
                
                jksInventoryDict[fullAlias] = string.Join("", certChainList);
            }
            // add the certificate chain to the inventory
            // jksInventoryDict[keyAlias] = string.Join("", certChainList);
        }
        return jksInventoryDict;
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

    private JobResult PushInventory(IEnumerable<string> certsList, long jobId, SubmitInventoryUpdate submitInventory, bool hasPrivateKey = false)
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
                Logger.LogWarning($"Kubernetes returned an empty inventory for store {KubeSecretName} in namespace {KubeNamespace} on host {KubeClient.GetHost()}.");
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
                Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
                return FailJob(e.Message, jobId);
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

    private JobResult PushInventory(Dictionary<string, string> certsList, long jobId, SubmitInventoryUpdate submitInventory, bool hasPrivateKey = false)
    {
        Logger.LogDebug("Entering PushInventory for job id " + jobId + "...");
        Logger.LogTrace("submitInventory: " + submitInventory);
        Logger.LogTrace("certsList: " + certsList);
        var inventoryItems = new List<CurrentInventoryItem>();
        foreach (KeyValuePair<string, string> certObj in certsList)
        {
            var cert = certObj.Value;
            Logger.LogTrace($"Cert:\n{cert}");
            // load as x509
            string alias = certObj.Key;
            Logger.LogDebug("Cert alias: " + alias);

            if (string.IsNullOrEmpty(cert))
            {
                Logger.LogWarning($"Kubernetes returned an empty inventory for store {KubeSecretName} in namespace {KubeNamespace} on host {KubeClient.GetHost()}.");
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
                Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
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

    private JobResult HandleOpaqueSecret(long jobId, SubmitInventoryUpdate submitInventory, string[] secretManagedKeys, string secretPath = "")
    {
        Logger.LogDebug("Inventory entering HandleOpaqueSecret for job id " + jobId + "...");
        const bool hasPrivateKey = true;
        //check if secretAllowedKeys is null or empty
        if (secretManagedKeys == null || secretManagedKeys.Length == 0)
        {
            secretManagedKeys = new[] { "certificates" };
        }
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
                if (certData.Data.ContainsKey(managedKey))
                {
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


    private List<string> HandleTlsSecret(long jobId, SubmitInventoryUpdate submitInventory)
    {
        Logger.LogDebug("Inventory entering HandleTlsSecret for job id " + jobId + "...");
        Logger.LogTrace("KubeNamespace: " + KubeNamespace);
        Logger.LogTrace("KubeSecretName: " + KubeSecretName);
        Logger.LogTrace("StorePath: " + StorePath);

        if (string.IsNullOrEmpty(KubeNamespace))
        {
            Logger.LogWarning("KubeNamespace is null or empty.  Attempting to parse from StorePath...");
            if (!string.IsNullOrEmpty(StorePath))
            {
                Logger.LogTrace("StorePath was not null or empty.  Parsing KubeNamespace from StorePath...");
                KubeNamespace = StorePath.Split("/").First();
                Logger.LogTrace("KubeNamespace: " + KubeNamespace);
                if (KubeNamespace == KubeSecretName)
                {
                    Logger.LogWarning("KubeNamespace was equal to KubeSecretName.  Setting KubeNamespace to 'default' for job id " + jobId + "...");
                    KubeNamespace = "default";
                }
            }
            else
            {
                Logger.LogWarning("StorePath was null or empty.  Setting KubeNamespace to 'default' for job id " + jobId + "...");
                KubeNamespace = "default";
            }
        }

        if (string.IsNullOrEmpty(KubeSecretName) && !string.IsNullOrEmpty(StorePath))
        {
            Logger.LogWarning("KubeSecretName is null or empty.  Attempting to parse from StorePath...");
            KubeSecretName = StorePath.Split("/").Last();
            Logger.LogTrace("KubeSecretName: " + KubeSecretName);
        }

        Logger.LogDebug(
            $"Querying Kubernetes {KubeSecretType} API for {KubeSecretName} in namespace {KubeNamespace} on host {KubeClient.GetHost()}...");
        var hasPrivateKey = true;
        Logger.LogTrace("Entering try block for HandleTlsSecret...");
        try
        {
            Logger.LogTrace("Calling KubeClient.GetCertificateStoreSecret()...");
            var certData = KubeClient.GetCertificateStoreSecret(
                KubeSecretName,
                KubeNamespace
            );
            Logger.LogDebug("KubeClient.GetCertificateStoreSecret() returned successfully.");
            Logger.LogTrace("certData: " + certData);
            var certificatesBytes = certData.Data["tls.crt"]; //TODO: Make these KubeSecretKey
            Logger.LogTrace("certificatesBytes: " + certificatesBytes);
            var privateKeyBytes = certData.Data["tls.key"]; //TODO: Make these KubeSecretKey
            Logger.LogTrace("privateKeyBytes: " + privateKeyBytes);
            if (privateKeyBytes == null)
            {
                Logger.LogDebug("privateKeyBytes was null.  Setting hasPrivateKey to false for job id " + jobId + "...");
                hasPrivateKey = false;
            }
            var certificates = Encoding.UTF8.GetString(certificatesBytes);
            Logger.LogTrace("certificates: " + certificates);
            var certsList = certificates.Split(CertChainSeparator);
            Logger.LogTrace("certsList: " + certsList);
            Logger.LogDebug("Submitting inventoryItems to Keyfactor Command for job id " + jobId + "...");
            // return PushInventory(certsList, jobId, submitInventory, hasPrivateKey);
            return certsList.ToList();
        }
        catch (HttpOperationException e)
        {
            Logger.LogError(e.Message);
            Logger.LogTrace(e.ToString());
            Logger.LogTrace(e.StackTrace);
            var certDataErrorMsg =
                $"Kubernetes {KubeSecretType} '{KubeSecretName}' was not found in namespace '{KubeNamespace}'.";
            Logger.LogError(certDataErrorMsg);
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
            throw new Exception(certDataErrorMsg);
        }
        catch (Exception e)
        {
            Logger.LogError(e.Message);
            Logger.LogTrace(e.ToString());
            Logger.LogTrace(e.StackTrace);
            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
            Logger.LogError(certDataErrorMsg);
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
            throw new Exception(certDataErrorMsg);
        }
    }

    private string getK8SStorePassword(V1Secret certData)
    {
        var storePasswordBytes = new byte[] { };

        // if secret is a buddy pass
        if (!string.IsNullOrEmpty(StorePassword))
        {
            storePasswordBytes = Encoding.UTF8.GetBytes(StorePassword);
        }
        else if (!string.IsNullOrEmpty(StorePasswordPath))
        {
            // Split password path into namespace and secret name
            var passwordPath = StorePasswordPath.Split("/");
            var passwordNamespace = "";
            var passwordSecretName = "";
            if (passwordPath.Length == 1)
            {
                passwordNamespace = KubeNamespace;
                passwordSecretName = passwordPath[0];
            }
            else
            {
                passwordNamespace = passwordPath[0];
                passwordSecretName = passwordPath[^1];
            }
            
             
            var k8sPasswordObj = KubeClient.ReadBuddyPass(passwordSecretName, passwordNamespace);
            storePasswordBytes = k8sPasswordObj.Data[PasswordFieldName];
        }
        else if (certData.Data.TryGetValue(PasswordFieldName, out var value1))
        {
            storePasswordBytes = value1;
        }
        else
        {
            var passwdEx = "Store secret '"+ StorePasswordPath +"'did not contain key '" + CertificateDataFieldName + "' or '" + PasswordFieldName + "'." +
                           "  Please provide a valid store password and try again.";
            Logger.LogError(passwdEx);
            throw new Exception(passwdEx);
        }

        //convert password to string
        var storePassword = Encoding.UTF8.GetString(storePasswordBytes);
        return storePassword;
    }

    private JobResult HandlePkcs12Secret(long jobId, SubmitInventoryUpdate submitInventory, bool isJks = false)
    {
        Logger.LogDebug("Inventory entering HandlePkcs12Secret for job id " + jobId + "...");
        Logger.LogTrace("KubeNamespace: " + KubeNamespace);
        Logger.LogTrace("KubeSecretName: " + KubeSecretName);
        Logger.LogTrace("StorePath: " + StorePath);

        if (string.IsNullOrEmpty(KubeNamespace))
        {
            Logger.LogWarning("KubeNamespace is null or empty.  Attempting to parse from StorePath...");
            if (!string.IsNullOrEmpty(StorePath))
            {
                Logger.LogTrace("StorePath was not null or empty.  Parsing KubeNamespace from StorePath...");
                KubeNamespace = StorePath.Split("/").First();
                Logger.LogTrace("KubeNamespace: " + KubeNamespace);
                if (KubeNamespace == KubeSecretName)
                {
                    Logger.LogWarning("KubeNamespace was equal to KubeSecretName.  Setting KubeNamespace to 'default' for job id " + jobId + "...");
                    KubeNamespace = "default";
                }
            }
            else
            {
                Logger.LogWarning("StorePath was null or empty.  Setting KubeNamespace to 'default' for job id " + jobId + "...");
                KubeNamespace = "default";
            }
        }

        if (string.IsNullOrEmpty(KubeSecretName) && !string.IsNullOrEmpty(StorePath))
        {
            Logger.LogWarning("KubeSecretName is null or empty.  Attempting to parse from StorePath...");
            KubeSecretName = StorePath.Split("/").Last();
            Logger.LogTrace("KubeSecretName: " + KubeSecretName);
        }

        Logger.LogDebug(
            $"Querying Kubernetes {KubeSecretType} API for {KubeSecretName} in namespace {KubeNamespace} on host {KubeClient.GetHost()}...");
        var hasPrivateKey = false;
        Logger.LogTrace("Entering try block for HandlePkcs12Secret...");
        try
        {
            Logger.LogTrace("Calling KubeClient.GetCertificateStoreSecret()...");
            var certData = KubeClient.GetCertificateStoreSecret(
                KubeSecretName,
                KubeNamespace
            );
            Logger.LogDebug("KubeClient.GetCertificateStoreSecret() returned successfully.");
            Logger.LogTrace("certData: " + certData);


            var storeBytes = new byte[] { };

            // Iterate through all keys in secret to see if any match the Pkcs12AllowedKeyNames
            // KeyValuePair<string, byte[]> pkcsStores = new KeyValuePair<string, byte[]>();

            var allowedKeys = isJks ? JksAllowedKeys : Pkcs12AllowedKeys;
            
            foreach (var key in certData.Data.Keys)
            {
                // split key on '.' and take the last element
                var keyName = key.Split(".").Last();
                if (!allowedKeys.Contains(keyName) && !CertificateDataFieldName.Contains(keyName)) continue;

                Logger.LogTrace("Found key '" + key + "' in secret '" + KubeSecretName + "' for job id " + jobId + "...");
                storeBytes = certData.Data[key];
                Logger.LogTrace("storeBytes: " + Encoding.UTF8.GetString(storeBytes));
                // add key and value to dictionary
                // pkcsStores = new KeyValuePair<string, byte[]>(key, storeBytes);
                break;
            }

            if (storeBytes == null)
            {
                var storeEx = "PKCS12 store did not contain key '" + CertificateDataFieldName + "for job id " + jobId + "...";
                Logger.LogError(storeEx);
                throw new Exception(storeEx);
            }
            Logger.LogTrace("storeb64: " + Encoding.UTF8.GetString(storeBytes));

           
            // Logger.LogTrace("password: " + password);


            // Load the bytes into a collection of X509Certificates
            var certCollection = new X509Certificate2Collection();

            var storePassword = getK8SStorePassword(certData);
           
            certCollection.Import(storeBytes, storePassword, X509KeyStorageFlags.Exportable);    
           
            
            

            // Extract the private key and certificate for each certificate in the collection

            var privateKeyBytes = certCollection.Export(X509ContentType.Pkcs12, storePassword);
            // Logger.LogTrace("privateKeyBytes: " + privateKeyBytes);
            var certificatesBytes = certCollection.Export(X509ContentType.Cert);
            var certsList = new List<string> { };
            foreach (var cert in certCollection)
            {
                var privateKey = cert.GetRSAPrivateKey();
                var certBytes = cert.Export(X509ContentType.Cert);
                var certObject = new X509Certificate2(certBytes);

                // Do something with the private key and certificate
                // Logger.LogTrace("privateKey: " + privateKey);
                Logger.LogTrace("certBytes: " + certBytes);
                Logger.LogTrace("certObject: " + certObject);
                Logger.LogTrace("certObject.Thumbprint: " + certObject.Thumbprint);
                Logger.LogTrace("certObject.Subject: " + certObject.Subject);
                Logger.LogTrace("certObject.Issuer: " + certObject.Issuer);

                // Get cert in PEM format
                var certPemString = "-----BEGIN CERTIFICATE-----\n" +
                                    Convert.ToBase64String(certBytes, Base64FormattingOptions.InsertLineBreaks) +
                                    "\n-----END CERTIFICATE-----";
                Logger.LogTrace("certPemString: " + certPemString);

                string keyType;
                Logger.LogTrace("Checking type of private key");
                using (AsymmetricAlgorithm keyAlg = cert.GetRSAPublicKey())
                {
                    keyType = keyAlg != null ? "RSA" : "EC";
                }
                Logger.LogTrace("Private key type is " + keyType);
                if (cert.HasPrivateKey)
                {
                    // Get private key in PEM format
                    var pkey = cert.GetRSAPrivateKey();
                    var pKeyB64 = Convert.ToBase64String(pkey.ExportPkcs8PrivateKey(), Base64FormattingOptions.InsertLineBreaks);
                    var pKeyPemString = $"-----BEGIN {keyType} PRIVATE KEY-----\n{pKeyB64}\n-----END {keyType} PRIVATE KEY-----";
                    hasPrivateKey = true;
                }
                certsList.Add(certPemString);
            }

            Logger.LogTrace("certsList: " + certsList);
            Logger.LogDebug("Submitting inventoryItems to Keyfactor Command for job id " + jobId + "...");
            return PushInventory(certsList, jobId, submitInventory, hasPrivateKey);
        }
        catch (HttpOperationException e)
        {
            Logger.LogError(e.Message);
            Logger.LogTrace(e.ToString());
            Logger.LogTrace(e.StackTrace);
            var certDataErrorMsg =
                $"Kubernetes {KubeSecretType} '{KubeSecretName}' was not found in namespace '{KubeNamespace}'.";
            Logger.LogError(certDataErrorMsg);
            var inventoryItems = new List<CurrentInventoryItem>();
            submitInventory.Invoke(inventoryItems);
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Success,
                JobHistoryId = jobId,
                FailureMessage = certDataErrorMsg
            };
        }
        catch (Exception e)
        {
            Logger.LogError(e.Message);
            Logger.LogTrace(e.ToString());
            Logger.LogTrace(e.StackTrace);
            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
            Logger.LogError(certDataErrorMsg);
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job " + jobId + " with failure.");
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = jobId,
                FailureMessage = certDataErrorMsg
            };
        }
    }
}
