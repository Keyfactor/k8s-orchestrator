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

            var allowedKeys = new List<string>();
            if (!string.IsNullOrEmpty(CertificateDataFieldName))
            {
                allowedKeys = CertificateDataFieldName.Split(',').ToList();
            }

            switch (KubeSecretType.ToLower())
            {
                case "secret":
                case "secrets":
                case "opaque":
                    Logger.LogInformation("Inventorying opaque secrets using the following allowed keys: {Keys}", OpaqueAllowedKeys?.ToString());
                    try {
                        var opaqueInventory = HandleTlsSecret(config.JobHistoryId);
                        Logger.LogDebug("Returned inventory count: {Count}",opaqueInventory.Count.ToString());
                        return PushInventory(opaqueInventory, config.JobHistoryId, submitInventory, true);
                    }
                    catch (StoreNotFoundException)
                    {
                        Logger.LogWarning("Unable to locate Opaque secret {Namespace}/{Name}. Sending empty inventory.", KubeNamespace, KubeSecretName);
                        return PushInventory(new List<string>() {}, config.JobHistoryId, submitInventory, false, "WARNING: Store not found in Kubernetes cluster. Assuming empty inventory.");
                    }
                    
                case "tls_secret":
                case "tls":
                case "tlssecret":
                case "tls_secrets":
                    Logger.LogInformation("Inventorying TLS secrets using the following allowed keys: {Keys}" , TLSAllowedKeys?.ToString());
                    try
                    {
                        var tlsCertsInv = HandleTlsSecret(config.JobHistoryId);
                        Logger.LogDebug("Returned inventory count: {Count}",tlsCertsInv.Count.ToString());
                        return PushInventory(tlsCertsInv, config.JobHistoryId, submitInventory, true);
                    }
                    catch (StoreNotFoundException ex)
                    {
                        Logger.LogWarning("Unable to locate tls secret {Namespace}/{Name}. Sending empty inventory.", KubeNamespace, KubeSecretName);
                        return PushInventory(new List<string>() {}, config.JobHistoryId, submitInventory, false, "WARNING: Store not found in Kubernetes cluster. Assuming empty inventory.");
                    }
                    
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
                    //combine allowed keys and CertificateDataFields into one list
                    allowedKeys.AddRange(Pkcs12AllowedKeys);
                    Logger.LogInformation("Inventorying PKCS12 using the following allowed keys: {Keys}", allowedKeys);
                    var pkcs12Inventory = HandlePkcs12Secret(config, allowedKeys);
                    Logger.LogDebug("Returned inventory count: {Count}",pkcs12Inventory.Count.ToString());
                    return PushInventory(pkcs12Inventory, config.JobHistoryId, submitInventory, true);
                case "jks":
                    allowedKeys.AddRange(JksAllowedKeys);
                    Logger.LogInformation("Inventorying JKS using the following allowed keys: {Keys}", allowedKeys);
                    var jksInventory = HandleJKSSecret(config, allowedKeys);
                    Logger.LogDebug("Returned inventory count: {Count}",jksInventory.Count.ToString());
                    return PushInventory(jksInventory, config.JobHistoryId, submitInventory, true);

                case "cluster":
                    var clusterOpaqueSecrets = KubeClient.DiscoverSecrets(OpaqueAllowedKeys, "Opaque", "all", false);
                    var clusterTlsSecrets = KubeClient.DiscoverSecrets(TLSAllowedKeys, "tls", "all", false);
                    var errors = new List<string>();

                    var clusterInventoryDict = new Dictionary<string, List<string>>();
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

                            var opaqueObj = HandleTlsSecret(config.JobHistoryId);
                            clusterInventoryDict[StorePath] = opaqueObj;
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

                            var tlsObj = HandleTlsSecret(config.JobHistoryId);
                            clusterInventoryDict[StorePath] = tlsObj; //todo: fix this  
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

                            var opaqueObj = HandleTlsSecret(config.JobHistoryId);
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


                            var tlsObj = HandleTlsSecret(config.JobHistoryId);
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
    private Dictionary<string, List<string>> HandleJKSSecret(JobConfiguration config, List<string> allowedKeys)
    {
        Logger.LogDebug("Enter HandleJKSSecret()");
        var hasPrivateKeyJks = false;
        Logger.LogDebug("Attempting to serialize JKS store");
        var jksStore = new JksCertificateStoreSerializer(config.JobProperties?.ToString());
        //getJksBytesFromKubeSecret
        Logger.LogDebug("Attempting to get JKS bytes from K8S secret " + KubeSecretName + " in namespace " + KubeNamespace);
        var k8sData = KubeClient.GetJksSecret(KubeSecretName, KubeNamespace, "","", allowedKeys);

        var jksInventoryDict = new Dictionary<string, List<string>>();
        // iterate through the keys in the secret and add them to the jks store
        Logger.LogDebug("Iterating through keys in K8S secret " + KubeSecretName + " in namespace " + KubeNamespace);
        foreach (var (keyName, keyBytes) in k8sData.Inventory)
        {
            Logger.LogDebug("Fetching store password for K8S secret " + KubeSecretName + " in namespace " + KubeNamespace + " and key " + keyName);
            var keyPassword = getK8SStorePassword(k8sData.Secret);
            var passwordHash = GetSHA256Hash(keyPassword);
            Logger.LogTrace("Password hash for '{Secret}/{Key}': {Hash}", KubeSecretName, keyName, passwordHash);
            var keyAlias = keyName;
            Logger.LogTrace("Key alias: {Alias}", keyAlias);
            Logger.LogDebug("Attempting to deserialize JKS store '{Secret}/{Key}'", KubeSecretName, keyName);
            var sourceIsPkcs12 = false; //This refers to if the JKS store is actually a PKCS12 store
            Pkcs12Store jStoreDs;
            try
            {
                jStoreDs = jksStore.DeserializeRemoteCertificateStore(keyBytes, keyName, keyPassword);
            }
            catch (JkSisPkcs12Exception)
            {
                sourceIsPkcs12 = true;
                var pkcs12Store = new Pkcs12CertificateStoreSerializer(config.JobProperties?.ToString());
                jStoreDs = pkcs12Store.DeserializeRemoteCertificateStore(keyBytes, keyName, keyPassword);
                // return HandlePkcs12Secret(config);
            }

            // create a list of certificate chains in PEM format

            Logger.LogDebug("Iterating through aliases in JKS store '{Secret}/{Key}'", KubeSecretName, keyName);
            var certAliasLookup = new Dictionary<string, string>();
            //make a copy of jStoreDs.Aliases so we can remove items from it

            foreach (var certAlias in jStoreDs.Aliases)
            {
                if (certAliasLookup.TryGetValue(certAlias, out var certAliasSubject))
                {
                    if (certAliasSubject == "skip")
                    {
                        Logger.LogTrace("Certificate alias: {Alias} already exists in lookup with subject '{Subject}'", certAlias, certAliasSubject);
                        continue;    
                    }
                }
                Logger.LogTrace("Certificate alias: {Alias}", certAlias);
                var certChainList = new List<string>();

                Logger.LogDebug("Attempting to get certificate chain for alias '{Alias}'", certAlias);
                var certChain = jStoreDs.GetCertificateChain(certAlias);

                if (certChain != null)
                {
                    certAliasLookup[certAlias] = certChain[0].Certificate.SubjectDN.ToString();    
                    if (sourceIsPkcs12 && certChain.Length > 0)
                    {
                        // This is a PKCS12 store that was created as a JKS so we need to check that the aliases aren't the same as the cert chain
                        // If they are the same then we need to only use the chain and break out of the loop
                        var certChainAliases = certChain.Select(cert => cert.Certificate.SubjectDN.ToString()).ToList();
                        // Remove leaf certificate from chain
                        certChainAliases.RemoveAt(0);
                        var storeAliases = jStoreDs.Aliases.ToList();
                        storeAliases.Remove(certAlias);
                        // Iterate though the aliases and add them to the lookup as 'skip' if they are in the chain
                        foreach (var alias in storeAliases.Where(alias => certChainAliases.Contains(alias)))
                        {
                            certAliasLookup[alias] = "skip";
                        }
                    }
                }
                else
                {
                    certAliasLookup[certAlias] = "skip";
                }

                var fullAlias = keyAlias + "/" + certAlias;
                Logger.LogTrace("Full alias: {Alias}", fullAlias);
                //check if the alias is a private key
                if (jStoreDs.IsKeyEntry(certAlias))
                {
                    hasPrivateKeyJks = true;
                }
                var pKey = jStoreDs.GetKey(certAlias);
                if (pKey != null)
                {
                    Logger.LogDebug("Found private key for alias '{Alias}'", certAlias);
                    hasPrivateKeyJks = true;
                }

                StringBuilder certChainPem;

                if (certChain != null)
                {
                    Logger.LogDebug("Certificate chain found for alias '{Alias}'", certAlias);
                    Logger.LogDebug("Iterating through certificate chain for alias '{Alias}' to build PEM chain", certAlias);
                    foreach (var cert in certChain)
                    {
                        certChainPem = new StringBuilder();
                        certChainPem.AppendLine("-----BEGIN CERTIFICATE-----");
                        certChainPem.AppendLine(Convert.ToBase64String(cert.Certificate.GetEncoded()));
                        certChainPem.AppendLine("-----END CERTIFICATE-----");
                        certChainList.Add(certChainPem.ToString());
                    }
                    Logger.LogTrace("Certificate chain for alias '{Alias}': {Chain}", certAlias, certChainList);
                }

                if (certChainList.Count != 0)
                {
                    Logger.LogDebug("Adding certificate chain for alias '{Alias}' to inventory", certAlias);
                    jksInventoryDict[fullAlias] = certChainList;
                    continue;
                }

                Logger.LogDebug("Attempting to get leaf certificate for alias '{Alias}'", certAlias);
                var leaf = jStoreDs.GetCertificate(certAlias);
                if (leaf != null)
                {
                    Logger.LogDebug("Leaf certificate found for alias '{Alias}'", certAlias);
                    certChainPem = new StringBuilder();
                    certChainPem.AppendLine("-----BEGIN CERTIFICATE-----");
                    certChainPem.AppendLine(Convert.ToBase64String(leaf.Certificate.GetEncoded()));
                    certChainPem.AppendLine("-----END CERTIFICATE-----");
                    certChainList.Add(certChainPem.ToString());
                }
                Logger.LogDebug("Adding leaf certificate for alias '{Alias}' to inventory", certAlias);
                if (certAliasLookup[certAlias] != "skip")
                {
                    jksInventoryDict[fullAlias] = certChainList;    
                }
                
            }
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

    private JobResult PushInventory(IEnumerable<string> certsList, long jobId, SubmitInventoryUpdate submitInventory, bool hasPrivateKey = false, string jobMessage = null)
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

    private JobResult PushInventory(Dictionary<string, List<string>> certsList, long jobId, SubmitInventoryUpdate submitInventory, bool hasPrivateKey = false)
    {
        Logger.LogDebug("Entering PushInventory for job id " + jobId + "...");
        Logger.LogTrace("submitInventory: " + submitInventory);
        Logger.LogTrace("certsList: " + certsList);
        var inventoryItems = new List<CurrentInventoryItem>();
        foreach (var certObj in certsList)
        {
            var certs = certObj.Value;


            // load as x509
            string alias = certObj.Key;
            Logger.LogDebug("Cert alias: " + alias);

            if (certs.Count == 0)
            {
                Logger.LogWarning($"Kubernetes returned an empty inventory for store {KubeSecretName} in namespace {KubeNamespace} on host {KubeClient.GetHost()}.");
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


    private List<string> HandleTlsSecret(long jobId)
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
            byte[] caBytes = null;
            var certsList = new List<string>();

            var certPem = Encoding.UTF8.GetString(certificatesBytes);
            Logger.LogTrace("certPem: " + certPem);
            var certObj = KubeClient.ReadPemCertificate(certPem);
            if (certObj == null)
            {
                Logger.LogDebug("Failed to parse certificate from opaque secret data as PEM. Attempting to parse as DER");
                // Attempt to read data as DER
                certObj = KubeClient.ReadDerCertificate(certPem);
                if (certObj != null)
                {
                    certPem = KubeClient.ConvertToPem(certObj);
                    Logger.LogTrace("certPem: " + certPem);
                }
                else
                {
                    certPem = KubeClient.ConvertToPem(certObj);
                }
                Logger.LogTrace("certPem: " + certPem);
            }
            else
            {
                certPem = KubeClient.ConvertToPem(certObj);
                Logger.LogTrace("certPem: " + certPem);
            }
            if (!string.IsNullOrEmpty(certPem))
            {
                certsList.Add(certPem);
            }

            var caPem = "";
            if (certData.Data.TryGetValue("ca.crt", out var value))
            {
                caBytes = value;
                Logger.LogTrace("caBytes: " + caBytes);
                var caObj = KubeClient.ReadPemCertificate(Encoding.UTF8.GetString(caBytes));
                if (caObj == null)
                {
                    Logger.LogDebug("Failed to parse certificate from opaque secret data as PEM. Attempting to parse as DER");
                    // Attempt to read data as DER
                    caObj = KubeClient.ReadDerCertificate(Encoding.UTF8.GetString(caBytes));
                    if (caObj != null)
                    {
                        caPem = KubeClient.ConvertToPem(caObj);
                        Logger.LogTrace("caPem: " + caPem);
                    }
                }
                else
                {
                    caPem = KubeClient.ConvertToPem(caObj);
                }

                Logger.LogTrace("caPem: " + caPem);
                if (!string.IsNullOrEmpty(caPem))
                {
                    certsList.Add(caPem);
                }
            }
            else
            {
                // Determine if chain is present in tls.crt
                var certChain = KubeClient.LoadCertificateChain(Encoding.UTF8.GetString(certificatesBytes));
                if (certChain != null && certChain.Count > 1)
                {
                    certsList.Clear();
                    Logger.LogDebug("Certificate chain detected in tls.crt.  Attempting to parse chain...");
                    foreach (var cert in certChain)
                    {
                        Logger.LogTrace("cert: " + cert);
                        certsList.Add(KubeClient.ConvertToPem(cert));
                    }
                }
            }
            // Logger.LogTrace("privateKeyBytes: " + privateKeyBytes);
            if (privateKeyBytes == null)
            {
                Logger.LogDebug("privateKeyBytes was null.  Setting hasPrivateKey to false for job id " + jobId + "...");
                hasPrivateKey = false;
            }

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
            throw new StoreNotFoundException(certDataErrorMsg);
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
    
    private Dictionary<string, List<string>> HandlePkcs12Secret(JobConfiguration config, List<string> allowedKeys)
    {
        var hasPrivateKey = false;
        var pkcs12Store = new Pkcs12CertificateStoreSerializer(config.JobProperties?.ToString());
        var k8sData = KubeClient.GetPkcs12Secret(KubeSecretName, KubeNamespace, "", "", allowedKeys);
        var pkcs12InventoryDict = new Dictionary<string, List<string>>();
        // iterate through the keys in the secret and add them to the pkcs12 store
        foreach (var (keyName, keyBytes) in k8sData.Inventory)
        {
            var keyPassword = getK8SStorePassword(k8sData.Secret);
            var pStoreDs = pkcs12Store.DeserializeRemoteCertificateStore(keyBytes, keyName, keyPassword);
            // create a list of certificate chains in PEM format
            foreach (var certAlias in pStoreDs.Aliases)
            {
                var certChainList = new List<string>();
                var certChain = pStoreDs.GetCertificateChain(certAlias);
                var certChainPem = new StringBuilder();
                var fullAlias = keyName + "/" + certAlias;
                //check if the alias is a private key
                if (pStoreDs.IsKeyEntry(certAlias))
                {
                    hasPrivateKey = true;
                }
                var pKey = pStoreDs.GetKey(certAlias);
                if (pKey != null)
                {
                    hasPrivateKey = true;
                }

                // if (certChain == null)
                // {
                //     pkcs12InventoryDict[fullAlias] = string.Join("", certChainList);
                //     continue;
                // }

                if (certChain != null)
                    foreach (var cert in certChain)
                    {
                        certChainPem = new StringBuilder();
                        certChainPem.AppendLine("-----BEGIN CERTIFICATE-----");
                        certChainPem.AppendLine(Convert.ToBase64String(cert.Certificate.GetEncoded()));
                        certChainPem.AppendLine("-----END CERTIFICATE-----");
                        certChainList.Add(certChainPem.ToString());

                    }

                if (certChainList.Count != 0)
                {
                    // pkcs12InventoryDict[fullAlias] = string.Join("", certChainList);
                    pkcs12InventoryDict[fullAlias] = certChainList;
                    continue;
                }

                var leaf = pStoreDs.GetCertificate(certAlias);
                if (leaf != null)
                {
                    certChainPem = new StringBuilder();
                    certChainPem.AppendLine("-----BEGIN CERTIFICATE-----");
                    certChainPem.AppendLine(Convert.ToBase64String(leaf.Certificate.GetEncoded()));
                    certChainPem.AppendLine("-----END CERTIFICATE-----");
                    certChainList.Add(certChainPem.ToString());
                    // var certificate = new X509Certificate2(leaf.Certificate.GetEncoded());
                    // var cn = certificate.GetNameInfo(X509NameType.SimpleName, false);
                    // fullAlias = keyName + "/" + cn;
                }

                // pkcs12InventoryDict[fullAlias] = string.Join("", certChainList);
                pkcs12InventoryDict[fullAlias] = certChainList;
            }
        }
        return pkcs12InventoryDict;
    }
}
