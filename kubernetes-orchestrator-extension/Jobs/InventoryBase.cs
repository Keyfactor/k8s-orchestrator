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
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SJKS;
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SPKCS12;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

// The Inventory class implements IAgentJobExtension and is meant to find all of the certificates in a given certificate store on a given server
//  and return those certificates back to Keyfactor for storing in its database.  Private keys will NOT be passed back to Keyfactor Command 
public abstract class InventoryBase : JobBase
{
    protected string[] SecretAllowedKeys = Array.Empty<string>();
    
    protected void Init(InventoryJobConfiguration config)
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
        Logger = LogHandler.GetClassLogger(GetType());
        Logger.LogInformation("Begin INVENTORY for K8S Orchestrator Extension for job '{JobId}", config.JobId);
        Logger.LogInformation("Inventory for store type: {Capability}", config.Capability);
        
        Logger.LogDebug("Calling InitializeStore()");
        InitializeStore(config);
        Logger.LogDebug("Returned from InitializeStore()");
        

        K8SHostName = KubeClient.GetHost();
        Logger.LogDebug("Server: {Host}", K8SHostName);
        Logger.LogDebug("Store Path: {StorePath}", StorePath);
        Logger.LogDebug("KubeSecretType: {SecretType}", KubeSecretType);
        Logger.LogDebug("KubeSecretName: {SecretName}", KubeSecretName);
        Logger.LogDebug("KubeNamespace: {Namespace}", KubeNamespace);

        if (Capability.Contains("Cluster")) KubeSecretType = "cluster";
        if (Capability.Contains("NS")) KubeSecretType = "namespace";

        if (!string.IsNullOrEmpty(CertificateDataFieldName))
            SecretAllowedKeys = CertificateDataFieldName.Split(',');
    }
    
    protected  Dictionary<string,List<string>> HandleK8SSecret(List<string> namespaceSecrets, string type)
    {
        Logger.LogDebug("Entering HandleK8SSecret()");
        var errors = new List<string>();

        var namespaceInventoryDict = new Dictionary<string, List<string>>();
        foreach (var secret in namespaceSecrets)
        {
            KubeSecretName = "";
            KubeNamespace = "";
            var secretType = type switch
            {
                "Opaque" or "opaque" => "opaque",
                _ => "tls"
            };
            try
            {
                Logger.LogDebug("Processing k8s secret of type '{SecretType}': {Secret}", type, secret);
                ResolveStorePath(secret);
                StorePath = secret.Replace("secrets", $"secrets/{secretType}");
                //Split store path by / and remove first element
                var storePathSplit = StorePath.Split('/');
                var storePathSplitList = storePathSplit.ToList();
                storePathSplitList.RemoveAt(0);
                StorePath = string.Join("/", storePathSplitList);

                var secretObj = HandleTlsSecret();
                namespaceInventoryDict[StorePath] = secretObj;
                Logger.LogDebug("Finished processing k8s secret of type '{SecretType}': {Secret}", type, secret);
            }
            catch (Exception ex)
            {
                Logger.LogError("Error processing k8s secret of type '{SecretType}': {Message}",
                    type, ex.Message);
                Logger.LogTrace("{Message}", ex.ToString());
                errors.Add(ex.Message);
            }
        }
        if (errors.Count > 0)
        {
            Logger.LogError("Errors processing k8s namespace secrets of type '{SecretType}': {Errors}",
                type, string.Join(",", errors));
        }

        Logger.LogDebug("Returning from HandleK8SSecret()");
        return namespaceInventoryDict;
    }
    
    protected Dictionary<string, List<string>> HandleJKSSecret(JobConfiguration config, List<string> allowedKeys)
    {
        Logger.LogDebug("Enter HandleJKSSecret()");
        Logger.LogDebug("Attempting to serialize JKS store");
        var jksStore = new JksCertificateStoreSerializer(config.JobProperties?.ToString());
        //getJksBytesFromKubeSecret
        Logger.LogDebug("Attempting to get JKS bytes from K8S secret " + KubeSecretName + " in namespace " +
                        KubeNamespace);
        var k8sData = KubeClient.GetJksSecret(KubeSecretName, KubeNamespace, "", "", allowedKeys);

        var jksInventoryDict = new Dictionary<string, List<string>>();
        // iterate through the keys in the secret and add them to the jks store
        Logger.LogDebug("Iterating through keys in K8S secret " + KubeSecretName + " in namespace " + KubeNamespace);
        foreach (var (keyName, keyBytes) in k8sData.Inventory)
        {
            Logger.LogDebug("Fetching store password for K8S secret " + KubeSecretName + " in namespace " +
                            KubeNamespace + " and key " + keyName);
            var keyPassword = GetK8SStorePassword(k8sData.Secret);
            var passwordHash = GetSha256Hash(keyPassword);
            Logger.LogTrace("Password hash for '{Secret}/{Key}': {Hash}", KubeSecretName, keyName, passwordHash);
            var keyAlias = keyName;
            Logger.LogTrace("Key alias: {Alias}", keyAlias);
            Logger.LogDebug("Attempting to deserialize JKS store '{Secret}/{Key}'", KubeSecretName, keyName);
            var sourceIsPkcs12 = false; //This refers to if the JKS store is actually a PKCS12 store
            Pkcs12Store jStoreDs;
            try
            {
                jStoreDs = jksStore.ToPkcs12(keyBytes, keyName, keyPassword);
            }
            catch (JkSisPkcs12Exception)
            {
                sourceIsPkcs12 = true;
                var pkcs12Store = new Pkcs12CertificateStoreSerializer(keyBytes, keyPassword);
                jStoreDs = pkcs12Store.ToPkcs12(keyBytes, keyPassword);
                // return HandlePkcs12Secret(config);
            }

            // create a list of certificate chains in PEM format

            Logger.LogDebug("Iterating through aliases in JKS store '{Secret}/{Key}'", KubeSecretName, keyName);
            var certAliasLookup = new Dictionary<string, string>();
            //make a copy of jStoreDs.Aliases so we can remove items from it

            foreach (var certAlias in jStoreDs.Aliases)
            {
                if (certAliasLookup.TryGetValue(certAlias, out var certAliasSubject))
                    if (certAliasSubject == "skip")
                    {
                        Logger.LogTrace("Certificate alias: {Alias} already exists in lookup with subject '{Subject}'",
                            certAlias, certAliasSubject);
                        continue;
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
                            certAliasLookup[alias] = "skip";
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
                }

                var pKey = jStoreDs.GetKey(certAlias);
                if (pKey != null)
                {
                    Logger.LogDebug("Found private key for alias '{Alias}'", certAlias);
                }

                StringBuilder certChainPem;

                if (certChain != null)
                {
                    Logger.LogDebug("Certificate chain found for alias '{Alias}'", certAlias);
                    Logger.LogDebug("Iterating through certificate chain for alias '{Alias}' to build PEM chain",
                        certAlias);
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
                if (certAliasLookup[certAlias] != "skip") jksInventoryDict[fullAlias] = certChainList;
            }
        }

        return jksInventoryDict;
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

    protected JobResult PushInventory(IEnumerable<string> certsList, long jobId, SubmitInventoryUpdate submitInventory,
        bool hasPrivateKey = false, string jobMessage = null)
    {
        Logger.LogDebug("Entered PushInventory for job id '{JobId}'", jobId);
        Logger.LogTrace("submitInventory: {Inv}", submitInventory.ToString());
        Logger.LogTrace("certsList: {Certs}", certsList.ToString());
        var inventoryItems = new List<CurrentInventoryItem>();
        var certificates = certsList as string[] ?? certsList.ToArray();
        foreach (var cert in certificates)
        {
            Logger.LogTrace("Cert:\n{Cert}", cert);
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

    protected JobResult PushInventory(Dictionary<string, string> certsList, long jobId,
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

    protected JobResult PushInventory(Dictionary<string, List<string>> certsList, long jobId,
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
}