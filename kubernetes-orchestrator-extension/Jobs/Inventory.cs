// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

// Suppress warnings for variables used for state tracking but not read (future functionality)
#pragma warning disable CS0219

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using k8s.Autorest;
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SJKS;
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SPKCS12;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;
using Org.BouncyCastle.Pkcs;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

/// <summary>
/// Inventory job implementation for Kubernetes certificate stores.
/// Finds all certificates in a given Kubernetes certificate store (secrets, CSRs, JKS, PKCS12)
/// and returns them to Keyfactor Command for storage in its database.
/// Private keys are NOT passed back to Keyfactor Command.
/// </summary>
/// <remarks>
/// Supports the following store types:
/// - Opaque secrets (K8SSecret)
/// - TLS secrets (K8STLSSecr)
/// - Certificate Signing Requests (K8SCert)
/// - JKS keystores (K8SJKS)
/// - PKCS12 keystores (K8SPKCS12)
/// - Cluster-wide inventory (K8SCluster)
/// - Namespace-wide inventory (K8SNS)
/// </remarks>
public class Inventory : JobBase, IInventoryJobExtension
{
    /// <summary>
    /// Represents a single inventory entry with per-item private key status and certificate chain.
    /// Used for K8SNS and K8SCluster inventory where each secret may have different private key status.
    /// </summary>
    private class InventoryEntry
    {
        /// <summary>The alias/identifier for this inventory item.</summary>
        public string Alias { get; set; } = string.Empty;

        /// <summary>The certificate chain (leaf cert first, then intermediates, then root).</summary>
        public List<string> Certificates { get; set; } = new();

        /// <summary>Whether this entry has a private key in the store.</summary>
        public bool HasPrivateKey { get; set; }
    }

    /// <summary>
    /// Stores the original KubeSecretName value from the job config properties.
    /// This is needed for K8SCert cluster-wide mode detection because InitializeStore
    /// may modify KubeSecretName by setting it from StorePath if empty.
    /// </summary>
    private string _originalKubeSecretName;

    /// <summary>
    /// Initializes a new instance of the Inventory job with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    public Inventory(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    /// <summary>
    /// Main entry point for the inventory job. Processes the job configuration and returns
    /// all certificates found in the specified Kubernetes certificate store.
    /// </summary>
    /// <param name="config">Inventory job configuration containing store details and credentials.</param>
    /// <param name="submitInventory">Callback delegate to submit discovered certificates to Keyfactor Command.</param>
    /// <returns>JobResult indicating success or failure of the inventory operation.</returns>
    /// <remarks>
    /// Configuration parameters available in config:
    /// - config.ServerUsername, config.ServerPassword - credentials for K8S API authentication
    /// - config.CertificateStoreDetails.StorePath - location path of certificate store
    /// - config.CertificateStoreDetails.StorePassword - password for protected stores (JKS/PKCS12)
    /// - config.CertificateStoreDetails.Properties - JSON string with custom store properties
    /// </remarks>
    public JobResult ProcessJob(InventoryJobConfiguration config, SubmitInventoryUpdate submitInventory)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(MsLogLevel.Debug);

        try
        {
            // For K8SCert cluster-wide mode detection, we need to capture the original KubeSecretName
            // BEFORE InitializeStore modifies it (it may get set from StorePath if empty)
            string originalKubeSecretName = null;
            if (!string.IsNullOrEmpty(config.CertificateStoreDetails?.Properties))
            {
                try
                {
                    var props = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(
                        config.CertificateStoreDetails.Properties);
                    if (props != null && props.TryGetValue("KubeSecretName", out var val))
                    {
                        originalKubeSecretName = val?.ToString();
                    }
                }
                catch
                {
                    // Ignore JSON parsing errors - will use default behavior
                }
            }

            Logger.LogDebug("Initializing store for inventory job {JobId}", config.JobId);
            InitializeStore(config);
            Logger.LogTrace("Returned from InitializeStore()");

            // Store the original KubeSecretName for K8SCert cluster-wide mode detection
            _originalKubeSecretName = originalKubeSecretName;

            Logger.LogInformation("Begin INVENTORY for K8S Orchestrator Extension for job " + config.JobId);
            Logger.LogInformation($"Inventory for store type: {config.Capability}");

            Logger.LogTrace("KubeClient is null: {IsNull}", KubeClient == null);
            if (KubeClient == null)
            {
                throw new InvalidOperationException("KubeClient is null after InitializeStore()");
            }

            Logger.LogDebug("Server: {Host}", KubeClient.GetHost());
            Logger.LogDebug("Store Path: {StorePath}", StorePath);
            Logger.LogDebug("KubeSecretType: {KubeSecretType}", KubeSecretType);
            Logger.LogDebug("KubeSecretName: {KubeSecretName}", KubeSecretName);
            Logger.LogDebug("KubeNamespace: {KubeNamespace}", KubeNamespace);
            Logger.LogDebug("Host: {Host}", KubeClient.GetHost());

            Logger.LogTrace("Inventory entering switch based on KubeSecretType: " + KubeSecretType + "...");

            Logger.LogTrace("Inventory entering switch based on KubeSecretType: " + KubeSecretType + "...");

            if (Capability.Contains("Cluster")) KubeSecretType = "cluster";
            if (Capability.Contains("NS")) KubeSecretType = "namespace";
            if (Capability.Contains("Cert")) KubeSecretType = "certificate";

            var allowedKeys = new List<string>();
            if (!string.IsNullOrEmpty(CertificateDataFieldName))
                allowedKeys = CertificateDataFieldName.Split(',').ToList();

            // Handle null KubeSecretType gracefully
            if (string.IsNullOrEmpty(KubeSecretType))
            {
                Logger.LogWarning("KubeSecretType is null or empty, defaulting to 'secret'");
                KubeSecretType = "secret";
            }

            switch (KubeSecretType.ToLower())
            {
                case "secret":
                case "secrets":
                case "opaque":
                    Logger.LogInformation("Inventorying opaque secrets using the following allowed keys: {Keys}",
                        OpaqueAllowedKeys?.ToString());
                    try
                    {
                        var opaqueInventory = HandleOpaqueSecretAsList(config.JobHistoryId);
                        Logger.LogDebug("Returned inventory count: {Count}", opaqueInventory.Count.ToString());
                        return PushInventory(opaqueInventory, config.JobHistoryId, submitInventory, true);
                    }
                    catch (StoreNotFoundException)
                    {
                        Logger.LogWarning("Unable to locate Opaque secret {Namespace}/{Name}. Sending empty inventory.",
                            KubeNamespace, KubeSecretName);
                        return PushInventory(new List<string>(), config.JobHistoryId, submitInventory, false,
                            "WARNING: Store not found in Kubernetes cluster. Assuming empty inventory.");
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError("Inventory failed with exception: " + ex.Message);
                        Logger.LogTrace(ex.Message);
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

                case "tls_secret":
                case "tls":
                case "tlssecret":
                case "tls_secrets":
                    Logger.LogInformation("Inventorying TLS secrets using the following allowed keys: {Keys}",
                        TLSAllowedKeys?.ToString());
                    try
                    {
                        var tlsCertsInv = HandleTlsSecret(config.JobHistoryId);
                        Logger.LogDebug("Returned inventory count: {Count}", tlsCertsInv.Count.ToString());
                        return PushInventory(tlsCertsInv, config.JobHistoryId, submitInventory, true);
                    }
                    catch (StoreNotFoundException)
                    {
                        Logger.LogWarning("Unable to locate tls secret {Namespace}/{Name}. Sending empty inventory.",
                            KubeNamespace, KubeSecretName);
                        return PushInventory(new List<string>(), config.JobHistoryId, submitInventory, false,
                            "WARNING: Store not found in Kubernetes cluster. Assuming empty inventory.");
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
                    Logger.LogDebug("Returned inventory count: {Count}", pkcs12Inventory.Count.ToString());
                    return PushInventory(pkcs12Inventory, config.JobHistoryId, submitInventory, true);
                case "jks":
                    allowedKeys.AddRange(JksAllowedKeys);
                    Logger.LogInformation("Inventorying JKS using the following allowed keys: {Keys}", allowedKeys);
                    var jksInventory = HandleJKSSecret(config, allowedKeys);
                    Logger.LogDebug("Returned inventory count: {Count}", jksInventory.Count.ToString());
                    return PushInventory(jksInventory, config.JobHistoryId, submitInventory, true);

                case "cluster":
                    var clusterOpaqueSecrets = KubeClient.DiscoverSecrets(OpaqueAllowedKeys, "Opaque", "all");
                    var clusterTlsSecrets = KubeClient.DiscoverSecrets(TLSAllowedKeys, "tls", "all");
                    var errors = new List<string>();

                    // Use List<InventoryEntry> to track per-secret private key status and full certificate chains
                    var clusterInventoryEntries = new List<InventoryEntry>();
                    foreach (var opaqueSecret in clusterOpaqueSecrets)
                    {
                        KubeSecretName = "";
                        KubeNamespace = "";
                        KubeSecretType = "secret";
                        try
                        {
                            // DiscoverSecrets returns format: cluster/namespace/secrets/secretname
                            // Parse the path directly since ResolveStorePath doesn't handle cluster stores with 4 parts
                            var pathParts = opaqueSecret.Split('/');
                            if (pathParts.Length >= 4)
                            {
                                // Format: cluster/namespace/secrets/secretname
                                KubeNamespace = pathParts[1];
                                KubeSecretName = pathParts[pathParts.Length - 1];
                                Logger.LogDebug("Cluster inventory: Parsed namespace={Namespace}, secretName={SecretName} from path {Path}",
                                    KubeNamespace, KubeSecretName, opaqueSecret);
                            }
                            else
                            {
                                // Fallback to ResolveStorePath for other formats
                                ResolveStorePath(opaqueSecret);
                            }
                            StorePath = opaqueSecret.Replace("secrets", "secrets/opaque");
                            //Split storepath by / and remove first 1 elements
                            var storePathSplit = StorePath.Split('/');
                            var storePathSplitList = storePathSplit.ToList();
                            storePathSplitList.RemoveAt(0);
                            var alias = string.Join("/", storePathSplitList);

                            var entry = HandleOpaqueSecretAsEntry(config.JobHistoryId, alias);
                            if (entry.Certificates.Count > 0)
                            {
                                clusterInventoryEntries.Add(entry);
                                Logger.LogDebug("Cluster inventory: Added opaque secret '{Alias}' with HasPrivateKey={HasPrivateKey}, CertCount={CertCount}",
                                    entry.Alias, entry.HasPrivateKey, entry.Certificates.Count);
                                Logger.LogTrace("Cluster inventory: Alias '{Alias}' certificate chain:\n{Chain}",
                                    entry.Alias, string.Join("\n---\n", entry.Certificates));
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.LogError("Error processing Opaque Secret: " + opaqueSecret + " - " + ex.Message +
                                            "\n\t" + ex.StackTrace);
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
                            // DiscoverSecrets returns format: cluster/namespace/secrets/secretname
                            // Parse the path directly since ResolveStorePath doesn't handle cluster stores with 4 parts
                            var pathParts = tlsSecret.Split('/');
                            if (pathParts.Length >= 4)
                            {
                                // Format: cluster/namespace/secrets/secretname
                                KubeNamespace = pathParts[1];
                                KubeSecretName = pathParts[pathParts.Length - 1];
                                Logger.LogDebug("Cluster inventory: Parsed namespace={Namespace}, secretName={SecretName} from path {Path}",
                                    KubeNamespace, KubeSecretName, tlsSecret);
                            }
                            else
                            {
                                // Fallback to ResolveStorePath for other formats
                                ResolveStorePath(tlsSecret);
                            }
                            StorePath = tlsSecret.Replace("secrets", "secrets/tls");
                            //Split storepath by / and remove first 1 elements
                            var storePathSplit = StorePath.Split('/');
                            var storePathSplitList = storePathSplit.ToList();
                            storePathSplitList.RemoveAt(0);
                            var alias = string.Join("/", storePathSplitList);

                            var entry = HandleTlsSecretAsEntry(config.JobHistoryId, alias);
                            if (entry.Certificates.Count > 0)
                            {
                                clusterInventoryEntries.Add(entry);
                                Logger.LogDebug("Cluster inventory: Added TLS secret '{Alias}' with HasPrivateKey={HasPrivateKey}, CertCount={CertCount}",
                                    entry.Alias, entry.HasPrivateKey, entry.Certificates.Count);
                                Logger.LogTrace("Cluster inventory: Alias '{Alias}' certificate chain:\n{Chain}",
                                    entry.Alias, string.Join("\n---\n", entry.Certificates));
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.LogError("Error processing TLS Secret: " + tlsSecret + " - " + ex.Message + "\n\t" +
                                            ex.StackTrace);
                            errors.Add(ex.Message);
                        }
                    }

                    Logger.LogDebug("Cluster inventory complete: {Count} secrets with per-item private key status", clusterInventoryEntries.Count);
                    return PushInventory(clusterInventoryEntries, config.JobHistoryId, submitInventory);
                case "namespace":
                    var namespaceOpaqueSecrets = KubeClient.DiscoverSecrets(OpaqueAllowedKeys, "Opaque", KubeNamespace);
                    var namespaceTlsSecrets = KubeClient.DiscoverSecrets(TLSAllowedKeys, "tls", KubeNamespace);
                    var namespaceErrors = new List<string>();

                    // Use List<InventoryEntry> to track per-secret private key status and full certificate chains
                    var namespaceInventoryEntries = new List<InventoryEntry>();
                    foreach (var opaqueSecret in namespaceOpaqueSecrets)
                    {
                        KubeSecretName = "";
                        // KubeNamespace = "";
                        KubeSecretType = "secret";
                        try
                        {
                            // DiscoverSecrets returns format: cluster/namespace/secrets/secretname
                            // Parse the path directly since ResolveStorePath doesn't handle NS stores with 4 parts
                            var pathParts = opaqueSecret.Split('/');
                            if (pathParts.Length >= 4)
                            {
                                // Format: cluster/namespace/secrets/secretname
                                // KubeNamespace is already set from store config, just need secret name
                                KubeSecretName = pathParts[pathParts.Length - 1];
                                Logger.LogDebug("Namespace inventory: Parsed secretName={SecretName} from path {Path}",
                                    KubeSecretName, opaqueSecret);
                            }
                            else
                            {
                                // Fallback to ResolveStorePath for other formats
                                ResolveStorePath(opaqueSecret);
                            }
                            StorePath = opaqueSecret.Replace("secrets", "secrets/opaque");
                            //Split storepath by / and remove first 2 elements
                            var storePathSplit = StorePath.Split('/');
                            var storePathSplitList = storePathSplit.ToList();
                            storePathSplitList.RemoveAt(0);
                            storePathSplitList.RemoveAt(0);
                            var alias = string.Join("/", storePathSplitList);

                            var entry = HandleOpaqueSecretAsEntry(config.JobHistoryId, alias);
                            if (entry.Certificates.Count > 0)
                            {
                                namespaceInventoryEntries.Add(entry);
                                Logger.LogDebug("Namespace inventory: Added opaque secret '{Alias}' with HasPrivateKey={HasPrivateKey}, CertCount={CertCount}",
                                    entry.Alias, entry.HasPrivateKey, entry.Certificates.Count);
                                Logger.LogTrace("Namespace inventory: Alias '{Alias}' certificate chain:\n{Chain}",
                                    entry.Alias, string.Join("\n---\n", entry.Certificates));
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.LogError("Error processing Opaque Secret: " + opaqueSecret + " - " + ex.Message +
                                            "\n\t" + ex.StackTrace);
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
                            // DiscoverSecrets returns format: cluster/namespace/secrets/secretname
                            // Parse the path directly since ResolveStorePath doesn't handle NS stores with 4 parts
                            var pathParts = tlsSecret.Split('/');
                            if (pathParts.Length >= 4)
                            {
                                // Format: cluster/namespace/secrets/secretname
                                // KubeNamespace is already set from store config, just need secret name
                                KubeSecretName = pathParts[pathParts.Length - 1];
                                Logger.LogDebug("Namespace inventory: Parsed secretName={SecretName} from path {Path}",
                                    KubeSecretName, tlsSecret);
                            }
                            else
                            {
                                // Fallback to ResolveStorePath for other formats
                                ResolveStorePath(tlsSecret);
                            }
                            StorePath = tlsSecret.Replace("secrets", "secrets/tls");

                            //Split storepath by / and remove first 2 elements
                            var storePathSplit = StorePath.Split('/');
                            var storePathSplitList = storePathSplit.ToList();
                            storePathSplitList.RemoveAt(0);
                            storePathSplitList.RemoveAt(0);
                            var alias = string.Join("/", storePathSplitList);

                            var entry = HandleTlsSecretAsEntry(config.JobHistoryId, alias);
                            if (entry.Certificates.Count > 0)
                            {
                                namespaceInventoryEntries.Add(entry);
                                Logger.LogDebug("Namespace inventory: Added TLS secret '{Alias}' with HasPrivateKey={HasPrivateKey}, CertCount={CertCount}",
                                    entry.Alias, entry.HasPrivateKey, entry.Certificates.Count);
                                Logger.LogTrace("Namespace inventory: Alias '{Alias}' certificate chain:\n{Chain}",
                                    entry.Alias, string.Join("\n---\n", entry.Certificates));
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.LogError("Error processing TLS Secret: " + tlsSecret + " - " + ex.Message + "\n\t" +
                                            ex.StackTrace);
                            namespaceErrors.Add(ex.Message);
                        }
                    }

                    Logger.LogDebug("Namespace inventory complete: {Count} secrets with per-item private key status", namespaceInventoryEntries.Count);
                    return PushInventory(namespaceInventoryEntries, config.JobHistoryId, submitInventory);

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

    /// <summary>
    /// Handles inventory of JKS (Java KeyStore) secrets stored in Kubernetes.
    /// Deserializes JKS data and extracts all certificates and their chains.
    /// </summary>
    /// <param name="config">Job configuration containing store properties.</param>
    /// <param name="allowedKeys">List of allowed secret data keys to process.</param>
    /// <returns>Dictionary mapping certificate aliases to their PEM certificate chains.</returns>
    private Dictionary<string, List<string>> HandleJKSSecret(JobConfiguration config, List<string> allowedKeys)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        var hasPrivateKeyJks = false;
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
            var keyPassword = getK8SStorePassword(k8sData.Secret);
            Logger.LogTrace("Password correlation for '{Secret}/{Key}': {CorrelationId}",
                KubeSecretName, keyName, LoggingUtilities.GetPasswordCorrelationId(keyPassword));
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
                if (jStoreDs.IsKeyEntry(certAlias)) hasPrivateKeyJks = true;
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

        Logger.LogDebug("JKS inventory complete with {Count} entries", jksInventoryDict.Count);
        Logger.MethodExit(MsLogLevel.Debug);
        return jksInventoryDict;
    }

    /// <summary>
    /// Handles inventory of Kubernetes Certificate Signing Requests (CSRs).
    /// If KubeSecretName is specified, inventories that specific CSR (legacy single-CSR mode).
    /// If KubeSecretName is empty or "*", inventories ALL issued CSRs in the cluster (cluster-wide mode).
    /// </summary>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <param name="submitInventory">Callback delegate to submit discovered certificates.</param>
    /// <returns>JobResult indicating success or failure.</returns>
    private JobResult HandleCertificate(long jobId, SubmitInventoryUpdate submitInventory)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogTrace("submitInventory: " + submitInventory);

        // Determine mode: single CSR or cluster-wide
        // Use the ORIGINAL KubeSecretName value from job config, not the potentially modified one
        // (InitializeStore may set KubeSecretName from StorePath if it was empty)
        var secretNameToCheck = _originalKubeSecretName ?? KubeSecretName;
        var isClusterWideMode = string.IsNullOrWhiteSpace(secretNameToCheck) || secretNameToCheck == "*";

        Logger.LogDebug("K8SCert mode detection: originalKubeSecretName='{Original}', KubeSecretName='{Current}', isClusterWideMode={IsClusterWide}",
            _originalKubeSecretName ?? "(null)", KubeSecretName, isClusterWideMode);

        if (isClusterWideMode)
        {
            Logger.LogDebug("Processing CSR inventory for job {JobId} - cluster-wide mode (all CSRs)", jobId);
            return HandleCertificateClusterWide(jobId, submitInventory);
        }
        else
        {
            // For single CSR mode, use the original KubeSecretName if it was explicitly set
            var csrName = !string.IsNullOrWhiteSpace(_originalKubeSecretName) ? _originalKubeSecretName : KubeSecretName;
            Logger.LogDebug("Processing CSR inventory for job {JobId} - single CSR mode (name: {CsrName})", jobId, csrName);
            return HandleCertificateSingle(jobId, submitInventory, csrName);
        }
    }

    /// <summary>
    /// Handles inventory of a single CSR by name (legacy behavior).
    /// </summary>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <param name="submitInventory">Callback delegate to submit discovered certificates.</param>
    /// <param name="csrName">The name of the CSR to inventory.</param>
    private JobResult HandleCertificateSingle(long jobId, SubmitInventoryUpdate submitInventory, string csrName)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogTrace("Calling GetCertificateSigningRequestStatus for CSR '{CsrName}'...", csrName);

        try
        {
            var certificates = KubeClient.GetCertificateSigningRequestStatus(csrName);
            Logger.LogDebug("GetCertificateSigningRequestStatus returned {Count} certificates.", certificates.Count());
            Logger.LogTrace(string.Join(",", certificates));
            Logger.LogDebug("Pushing {Count} certificates to inventory", certificates.Count());
            var result = PushInventory(certificates, jobId, submitInventory);
            Logger.MethodExit(MsLogLevel.Debug);
            return result;
        }
        catch (HttpOperationException e)
        {
            Logger.LogError("HttpOperationException: {Message}", e.Message);
            Logger.LogTrace(e.ToString());
            Logger.LogTrace(e.StackTrace);
            var certDataErrorMsg =
                $"Kubernetes CSR '{csrName}' was not found on host '{KubeClient.GetHost()}'.";
            Logger.LogError(certDataErrorMsg);
            var inventoryItems = new List<CurrentInventoryItem>();
            submitInventory.Invoke(inventoryItems);
            Logger.LogTrace("Exiting HandleCertificateSingle for job id " + jobId + "...");
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Success,
                JobHistoryId = jobId,
                FailureMessage = certDataErrorMsg
            };
        }
        catch (Exception e)
        {
            Logger.LogError("Exception: " + e.Message);
            Logger.LogTrace(e.ToString());
            Logger.LogTrace(e.StackTrace);
            var certDataErrorMsg = $"Error querying Kubernetes CSR API: {e.Message}";
            Logger.LogError(certDataErrorMsg);
            Logger.LogTrace("Exiting HandleCertificateSingle for job id " + jobId + "...");
            return FailJob(certDataErrorMsg, jobId);
        }
    }

    /// <summary>
    /// Handles inventory of all CSRs in the cluster (new cluster-wide behavior).
    /// </summary>
    private JobResult HandleCertificateClusterWide(long jobId, SubmitInventoryUpdate submitInventory)
    {
        Logger.MethodEntry(MsLogLevel.Debug);

        try
        {
            // List all CSRs in the cluster that have issued certificates
            var csrCertificates = KubeClient.ListAllCertificateSigningRequests();
            Logger.LogDebug("Found {Count} issued certificates from CSRs", csrCertificates.Count);

            if (csrCertificates.Count == 0)
            {
                Logger.LogInformation("No issued CSR certificates found in cluster");
                submitInventory.Invoke(new List<CurrentInventoryItem>());
                return new JobResult
                {
                    Result = OrchestratorJobStatusJobResult.Success,
                    JobHistoryId = jobId,
                    FailureMessage = "No issued CSR certificates found in cluster"
                };
            }

            var inventoryItems = new List<CurrentInventoryItem>();
            foreach (var kvp in csrCertificates)
            {
                var csrName = kvp.Key;
                var certPem = kvp.Value;

                Logger.LogDebug("Processing CSR {CsrName}", csrName);
                Logger.LogTrace("Certificate PEM: {CertPem}", certPem);

                try
                {
                    // Parse the certificate chain - CSRs can contain multiple certificates if signed by a CA with intermediates
                    var certChain = KubeClient.LoadCertificateChain(certPem);
                    if (certChain == null || certChain.Count == 0)
                    {
                        Logger.LogWarning("Failed to parse certificate chain from CSR {CsrName}, skipping", csrName);
                        continue;
                    }

                    // Convert each certificate in the chain to PEM format
                    var certPemList = new List<string>();
                    foreach (var cert in certChain)
                    {
                        var pem = KubeClient.ConvertToPem(cert);
                        certPemList.Add(pem);
                    }

                    Logger.LogDebug("CSR {CsrName} has {Count} certificate(s) in chain", csrName, certPemList.Count);
                    Logger.LogTrace("CSR {CsrName} certificate chain:\n{Chain}", csrName, string.Join("\n---\n", certPemList));

                    // Use CSR name as the alias for easy identification
                    var inventoryItem = new CurrentInventoryItem
                    {
                        Alias = csrName,
                        PrivateKeyEntry = false, // CSRs never have private keys in K8s
                        UseChainLevel = certPemList.Count > 1,
                        ItemStatus = OrchestratorInventoryItemStatus.Unknown,
                        Certificates = certPemList.ToArray()
                    };

                    inventoryItems.Add(inventoryItem);
                    Logger.LogDebug("Added CSR {CsrName} to inventory with {CertCount} certificates", csrName, certPemList.Count);
                }
                catch (Exception ex)
                {
                    Logger.LogWarning(ex, "Error processing certificate from CSR {CsrName}, skipping", csrName);
                }
            }

            Logger.LogDebug("Submitting {Count} CSR certificates to inventory", inventoryItems.Count);
            submitInventory.Invoke(inventoryItems);

            Logger.MethodExit(MsLogLevel.Debug);
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Success,
                JobHistoryId = jobId
            };
        }
        catch (Exception e)
        {
            Logger.LogError(e, "Error listing CSRs from cluster: {Message}", e.Message);
            var certDataErrorMsg = $"Error querying Kubernetes CSR API: {e.Message}";
            Logger.LogTrace("Exiting HandleCertificateClusterWide for job id " + jobId + "...");
            return FailJob(certDataErrorMsg, jobId);
        }
    }

    /// <summary>
    /// Submits discovered certificates to Keyfactor Command.
    /// Converts certificate strings to CurrentInventoryItem objects and invokes the submit callback.
    /// </summary>
    /// <param name="certsList">Collection of PEM-formatted certificate strings.</param>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <param name="submitInventory">Callback delegate to submit certificates to Keyfactor Command.</param>
    /// <param name="hasPrivateKey">Whether the certificates have associated private keys in the store.</param>
    /// <param name="jobMessage">Optional message to include in the job result.</param>
    /// <returns>JobResult indicating success or failure of the submission.</returns>
    private JobResult PushInventory(IEnumerable<string> certsList, long jobId, SubmitInventoryUpdate submitInventory,
        bool hasPrivateKey = false, string jobMessage = null)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Processing certificate list for job {JobId}", jobId);
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
                Logger.LogDebug("Attempting to parse certificate using BouncyCastle...");
                var bcCert = cert.Contains("BEGIN CERTIFICATE")
                    ? Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.ParseCertificateFromPem(cert)
                    : Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.ParseCertificateFromDer(Convert.FromBase64String(cert));
                Logger.LogTrace("Certificate parsed successfully: " + bcCert.SubjectDN);
                Logger.LogDebug("Attempting to get certificate thumbprint...");
                alias = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.GetThumbprint(bcCert);
                Logger.LogDebug("Certificate thumbprint: " + alias);
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

    /// <summary>
    /// Submits discovered certificates (dictionary variant) to Keyfactor Command.
    /// Used for namespace-level inventory where certificates are keyed by their store path.
    /// </summary>
    /// <param name="certsList">Dictionary mapping store paths to PEM certificate strings.</param>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <param name="submitInventory">Callback delegate to submit certificates to Keyfactor Command.</param>
    /// <param name="hasPrivateKey">Whether the certificates have associated private keys in the store.</param>
    /// <returns>JobResult indicating success or failure of the submission.</returns>
    private JobResult PushInventory(Dictionary<string, string> certsList, long jobId,
        SubmitInventoryUpdate submitInventory, bool hasPrivateKey = false)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Processing {Count} certificate entries for job {JobId}", certsList.Count, jobId);
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
                Logger.LogDebug("Attempting to parse certificate using BouncyCastle...");
                var bcCert = cert.Contains("BEGIN CERTIFICATE")
                    ? Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.ParseCertificateFromPem(cert)
                    : Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.ParseCertificateFromDer(Convert.FromBase64String(cert));
                Logger.LogTrace("Certificate parsed successfully: " + bcCert.SubjectDN);
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

    /// <summary>
    /// Submits discovered certificates with chains (dictionary variant) to Keyfactor Command.
    /// Used for JKS/PKCS12 inventory where each alias has a certificate chain.
    /// </summary>
    /// <param name="certsList">Dictionary mapping aliases to lists of PEM certificates (chains).</param>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <param name="submitInventory">Callback delegate to submit certificates to Keyfactor Command.</param>
    /// <param name="hasPrivateKey">Whether the certificates have associated private keys in the store.</param>
    /// <returns>JobResult indicating success or failure of the submission.</returns>
    private JobResult PushInventory(Dictionary<string, List<string>> certsList, long jobId,
        SubmitInventoryUpdate submitInventory, bool hasPrivateKey = false)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Processing {Count} certificate chain entries for job {JobId}", certsList.Count, jobId);
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

    /// <summary>
    /// Submits discovered certificates with per-item private key status to Keyfactor Command.
    /// Used for K8SNS and K8SCluster inventory where each secret may have different private key status.
    /// </summary>
    /// <param name="entries">List of inventory entries with per-item private key status and certificate chains.</param>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <param name="submitInventory">Callback delegate to submit certificates to Keyfactor Command.</param>
    /// <returns>JobResult indicating success or failure of the submission.</returns>
    private JobResult PushInventory(List<InventoryEntry> entries, long jobId, SubmitInventoryUpdate submitInventory)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Processing {Count} inventory entries with per-item private key status for job {JobId}", entries.Count, jobId);

        var inventoryItems = new List<CurrentInventoryItem>();

        foreach (var entry in entries)
        {
            if (entry.Certificates == null || entry.Certificates.Count == 0)
            {
                Logger.LogWarning("Skipping entry '{Alias}' - no certificates", entry.Alias);
                continue;
            }

            Logger.LogDebug("Adding entry '{Alias}' with {CertCount} certificates, HasPrivateKey={HasPrivateKey}",
                entry.Alias, entry.Certificates.Count, entry.HasPrivateKey);

            inventoryItems.Add(new CurrentInventoryItem
            {
                ItemStatus = OrchestratorInventoryItemStatus.Unknown,
                Alias = entry.Alias,
                PrivateKeyEntry = entry.HasPrivateKey,
                UseChainLevel = entry.Certificates.Count > 1,
                Certificates = entry.Certificates.ToArray()
            });
        }

        try
        {
            Logger.LogDebug("Submitting {Count} inventory items to Keyfactor Command...", inventoryItems.Count);
            submitInventory.Invoke(inventoryItems);
            Logger.LogInformation("End INVENTORY completed successfully for job id {JobId}.", jobId);
            return SuccessJob(jobId);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Unable to submit inventory to Keyfactor Command for job id {JobId}.", jobId);
            return FailJob(ex.Message, jobId);
        }
    }

    /// <summary>
    /// Handles inventory of Kubernetes Opaque secrets and returns certificate list.
    /// Extracts certificates from the secret's data fields using OpaqueAllowedKeys.
    /// </summary>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <returns>List of PEM-formatted certificates found in the opaque secret.</returns>
    /// <exception cref="StoreNotFoundException">Thrown when the secret cannot be found.</exception>
    /// <exception cref="Exception">Thrown when an error occurs querying the K8S API.</exception>
    private List<string> HandleOpaqueSecretAsList(long jobId)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Processing opaque secret inventory for job {JobId}", jobId);
        Logger.LogTrace("KubeNamespace: " + KubeNamespace);
        Logger.LogTrace("KubeSecretName: " + KubeSecretName);
        Logger.LogTrace("StorePath: " + StorePath);

        if (string.IsNullOrEmpty(KubeNamespace))
        {
            Logger.LogWarning("KubeNamespace is null or empty. Attempting to parse from StorePath...");
            if (!string.IsNullOrEmpty(StorePath))
            {
                KubeNamespace = StorePath.Split("/").First();
                Logger.LogTrace("KubeNamespace: " + KubeNamespace);
                if (KubeNamespace == KubeSecretName)
                {
                    Logger.LogWarning("KubeNamespace was equal to KubeSecretName. Setting KubeNamespace to 'default'...");
                    KubeNamespace = "default";
                }
            }
            else
            {
                Logger.LogWarning("StorePath was null or empty. Setting KubeNamespace to 'default'...");
                KubeNamespace = "default";
            }
        }

        if (string.IsNullOrEmpty(KubeSecretName) && !string.IsNullOrEmpty(StorePath))
        {
            Logger.LogWarning("KubeSecretName is null or empty. Attempting to parse from StorePath...");
            KubeSecretName = StorePath.Split("/").Last();
            Logger.LogTrace("KubeSecretName: " + KubeSecretName);
        }

        Logger.LogDebug($"Querying Kubernetes opaque secret API for {KubeSecretName} in namespace {KubeNamespace}...");
        try
        {
            var certData = KubeClient.GetCertificateStoreSecret(KubeSecretName, KubeNamespace);
            var certsList = new List<string>();

            // First, process the primary certificate field (tls.crt, cert, etc.) - excludes ca.crt
            var primaryCertKeys = OpaqueAllowedKeys.Where(k => k != "ca.crt").ToArray();
            foreach (var allowedKey in primaryCertKeys)
            {
                if (!certData.Data.ContainsKey(allowedKey)) continue;

                Logger.LogDebug("Found certificate data in key: {Key}", allowedKey);
                var certificatesBytes = certData.Data[allowedKey];

                // Skip empty certificate data
                if (certificatesBytes == null || certificatesBytes.Length == 0)
                {
                    Logger.LogDebug("Certificate data in key '{Key}' is empty, skipping", allowedKey);
                    continue;
                }

                var certPemData = Encoding.UTF8.GetString(certificatesBytes);

                // Skip empty or whitespace-only certificate data
                if (string.IsNullOrWhiteSpace(certPemData))
                {
                    Logger.LogDebug("Certificate data in key '{Key}' is empty or whitespace, skipping", allowedKey);
                    continue;
                }

                // Use LoadCertificateChain to handle multiple certificates in the field
                var certChain = KubeClient.LoadCertificateChain(certPemData);
                if (certChain != null && certChain.Count > 0)
                {
                    Logger.LogDebug("Found {Count} certificate(s) in key '{Key}'", certChain.Count, allowedKey);
                    foreach (var cert in certChain)
                    {
                        var certPem = KubeClient.ConvertToPem(cert);
                        Logger.LogTrace("Adding certificate from '{Key}': {Subject}", allowedKey, cert.SubjectDN);
                        certsList.Add(certPem);
                    }
                    // Found certificates in this key, don't process other primary keys
                    break;
                }
                else
                {
                    // Try to parse as single DER certificate
                    Logger.LogDebug("Failed to parse as PEM chain. Attempting to parse as DER...");
                    var certObj = KubeClient.ReadDerCertificate(certPemData);
                    if (certObj != null)
                    {
                        var certPem = KubeClient.ConvertToPem(certObj);
                        certsList.Add(certPem);
                        break;
                    }
                    else
                    {
                        Logger.LogWarning(
                            "Failed to parse certificate from secret '{SecretName}' key '{Key}' in namespace '{Namespace}'. " +
                            "The certificate data could not be parsed as PEM or DER format. Skipping this key.",
                            KubeSecretName, allowedKey, KubeNamespace);
                    }
                }
            }

            // Then, process ca.crt separately to add chain certificates
            if (certData.Data.TryGetValue("ca.crt", out var caBytes))
            {
                if (caBytes != null && caBytes.Length > 0)
                {
                    var caCertPemData = Encoding.UTF8.GetString(caBytes);
                    if (!string.IsNullOrWhiteSpace(caCertPemData))
                    {
                        // ca.crt can contain multiple certificates (intermediate + root)
                        var caCertChain = KubeClient.LoadCertificateChain(caCertPemData);
                        if (caCertChain != null && caCertChain.Count > 0)
                        {
                            Logger.LogDebug("Found {Count} certificate(s) in ca.crt", caCertChain.Count);
                            foreach (var caCert in caCertChain)
                            {
                                var caPem = KubeClient.ConvertToPem(caCert);
                                // Avoid duplicates - check if certificate is already in the list
                                if (!certsList.Contains(caPem))
                                {
                                    Logger.LogTrace("Adding CA certificate from ca.crt: {Subject}", caCert.SubjectDN);
                                    certsList.Add(caPem);
                                }
                            }
                        }
                        else
                        {
                            // Fallback: try to read as a single DER certificate
                            var caObj = KubeClient.ReadDerCertificate(caCertPemData);
                            if (caObj != null)
                            {
                                var caPem = KubeClient.ConvertToPem(caObj);
                                if (!certsList.Contains(caPem))
                                {
                                    certsList.Add(caPem);
                                }
                            }
                        }
                    }
                }
            }

            Logger.LogTrace("certsList count: " + certsList.Count);
            Logger.MethodExit(MsLogLevel.Debug);
            return certsList;
        }
        catch (HttpOperationException e)
        {
            Logger.LogError(e.Message);
            var certDataErrorMsg = $"Kubernetes opaque secret '{KubeSecretName}' was not found in namespace '{KubeNamespace}'.";
            Logger.LogError(certDataErrorMsg);
            throw new StoreNotFoundException(certDataErrorMsg);
        }
        catch (Exception e) when (e is not StoreNotFoundException && e is not InvalidOperationException)
        {
            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
            Logger.LogError(certDataErrorMsg);
            throw new Exception(certDataErrorMsg);
        }
    }

    /// <summary>
    /// Handles inventory of Kubernetes Opaque secrets containing certificate data.
    /// Extracts certificates from the secret's data fields using the specified managed keys.
    /// </summary>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <param name="submitInventory">Callback delegate to submit discovered certificates.</param>
    /// <param name="secretManagedKeys">Array of secret data keys to check for certificate data.</param>
    /// <param name="secretPath">Optional path specification for the secret.</param>
    /// <returns>JobResult indicating success or failure.</returns>
    private JobResult HandleOpaqueSecret(long jobId, SubmitInventoryUpdate submitInventory, string[] secretManagedKeys,
        string secretPath = "")
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Processing opaque secret inventory for job {JobId}", jobId);
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


    /// <summary>
    /// Handles inventory of a TLS secret and returns an InventoryEntry with certificate chain and private key status.
    /// Used for K8SNS and K8SCluster inventory where per-item private key status is needed.
    /// </summary>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <param name="alias">The alias to use for the inventory entry.</param>
    /// <returns>InventoryEntry with certificates and private key status.</returns>
    private InventoryEntry HandleTlsSecretAsEntry(long jobId, string alias)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Processing TLS secret as inventory entry for job {JobId}, alias {Alias}", jobId, alias);

        var certs = HandleTlsSecretWithPrivateKeyStatus(jobId, out var hasPrivateKey);

        var entry = new InventoryEntry
        {
            Alias = alias,
            Certificates = certs,
            HasPrivateKey = hasPrivateKey
        };

        Logger.LogDebug("Created inventory entry for alias '{Alias}' with {CertCount} certificates, HasPrivateKey={HasPrivateKey}",
            alias, certs.Count, hasPrivateKey);
        Logger.MethodExit(MsLogLevel.Debug);
        return entry;
    }

    /// <summary>
    /// Handles inventory of an opaque secret and returns an InventoryEntry with certificate chain and private key status.
    /// Used for K8SNS and K8SCluster inventory where per-item private key status is needed.
    /// </summary>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <param name="alias">The alias to use for the inventory entry.</param>
    /// <returns>InventoryEntry with certificates and private key status.</returns>
    private InventoryEntry HandleOpaqueSecretAsEntry(long jobId, string alias)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Processing opaque secret as inventory entry for job {JobId}, alias {Alias}", jobId, alias);

        var certs = HandleOpaqueSecretWithPrivateKeyStatus(jobId, out var hasPrivateKey);

        var entry = new InventoryEntry
        {
            Alias = alias,
            Certificates = certs,
            HasPrivateKey = hasPrivateKey
        };

        Logger.LogDebug("Created inventory entry for alias '{Alias}' with {CertCount} certificates, HasPrivateKey={HasPrivateKey}",
            alias, certs.Count, hasPrivateKey);
        Logger.MethodExit(MsLogLevel.Debug);
        return entry;
    }

    /// <summary>
    /// Handles inventory of Kubernetes TLS secrets with private key status detection.
    /// </summary>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <param name="hasPrivateKey">Output parameter indicating whether the secret has a private key.</param>
    /// <returns>List of PEM-formatted certificates (chain if present).</returns>
    private List<string> HandleTlsSecretWithPrivateKeyStatus(long jobId, out bool hasPrivateKey)
    {
        hasPrivateKey = false;
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Processing TLS secret inventory with private key status for job {JobId}", jobId);
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
                    Logger.LogWarning(
                        "KubeNamespace was equal to KubeSecretName.  Setting KubeNamespace to 'default' for job id " +
                        jobId + "...");
                    KubeNamespace = "default";
                }
            }
            else
            {
                Logger.LogWarning("StorePath was null or empty.  Setting KubeNamespace to 'default' for job id " +
                                  jobId + "...");
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
        Logger.LogTrace("Entering try block for HandleTlsSecretWithPrivateKeyStatus...");
        try
        {
            Logger.LogTrace("Calling KubeClient.GetCertificateStoreSecret()...");
            var certData = KubeClient.GetCertificateStoreSecret(
                KubeSecretName,
                KubeNamespace
            );
            Logger.LogDebug("KubeClient.GetCertificateStoreSecret() returned successfully.");
            Logger.LogTrace("certData: " + certData);

            // Check if tls.crt exists and has data
            if (!certData.Data.TryGetValue("tls.crt", out var certificatesBytes) ||
                certificatesBytes == null || certificatesBytes.Length == 0)
            {
                Logger.LogWarning("Secret '{SecretName}' in namespace '{Namespace}' has no certificate data (tls.crt is empty or missing). Returning empty inventory.",
                    KubeSecretName, KubeNamespace);
                return new List<string>();
            }

            Logger.LogTrace("certificatesBytes: " + certificatesBytes);

            // Check if tls.key exists and has actual content (not empty/whitespace)
            if (certData.Data.TryGetValue("tls.key", out var privateKeyBytes) &&
                privateKeyBytes != null && privateKeyBytes.Length > 0)
            {
                var privateKeyContent = Encoding.UTF8.GetString(privateKeyBytes);
                // Check if it's not just whitespace or empty
                hasPrivateKey = !string.IsNullOrWhiteSpace(privateKeyContent);
                Logger.LogDebug("tls.key exists with content: {HasContent}, HasPrivateKey={HasPrivateKey}",
                    !string.IsNullOrWhiteSpace(privateKeyContent), hasPrivateKey);
            }
            else
            {
                Logger.LogDebug("tls.key is missing or empty. HasPrivateKey=false");
                hasPrivateKey = false;
            }

            byte[] caBytes = null;
            var certsList = new List<string>();

            var certPem = Encoding.UTF8.GetString(certificatesBytes);

            // Check if the certificate data is empty or whitespace-only
            if (string.IsNullOrWhiteSpace(certPem))
            {
                Logger.LogWarning("Secret '{SecretName}' in namespace '{Namespace}' has empty certificate data. Returning empty inventory.",
                    KubeSecretName, KubeNamespace);
                return new List<string>();
            }

            Logger.LogTrace("certPem: " + certPem);
            var certObj = KubeClient.ReadPemCertificate(certPem);
            if (certObj == null)
            {
                Logger.LogDebug(
                    "Failed to parse certificate from opaque secret data as PEM. Attempting to parse as DER");
                // Attempt to read data as DER
                certObj = KubeClient.ReadDerCertificate(certPem);
                if (certObj != null)
                {
                    certPem = KubeClient.ConvertToPem(certObj);
                    Logger.LogTrace("certPem: " + certPem);
                }
                else
                {
                    // Both PEM and DER parsing failed - throw a meaningful error
                    throw new InvalidOperationException(
                        $"Failed to parse certificate from secret '{KubeSecretName}' in namespace '{KubeNamespace}'. " +
                        "The certificate data could not be parsed as PEM or DER format.");
                }

                Logger.LogTrace("certPem: " + certPem);
            }
            else
            {
                certPem = KubeClient.ConvertToPem(certObj);
                Logger.LogTrace("certPem: " + certPem);
            }

            if (!string.IsNullOrEmpty(certPem)) certsList.Add(certPem);

            if (certData.Data.TryGetValue("ca.crt", out var value))
            {
                caBytes = value;
                Logger.LogTrace("caBytes length: {Length}", caBytes?.Length ?? 0);

                // ca.crt can contain multiple certificates (e.g., intermediate + root)
                // Use LoadCertificateChain to parse all certificates
                var caCertChain = KubeClient.LoadCertificateChain(Encoding.UTF8.GetString(caBytes));
                if (caCertChain != null && caCertChain.Count > 0)
                {
                    Logger.LogDebug("Found {Count} certificate(s) in ca.crt", caCertChain.Count);
                    foreach (var caCert in caCertChain)
                    {
                        var caPem = KubeClient.ConvertToPem(caCert);
                        Logger.LogTrace("Adding CA certificate to inventory: {Subject}", caCert.SubjectDN);
                        certsList.Add(caPem);
                    }
                }
                else
                {
                    Logger.LogDebug("Failed to parse certificate chain from ca.crt as PEM. Attempting to parse as single DER certificate");
                    // Fallback: try to read as a single DER certificate
                    var caObj = KubeClient.ReadDerCertificate(Encoding.UTF8.GetString(caBytes));
                    if (caObj != null)
                    {
                        var caPem = KubeClient.ConvertToPem(caObj);
                        Logger.LogTrace("caPem: " + caPem);
                        certsList.Add(caPem);
                    }
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

            Logger.LogTrace("certsList: " + certsList);
            Logger.LogDebug("Returning certificate list with {Count} certificates and HasPrivateKey={HasPrivateKey}", certsList.Count, hasPrivateKey);
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

    /// <summary>
    /// Handles inventory of Kubernetes Opaque secrets with private key status detection.
    /// </summary>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <param name="hasPrivateKey">Output parameter indicating whether the secret has a private key.</param>
    /// <returns>List of PEM-formatted certificates found in the opaque secret.</returns>
    private List<string> HandleOpaqueSecretWithPrivateKeyStatus(long jobId, out bool hasPrivateKey)
    {
        hasPrivateKey = false;
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Processing opaque secret inventory with private key status for job {JobId}", jobId);
        Logger.LogTrace("KubeNamespace: " + KubeNamespace);
        Logger.LogTrace("KubeSecretName: " + KubeSecretName);
        Logger.LogTrace("StorePath: " + StorePath);

        if (string.IsNullOrEmpty(KubeNamespace))
        {
            Logger.LogWarning("KubeNamespace is null or empty. Attempting to parse from StorePath...");
            if (!string.IsNullOrEmpty(StorePath))
            {
                KubeNamespace = StorePath.Split("/").First();
                Logger.LogTrace("KubeNamespace: " + KubeNamespace);
                if (KubeNamespace == KubeSecretName)
                {
                    Logger.LogWarning("KubeNamespace was equal to KubeSecretName. Setting KubeNamespace to 'default'...");
                    KubeNamespace = "default";
                }
            }
            else
            {
                Logger.LogWarning("StorePath was null or empty. Setting KubeNamespace to 'default'...");
                KubeNamespace = "default";
            }
        }

        if (string.IsNullOrEmpty(KubeSecretName) && !string.IsNullOrEmpty(StorePath))
        {
            Logger.LogWarning("KubeSecretName is null or empty. Attempting to parse from StorePath...");
            KubeSecretName = StorePath.Split("/").Last();
            Logger.LogTrace("KubeSecretName: " + KubeSecretName);
        }

        Logger.LogDebug($"Querying Kubernetes opaque secret API for {KubeSecretName} in namespace {KubeNamespace}...");
        try
        {
            var certData = KubeClient.GetCertificateStoreSecret(KubeSecretName, KubeNamespace);
            var certsList = new List<string>();

            // Check for private key in common key field names
            var privateKeyFields = new[] { "tls.key", "key", "private.key", "privateKey", "key.pem" };
            foreach (var keyField in privateKeyFields)
            {
                if (certData.Data.TryGetValue(keyField, out var keyBytes) &&
                    keyBytes != null && keyBytes.Length > 0)
                {
                    var keyContent = Encoding.UTF8.GetString(keyBytes);
                    if (!string.IsNullOrWhiteSpace(keyContent))
                    {
                        hasPrivateKey = true;
                        Logger.LogDebug("Found private key in field '{KeyField}'", keyField);
                        break;
                    }
                }
            }

            // First, process the primary certificate field (tls.crt, cert, etc.) - excludes ca.crt
            var primaryCertKeys = OpaqueAllowedKeys.Where(k => k != "ca.crt").ToArray();
            foreach (var allowedKey in primaryCertKeys)
            {
                if (!certData.Data.ContainsKey(allowedKey)) continue;

                Logger.LogDebug("Found certificate data in key: {Key}", allowedKey);
                var certificatesBytes = certData.Data[allowedKey];

                // Skip empty certificate data
                if (certificatesBytes == null || certificatesBytes.Length == 0)
                {
                    Logger.LogDebug("Certificate data in key '{Key}' is empty, skipping", allowedKey);
                    continue;
                }

                var certPemData = Encoding.UTF8.GetString(certificatesBytes);

                // Skip empty or whitespace-only certificate data
                if (string.IsNullOrWhiteSpace(certPemData))
                {
                    Logger.LogDebug("Certificate data in key '{Key}' is empty or whitespace, skipping", allowedKey);
                    continue;
                }

                // Use LoadCertificateChain to handle multiple certificates in the field
                var certChain = KubeClient.LoadCertificateChain(certPemData);
                if (certChain != null && certChain.Count > 0)
                {
                    Logger.LogDebug("Found {Count} certificate(s) in key '{Key}'", certChain.Count, allowedKey);
                    foreach (var cert in certChain)
                    {
                        var certPem = KubeClient.ConvertToPem(cert);
                        Logger.LogTrace("Adding certificate from '{Key}': {Subject}", allowedKey, cert.SubjectDN);
                        certsList.Add(certPem);
                    }
                    // Found certificates in this key, don't process other primary keys
                    break;
                }
                else
                {
                    // Try to parse as single DER certificate
                    Logger.LogDebug("Failed to parse as PEM chain. Attempting to parse as DER...");
                    var certObj = KubeClient.ReadDerCertificate(certPemData);
                    if (certObj != null)
                    {
                        var certPem = KubeClient.ConvertToPem(certObj);
                        certsList.Add(certPem);
                        break;
                    }
                    else
                    {
                        Logger.LogWarning(
                            "Failed to parse certificate from secret '{SecretName}' key '{Key}' in namespace '{Namespace}'. " +
                            "The certificate data could not be parsed as PEM or DER format. Skipping this key.",
                            KubeSecretName, allowedKey, KubeNamespace);
                    }
                }
            }

            // Then, process ca.crt separately to add chain certificates
            if (certData.Data.TryGetValue("ca.crt", out var caBytes))
            {
                if (caBytes != null && caBytes.Length > 0)
                {
                    var caCertPemData = Encoding.UTF8.GetString(caBytes);
                    if (!string.IsNullOrWhiteSpace(caCertPemData))
                    {
                        // ca.crt can contain multiple certificates (intermediate + root)
                        var caCertChain = KubeClient.LoadCertificateChain(caCertPemData);
                        if (caCertChain != null && caCertChain.Count > 0)
                        {
                            Logger.LogDebug("Found {Count} certificate(s) in ca.crt", caCertChain.Count);
                            foreach (var caCert in caCertChain)
                            {
                                var caPem = KubeClient.ConvertToPem(caCert);
                                // Avoid duplicates - check if certificate is already in the list
                                if (!certsList.Contains(caPem))
                                {
                                    Logger.LogTrace("Adding CA certificate from ca.crt: {Subject}", caCert.SubjectDN);
                                    certsList.Add(caPem);
                                }
                            }
                        }
                        else
                        {
                            // Fallback: try to read as a single DER certificate
                            var caObj = KubeClient.ReadDerCertificate(caCertPemData);
                            if (caObj != null)
                            {
                                var caPem = KubeClient.ConvertToPem(caObj);
                                if (!certsList.Contains(caPem))
                                {
                                    certsList.Add(caPem);
                                }
                            }
                        }
                    }
                }
            }

            Logger.LogTrace("certsList count: " + certsList.Count);
            Logger.LogDebug("Returning certificate list with {Count} certificates and HasPrivateKey={HasPrivateKey}", certsList.Count, hasPrivateKey);
            Logger.MethodExit(MsLogLevel.Debug);
            return certsList;
        }
        catch (HttpOperationException e)
        {
            Logger.LogError(e.Message);
            var certDataErrorMsg = $"Kubernetes opaque secret '{KubeSecretName}' was not found in namespace '{KubeNamespace}'.";
            Logger.LogError(certDataErrorMsg);
            throw new StoreNotFoundException(certDataErrorMsg);
        }
        catch (Exception e) when (e is not StoreNotFoundException && e is not InvalidOperationException)
        {
            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
            Logger.LogError(certDataErrorMsg);
            throw new Exception(certDataErrorMsg);
        }
    }

    /// <summary>
    /// Handles inventory of Kubernetes TLS secrets (kubernetes.io/tls type).
    /// Extracts certificate from tls.crt and optionally the CA from ca.crt.
    /// </summary>
    /// <param name="jobId">The job history ID for tracking.</param>
    /// <returns>List of PEM-formatted certificates (chain if present).</returns>
    /// <exception cref="StoreNotFoundException">Thrown when the secret cannot be found.</exception>
    /// <exception cref="Exception">Thrown when an error occurs querying the K8S API.</exception>
    private List<string> HandleTlsSecret(long jobId)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Processing TLS secret inventory for job {JobId}", jobId);
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
                    Logger.LogWarning(
                        "KubeNamespace was equal to KubeSecretName.  Setting KubeNamespace to 'default' for job id " +
                        jobId + "...");
                    KubeNamespace = "default";
                }
            }
            else
            {
                Logger.LogWarning("StorePath was null or empty.  Setting KubeNamespace to 'default' for job id " +
                                  jobId + "...");
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

            // Check if tls.crt exists and has data
            if (!certData.Data.TryGetValue("tls.crt", out var certificatesBytes) ||
                certificatesBytes == null || certificatesBytes.Length == 0)
            {
                Logger.LogWarning("Secret '{SecretName}' in namespace '{Namespace}' has no certificate data (tls.crt is empty or missing). Returning empty inventory.",
                    KubeSecretName, KubeNamespace);
                return new List<string>();
            }

            Logger.LogTrace("certificatesBytes: " + certificatesBytes);

            // Check if tls.key exists (may be empty for cert-only secrets)
            certData.Data.TryGetValue("tls.key", out var privateKeyBytes);
            byte[] caBytes = null;
            var certsList = new List<string>();

            var certPem = Encoding.UTF8.GetString(certificatesBytes);

            // Check if the certificate data is empty or whitespace-only
            if (string.IsNullOrWhiteSpace(certPem))
            {
                Logger.LogWarning("Secret '{SecretName}' in namespace '{Namespace}' has empty certificate data. Returning empty inventory.",
                    KubeSecretName, KubeNamespace);
                return new List<string>();
            }

            Logger.LogTrace("certPem: " + certPem);
            var certObj = KubeClient.ReadPemCertificate(certPem);
            if (certObj == null)
            {
                Logger.LogDebug(
                    "Failed to parse certificate from opaque secret data as PEM. Attempting to parse as DER");
                // Attempt to read data as DER
                certObj = KubeClient.ReadDerCertificate(certPem);
                if (certObj != null)
                {
                    certPem = KubeClient.ConvertToPem(certObj);
                    Logger.LogTrace("certPem: " + certPem);
                }
                else
                {
                    // Both PEM and DER parsing failed - throw a meaningful error
                    throw new InvalidOperationException(
                        $"Failed to parse certificate from secret '{KubeSecretName}' in namespace '{KubeNamespace}'. " +
                        "The certificate data could not be parsed as PEM or DER format.");
                }

                Logger.LogTrace("certPem: " + certPem);
            }
            else
            {
                certPem = KubeClient.ConvertToPem(certObj);
                Logger.LogTrace("certPem: " + certPem);
            }

            if (!string.IsNullOrEmpty(certPem)) certsList.Add(certPem);

            if (certData.Data.TryGetValue("ca.crt", out var value))
            {
                caBytes = value;
                Logger.LogTrace("caBytes length: {Length}", caBytes?.Length ?? 0);

                // ca.crt can contain multiple certificates (e.g., intermediate + root)
                // Use LoadCertificateChain to parse all certificates
                var caCertChain = KubeClient.LoadCertificateChain(Encoding.UTF8.GetString(caBytes));
                if (caCertChain != null && caCertChain.Count > 0)
                {
                    Logger.LogDebug("Found {Count} certificate(s) in ca.crt", caCertChain.Count);
                    foreach (var caCert in caCertChain)
                    {
                        var caPem = KubeClient.ConvertToPem(caCert);
                        Logger.LogTrace("Adding CA certificate to inventory: {Subject}", caCert.SubjectDN);
                        certsList.Add(caPem);
                    }
                }
                else
                {
                    Logger.LogDebug("Failed to parse certificate chain from ca.crt as PEM. Attempting to parse as single DER certificate");
                    // Fallback: try to read as a single DER certificate
                    var caObj = KubeClient.ReadDerCertificate(Encoding.UTF8.GetString(caBytes));
                    if (caObj != null)
                    {
                        var caPem = KubeClient.ConvertToPem(caObj);
                        Logger.LogTrace("caPem: " + caPem);
                        certsList.Add(caPem);
                    }
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
                Logger.LogDebug("privateKeyBytes was null.  Setting hasPrivateKey to false for job id " + jobId +
                                "...");
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

    /// <summary>
    /// Handles inventory of PKCS12/PFX keystores stored in Kubernetes secrets.
    /// Deserializes PKCS12 data and extracts all certificates and their chains.
    /// </summary>
    /// <param name="config">Job configuration containing store properties.</param>
    /// <param name="allowedKeys">List of allowed secret data keys to process.</param>
    /// <returns>Dictionary mapping certificate aliases to their PEM certificate chains.</returns>
    private Dictionary<string, List<string>> HandlePkcs12Secret(JobConfiguration config, List<string> allowedKeys)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
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
                if (pStoreDs.IsKeyEntry(certAlias)) hasPrivateKey = true;
                var pKey = pStoreDs.GetKey(certAlias);
                if (pKey != null) hasPrivateKey = true;

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

        Logger.LogDebug("PKCS12 inventory complete with {Count} entries", pkcs12InventoryDict.Count);
        Logger.MethodExit(MsLogLevel.Debug);
        return pkcs12InventoryDict;
    }
}