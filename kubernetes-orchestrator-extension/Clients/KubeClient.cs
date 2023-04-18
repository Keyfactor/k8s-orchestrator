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
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using k8s;
using k8s.Autorest;
using k8s.KubeConfigModels;
using k8s.Models;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Keyfactor.Extensions.Orchestrator.K8S;

public class KubeCertificateManagerClient
{

    internal protected ILogger Logger;
    public KubeCertificateManagerClient(string kubeconfig)
    {
        Logger = LogHandler.GetClassLogger(GetType());
        Client = GetKubeClient(kubeconfig);
        
    }

    private IKubernetes Client { get; set; }

    public string GetHost()
    {
        Logger.LogTrace("Entered GetHost()");
        return Client.BaseUri.ToString();
    }

    private K8SConfiguration ParseKubeConfig(string kubeconfig)
    {
        Logger.LogTrace("Entered ParseKubeConfig()");
        var k8SConfiguration = new K8SConfiguration();
        // test if kubeconfig is base64 encoded
        Logger.LogDebug("Testing if kubeconfig is base64 encoded");
        try
        {
            var decodedKubeconfig = Encoding.UTF8.GetString(Convert.FromBase64String(kubeconfig));
            kubeconfig = decodedKubeconfig;
            Logger.LogDebug("Successfully decoded kubeconfig from base64");
        }
        catch
        {
            // not base64 encoded so do nothing
        }

        // check if json is escaped
        if (kubeconfig.StartsWith("\\"))
        {
            Logger.LogDebug("Unescaping kubeconfig JSON");
            kubeconfig = kubeconfig.Replace("\\", "");
            kubeconfig = kubeconfig.Replace("\\n", "\n");
        }

        // parse kubeconfig as a dictionary of string, string
        if (!kubeconfig.StartsWith("{")) return k8SConfiguration;

        Logger.LogDebug("Parsing kubeconfig as a dictionary of string, string");

        //load json into dictionary of string, string
        Logger.LogTrace("Deserializing kubeconfig JSON");
        var configDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(kubeconfig);
        Logger.LogTrace("Deserialized kubeconfig JSON successfully.");

        Logger.LogTrace("Creating K8SConfiguration object");
        k8SConfiguration = new K8SConfiguration
        {
            ApiVersion = configDict["apiVersion"].ToString(),
            Kind = configDict["kind"].ToString(),
            CurrentContext = configDict["current-context"].ToString(),
            Clusters = new List<Cluster>(),
            Users = new List<User>(),
            Contexts = new List<Context>()
        };

        // parse clusters
        Logger.LogDebug("Parsing clusters");
        var cl = configDict["clusters"];

        Logger.LogTrace("Entering foreach loop to parse clusters...");
        foreach (var clusterMetadata in JsonConvert.DeserializeObject<JArray>(cl.ToString()))
        {
            var clusterObj = new Cluster
            {
                Name = clusterMetadata["name"].ToString(),
                ClusterEndpoint = new ClusterEndpoint
                {
                    Server = clusterMetadata["cluster"]["server"].ToString(),
                    CertificateAuthorityData = clusterMetadata["cluster"]["certificate-authority-data"].ToString(),
                    SkipTlsVerify = false
                }
            };
            Logger.LogTrace($"Adding cluster '{clusterObj.Name}'({clusterObj.ClusterEndpoint}) to K8SConfiguration");
            k8SConfiguration.Clusters = new List<Cluster> { clusterObj };
        }
        Logger.LogTrace("Finished parsing clusters.");

        Logger.LogDebug("Parsing users");
        Logger.LogTrace("Entering foreach loop to parse users...");
        // parse users
        foreach (var user in JsonConvert.DeserializeObject<JArray>(configDict["users"].ToString()))
        {
            var userObj = new User
            {
                Name = user["name"].ToString(),
                UserCredentials = new UserCredentials
                {
                    UserName = user["name"].ToString(),
                    Token = user["user"]["token"].ToString()
                }
            };
            Logger.LogTrace($"Adding user {userObj.Name} to K8SConfiguration object");
            k8SConfiguration.Users = new List<User> { userObj };
        }
        Logger.LogTrace("Finished parsing users.");

        Logger.LogDebug("Parsing contexts");
        Logger.LogTrace("Entering foreach loop to parse contexts...");
        foreach (var ctx in JsonConvert.DeserializeObject<JArray>(configDict["contexts"].ToString()))
        {
            Logger.LogTrace("Creating Context object");
            var contextObj = new Context
            {
                Name = ctx["name"].ToString(),
                ContextDetails = new ContextDetails
                {
                    Cluster = ctx["context"]["cluster"].ToString(),
                    Namespace = ctx["context"]["namespace"].ToString(),
                    User = ctx["context"]["user"].ToString()
                }
            };
            Logger.LogTrace($"Adding context '{contextObj.Name}' to K8SConfiguration object");
            k8SConfiguration.Contexts = new List<Context> { contextObj };
        }
        Logger.LogTrace("Finished parsing contexts.");
        Logger.LogDebug("Finished parsing kubeconfig.");
        return k8SConfiguration;
    }

    private IKubernetes GetKubeClient(string kubeconfig)
    {
        Logger.LogTrace("Entered GetKubeClient()");
        Logger.LogTrace("Getting executing assembly location");
        var strExeFilePath = Assembly.GetExecutingAssembly().Location;
        Logger.LogTrace($"Executing assembly location: {strExeFilePath}");

        Logger.LogTrace("Getting executing assembly directory");
        var strWorkPath = Path.GetDirectoryName(strExeFilePath);
        Logger.LogTrace($"Executing assembly directory: {strWorkPath}");

        var credentialFileName = kubeconfig;
        Logger.LogDebug($"credentialFileName: {credentialFileName}");
        Logger.LogDebug("Calling ParseKubeConfig()");
        var k8SConfiguration = ParseKubeConfig(kubeconfig);
        Logger.LogDebug("Finished calling ParseKubeConfig()");

        // use k8sConfiguration over credentialFileName
        KubernetesClientConfiguration config;
        if (k8SConfiguration != null) // Config defined in store parameters takes highest precedence
        {
            Logger.LogDebug("Config defined in store parameters takes highest precedence - calling BuildConfigFromConfigObject()");
            config = KubernetesClientConfiguration.BuildConfigFromConfigObject(k8SConfiguration);
            Logger.LogDebug("Finished calling BuildConfigFromConfigObject()");
        }
        else if (credentialFileName == "") // If no config defined in store parameters, use default config. This should never happen though.
        {
            Logger.LogWarning("No config defined in store parameters, using default config. This should never happen though.");
            config = KubernetesClientConfiguration.BuildDefaultConfig();
            Logger.LogDebug("Finished calling BuildDefaultConfig()");
        }
        else
        {
            Logger.LogDebug($"Attempting to load config from file {credentialFileName}");
            config = KubernetesClientConfiguration.BuildConfigFromConfigFile(!credentialFileName.Contains(strWorkPath)
                ? Path.Join(strWorkPath, credentialFileName)
                : // Else attempt to load config from file
                credentialFileName); // Else attempt to load config from file
            Logger.LogDebug("Finished calling BuildConfigFromConfigFile()");

        }

        Logger.LogDebug("Creating Kubernetes client");
        IKubernetes client = new Kubernetes(config);
        Logger.LogDebug("Finished creating Kubernetes client");

        Logger.LogTrace("Setting Client property");
        Client = client;
        Logger.LogTrace("Exiting GetKubeClient()");
        return client;
    }

    public V1Secret CreateOrUpdateCertificateStoreSecret(string[] keyPems, string[] certPems, string[] caCertPems, string[] chainPems, string secretName,
        string namespaceName, string secretType, bool append = false, bool overwrite = false)
    {
        Logger.LogTrace("Entered CreateOrUpdateCertificateStoreSecret()");

        Logger.LogTrace("Attempting to split certificate PEMs by \\n");
        var certPem = string.Join("\n", certPems);
        Logger.LogTrace("certPems: " + certPem);

        Logger.LogTrace("Attempting to split key PEMs by \\n");
        var keyPem = string.Join("\n", keyPems);
        Logger.LogDebug(string.IsNullOrEmpty(keyPem) ? "Unable to parse private keys, setting to null" : "Parsed private keys");

        Logger.LogTrace("Attempting to split CA certificate PEMs by \\n");
        var caCertPem = string.Join("\n", caCertPems);
        Logger.LogTrace("caCertPems: " + caCertPem);

        Logger.LogTrace("Attempting to split chain PEMs by \\n\\n");
        var chainPem = string.Join("\n\n", chainPems);
        Logger.LogTrace("chainPems: " + chainPem);

        Logger.LogDebug($"Attempting to create new secret {secretName} in namespace {namespaceName}");
        Logger.LogTrace("Calling CreateNewSecret()");
        var k8SSecretData = CreateNewSecret(secretName, namespaceName, keyPem, certPem, caCertPem, chainPem, secretType);
        Logger.LogTrace("Finished calling CreateNewSecret()");

        Logger.LogTrace("Entering try/catch block to create secret...");
        try
        {
            Logger.LogDebug("Calling CreateNamespacedSecret()");
            var secretResponse = Client.CoreV1.CreateNamespacedSecret(k8SSecretData, namespaceName);
            Logger.LogDebug("Finished calling CreateNamespacedSecret()");
            Logger.LogTrace(secretResponse.ToString());
            Logger.LogTrace("Exiting CreateOrUpdateCertificateStoreSecret()");
            return secretResponse;
        }
        catch (HttpOperationException e)
        {
            Logger.LogWarning("Error while attempting to create secret: " + e.Message);
            if (e.Message.Contains("Conflict"))
            {
                Logger.LogDebug($"Secret {secretName} already exists in namespace {namespaceName}, attempting to update secret...");
                Logger.LogTrace("Calling UpdateSecretStore()");
                return UpdateSecretStore(secretName, namespaceName, secretType, certPem, keyPem, k8SSecretData, append, overwrite);
            }
        }
        Logger.LogError("Unable to create secret for unknown reason.");
        return null;
    }

    private V1Secret CreateNewSecret(string secretName, string namespaceName, string keyPem, string certPem, string caCertPem, string chainPem, string secretType)
    {
        Logger.LogTrace("Entered CreateNewSecret()");
        Logger.LogDebug("Attempting to create new secret...");
        var k8SSecretData = secretType switch
        {
            "secret" => new V1Secret
            {
                Metadata = new V1ObjectMeta
                {
                    Name = secretName,
                    NamespaceProperty = namespaceName
                },

                Data = new Dictionary<string, byte[]>
                {
                    { "private_keys", Encoding.UTF8.GetBytes(keyPem) }, //TODO: Make this configurable
                    { "certificates", Encoding.UTF8.GetBytes(certPem) } //TODO: Make this configurable
                }
            },
            "tls_secret" => new V1Secret
            {
                Metadata = new V1ObjectMeta
                {
                    Name = secretName,
                    NamespaceProperty = namespaceName

                },

                Type = "kubernetes.io/tls",

                Data = new Dictionary<string, byte[]>
                {
                    { "tls.key", Encoding.UTF8.GetBytes(keyPem) },
                    { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
                }
            },
            _ => throw new NotImplementedException(
                $"Secret type {secretType} not implemented. Unable to create or update certificate store {secretName} in {namespaceName} on {GetHost()}.")
        };
        Logger.LogTrace("Exiting CreateNewSecret()");
        return k8SSecretData;
    }

    private V1Secret UpdateOpaqueSecret(string secretName, string namespaceName, V1Secret existingSecret, string certPem, string keyPem)
    {
        Logger.LogTrace("Entered UpdateOpaqueSecret()");
        var existingCerts = Encoding.UTF8.GetString(existingSecret.Data["certificates"]); //TODO: Make this configurable
        Logger.LogTrace("Existing certificates: " + existingCerts);

        var existingKeys = Encoding.UTF8.GetString(existingSecret.Data["private_keys"]); //TODO: Make this configurable
        // Logger.LogTrace("Existing private keys: " + existingKeys);

        if (existingCerts.Contains(certPem) && existingKeys.Contains(keyPem))
        {
            // certificate already exists, return existing secret
            Logger.LogDebug($"Certificate already exists in secret {secretName} in namespace {namespaceName}");
            Logger.LogTrace("Exiting UpdateOpaqueSecret()");
            return existingSecret;
        }

        if (!existingCerts.Contains(certPem))
        {
            Logger.LogDebug("Certificate does not exist in secret, adding certificate to secret");
            var newCerts = existingCerts;
            if (existingCerts.Length > 0)
            {
                Logger.LogTrace("Adding comma to existing certificates");
                newCerts += ",";
            }
            Logger.LogTrace("Adding certificate to existing certificates");
            newCerts += certPem;

            Logger.LogTrace("Updating 'certificates' secret data");
            existingSecret.Data["certificates"] = Encoding.UTF8.GetBytes(newCerts);
        }

        if (!existingKeys.Contains(keyPem))
        {
            Logger.LogDebug("Private key does not exist in secret, adding private key to secret");
            var newKeys = existingKeys;
            if (existingKeys.Length > 0)
            {
                Logger.LogTrace("Adding comma to existing private keys");
                newKeys += ",";
            }
            Logger.LogTrace("Adding private key to existing private keys");
            newKeys += keyPem;

            Logger.LogTrace("Updating 'private_keys' secret data");
            existingSecret.Data["private_keys"] = Encoding.UTF8.GetBytes(newKeys);
        }

        Logger.LogDebug($"Attempting to update secret {secretName} in namespace {namespaceName}");
        Logger.LogTrace("Calling ReplaceNamespacedSecret()");
        var secretResponse = Client.CoreV1.ReplaceNamespacedSecret(existingSecret, secretName, namespaceName);
        Logger.LogTrace("Finished calling ReplaceNamespacedSecret()");
        Logger.LogTrace("Exiting UpdateOpaqueSecret()");
        return secretResponse;
    }

    private V1Secret UpdateSecretStore(string secretName, string namespaceName, string secretType, string certPem, string keyPem, V1Secret newData, bool append,
        bool overwrite = false)
    {
        Logger.LogTrace("Entered UpdateSecretStore()");

        if (!append)
        {
            Logger.LogDebug($"Overwriting existing secret {secretName} in namespace {namespaceName}");
            Logger.LogTrace("Calling ReplaceNamespacedSecret()");
            return Client.CoreV1.ReplaceNamespacedSecret(newData, secretName, namespaceName);
        }

        Logger.LogDebug($"Appending to existing secret {secretName} in namespace {namespaceName}");
        Logger.LogTrace("Calling ReadNamespacedSecret()");
        var existingSecret = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName, true);
        Logger.LogTrace("Finished calling ReadNamespacedSecret()");
        if (existingSecret == null)
        {
            var errMsg =
                $"Update {secretType} secret {secretName} in Kubernetes namespace {namespaceName} on {GetHost()} failed. Also unable to read secret, please verify credentials have correct access.";
            Logger.LogError(errMsg);
            throw new Exception(errMsg);
        }

        Logger.LogTrace($"Entering switch statement for secret type {secretType}");
        switch (secretType)
        {
            // check if certificate already exists in "certificates" field
            case "secret":
            {
                Logger.LogInformation($"Attempting to update opaque secret {secretName} in namespace {namespaceName}");
                Logger.LogTrace("Calling UpdateOpaqueSecret()");
                return UpdateOpaqueSecret(secretName, namespaceName, existingSecret, certPem, keyPem);
            }
            case "tls_secret" when !overwrite:
                var errMsg = "Overwrite is not specified, cannot add multiple certificates to a Kubernetes secret type 'tls_secret'.";
                Logger.LogError(errMsg);
                Logger.LogTrace("Exiting UpdateSecretStore()");
                throw new Exception(errMsg);
            case "tls_secret":
            {
                Logger.LogInformation($"Attempting to update tls secret {secretName} in namespace {namespaceName}");
                Logger.LogTrace("Calling ReplaceNamespacedSecret()");
                var secretResponse = Client.CoreV1.ReplaceNamespacedSecret(newData, secretName, namespaceName);
                Logger.LogTrace("Finished calling ReplaceNamespacedSecret()");
                Logger.LogTrace("Exiting UpdateSecretStore()");
                return secretResponse;
            }
            default:
                var dErrMsg = $"Secret type not implemented. Unable to create or update certificate store {secretName} in {namespaceName} on {GetHost()}.";
                Logger.LogError(dErrMsg);
                Logger.LogTrace("Exiting UpdateSecretStore()");
                throw new NotImplementedException(dErrMsg);
        }
    }
    public V1Secret GetCertificateStoreSecret(string secretName, string namespaceName)
    {
        Logger.LogTrace("Entered GetCertificateStoreSecret()");
        Logger.LogTrace("Calling ReadNamespacedSecret()");
        Logger.LogDebug($"Attempting to read secret {secretName} in namespace {namespaceName} from {GetHost()}");
        return Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
    }

    private string CleanOpaqueStore(string existingEntries, string pemString)
    {
        Logger.LogTrace("Entered CleanOpaqueStore()");
        // Logger.LogTrace($"pemString: {pemString}");
        Logger.LogTrace("Entering try/catch block to remove existing certificate from opaque secret");
        try
        {
            Logger.LogDebug("Attempting to remove existing certificate from opaque secret");
            existingEntries = existingEntries.Replace(pemString, "").Replace(",,", ",");

            if (existingEntries.StartsWith(","))
            {
                Logger.LogDebug("Removing leading comma from existing certificates.");
                existingEntries = existingEntries.Substring(1);
            }
            if (existingEntries.EndsWith(","))
            {
                Logger.LogDebug("Removing trailing comma from existing certificates.");
                existingEntries = existingEntries.Substring(0, existingEntries.Length - 1);
            }
        }
        catch (Exception)
        {
            // Didn't find existing key for whatever reason so no need to delete.
            Logger.LogWarning("Unable to find existing certificate in opaque secret. No need to remove.");
        }
        Logger.LogTrace("Exiting CleanOpaqueStore()");
        return existingEntries;
    }

    private V1Secret DeleteCertificateStoreSecret(string secretName, string namespaceName, string alias)
    {
        Logger.LogTrace("Entered DeleteCertificateStoreSecret()");
        Logger.LogTrace("secretName: " + secretName);
        Logger.LogTrace("namespaceName: " + namespaceName);
        Logger.LogTrace("alias: " + alias);

        Logger.LogDebug($"Attempting to read secret {secretName} in namespace {namespaceName} from {GetHost()}");
        Logger.LogTrace("Calling ReadNamespacedSecret()");
        var existingSecret = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName, true);
        Logger.LogTrace("Finished calling ReadNamespacedSecret()");
        if (existingSecret == null)
        {
            var errMsg =
                $"Delete secret {secretName} in Kubernetes namespace {namespaceName} failed. Unable unable to read secret, please verify credentials have correct access.";
            Logger.LogError(errMsg);
            throw new Exception(errMsg);
        }

        // handle cert removal
        Logger.LogDebug("Parsing existing certificates from secret into a string.");
        var existingCerts = Encoding.UTF8.GetString(existingSecret.Data["certificates"]); //TODO: Make this configurable.
        Logger.LogTrace("existingCerts: " + existingCerts);

        Logger.LogDebug("Parsing existing private keys from secret into a string.");
        var existingKeys = Encoding.UTF8.GetString(existingSecret.Data["private_keys"]); //TODO: Make this configurable.
        // Logger.LogTrace("existingKeys: " + existingKeys);

        Logger.LogDebug("Splitting existing certificates into an array.");
        var certs = existingCerts.Split(",");
        Logger.LogTrace("certs: " + certs);

        Logger.LogDebug("Splitting existing private keys into an array.");
        var keys = existingKeys.Split(",");
        // Logger.LogTrace("keys: " + keys);

        var index = 0; //Currently keys are assumed to be in the same order as certs. //TODO: Make this less fragile
        Logger.LogTrace("Entering foreach loop to remove existing certificate from opaque secret");
        foreach (var cer in certs)
        {
            Logger.LogTrace("pkey index: " + index);
            Logger.LogTrace("cer: " + cer);
            Logger.LogDebug("Creating X509Certificate2 from certificate string.");
            var sCert = new X509Certificate2(Encoding.UTF8.GetBytes(cer));
            Logger.LogDebug("sCert.Thumbprint: " + sCert.Thumbprint);

            if (sCert.Thumbprint == alias)
            {
                Logger.LogDebug("Found matching certificate thumbprint. Removing certificate from opaque secret.");
                Logger.LogTrace("Calling CleanOpaqueStore()");
                existingCerts = CleanOpaqueStore(existingCerts, cer);
                Logger.LogTrace("Finished calling CleanOpaqueStore()");
                Logger.LogTrace("Updated existingCerts: " + existingCerts);
                Logger.LogTrace("Calling CleanOpaqueStore()");
                try
                {
                    existingKeys = CleanOpaqueStore(existingKeys, keys[index]);
                }
                catch (IndexOutOfRangeException)
                {
                    // Didn't find existing key for whatever reason so no need to delete.
                    // Find the corresponding key the the keys array and by checking if the private key corresponds to the cert public key.
                    Logger.LogWarning($"Unable to find corresponding private key in opaque secret for certificate {sCert.Thumbprint}. No need to remove.");
                }

            }
            Logger.LogTrace("Incrementing pkey index...");
            index++; //Currently keys are assumed to be in the same order as certs.
        }

        Logger.LogDebug("Updating existing secret with new certificate data.");
        existingSecret.Data["certificates"] = Encoding.UTF8.GetBytes(existingCerts); //TODO: Make this configurable.
        Logger.LogDebug("Updating existing secret with new key data.");
        existingSecret.Data["private_keys"] = Encoding.UTF8.GetBytes(existingKeys); //TODO: Make this configurable.

        // Update Kubernetes secret
        Logger.LogDebug($"Updating secret {secretName} in namespace {namespaceName} on {GetHost()} with new certificate data.");
        Logger.LogTrace("Calling ReplaceNamespacedSecret()");
        return Client.CoreV1.ReplaceNamespacedSecret(existingSecret, secretName, namespaceName);
    }

    public V1Status DeleteCertificateStoreSecret(string secretName, string namespaceName, string storeType, string alias)
    {
        Logger.LogTrace("Entered DeleteCertificateStoreSecret()");
        Logger.LogTrace("secretName: " + secretName);
        Logger.LogTrace("namespaceName: " + namespaceName);
        Logger.LogTrace("storeType: " + storeType);
        Logger.LogTrace("alias: " + alias);
        Logger.LogTrace("Entering switch statement to determine which delete method to use.");
        switch (storeType)
        {
            case "secret":
                // check the current inventory and only remove the cert if it is found else throw not found exception
                Logger.LogDebug($"Attempting to delete certificate from opaque secret {secretName} in namespace {namespaceName} on {GetHost()}");
                Logger.LogTrace("Calling DeleteCertificateStoreSecret()");
                _ = DeleteCertificateStoreSecret(secretName, namespaceName, alias);
                Logger.LogTrace("Finished calling DeleteCertificateStoreSecret()");
                return new V1Status("v1", 0, status: "Success");
            case "tls_secret":
                Logger.LogDebug($"Deleting TLS secret {secretName} in namespace {namespaceName} on {GetHost()}");
                Logger.LogTrace("Calling DeleteNamespacedSecret()");
                return Client.CoreV1.DeleteNamespacedSecret(
                    secretName,
                    namespaceName,
                    new V1DeleteOptions()
                );
            case "certificate":
                Logger.LogDebug($"Deleting Certificate Signing Request {secretName} on {GetHost()}");
                Logger.LogTrace("Calling CertificatesV1.DeleteCertificateSigningRequest()");
                _ = Client.CertificatesV1.DeleteCertificateSigningRequest(
                    secretName,
                    new V1DeleteOptions()
                );
                var errMsg = "DeleteCertificateStoreSecret not implemented for 'certificate' type.";
                Logger.LogError(errMsg);
                throw new NotImplementedException(errMsg);
            default:
                var dErrMsg = $"DeleteCertificateStoreSecret not implemented for type '{storeType}'.";
                Logger.LogError(dErrMsg);
                throw new NotImplementedException(dErrMsg);
        }
    }
    public List<string> DiscoverCertificates()
    {
        Logger.LogTrace("Entered DiscoverCertificates()");
        var locations = new List<string>();
        Logger.LogDebug("Discovering certificates from k8s certificate resources.");
        Logger.LogTrace("Calling CertificatesV1.ListCertificateSigningRequest()");
        var csr = Client.CertificatesV1.ListCertificateSigningRequest();
        Logger.LogTrace("Finished calling CertificatesV1.ListCertificateSigningRequest()");
        Logger.LogTrace("csr.Items.Count: " + csr.Items.Count);

        Logger.LogTrace("Entering foreach loop to add certificate locations to list.");
        foreach (var cr in csr)
        {
            Logger.LogTrace("cr.Metadata.Name: " + cr.Metadata.Name);
            Logger.LogDebug("Parsing certificate from certificate resource.");
            var utfCert = cr.Status.Certificate != null ? Encoding.UTF8.GetString(cr.Status.Certificate) : "";
            Logger.LogDebug("Parsing certificate signing request from certificate resource.");
            var utfCsr = cr.Spec.Request != null
                ? Encoding.UTF8.GetString(cr.Spec.Request, 0, cr.Spec.Request.Length)
                : "";

            if (utfCsr != "")
            {
                Logger.LogTrace("utfCsr: " + utfCsr);
            }
            if (utfCert == "")
            {
                Logger.LogWarning("CSR has not been signed yet. Skipping.");
                continue;
            }

            Logger.LogDebug("Converting UTF8 encoded certificate to X509Certificate2 object.");
            var cert = new X509Certificate2(Encoding.UTF8.GetBytes(utfCert));
            Logger.LogTrace("cert: " + cert);

            Logger.LogDebug("Getting certificate name from X509Certificate2 object.");
            var certName = cert.GetNameInfo(X509NameType.SimpleName, false);
            Logger.LogTrace("certName: " + certName);

            Logger.LogDebug($"Adding certificate {certName} discovered location to list.");
            locations.Add($"certificate/{certName}");
            // else
            // {
            //     // locations.Add(utfCsr);
            //     continue;
            // }
        }

        Logger.LogDebug("Completed discovering certificates from k8s certificate resources.");
        Logger.LogTrace("locations.Count: " + locations.Count);
        Logger.LogTrace("locations: " + locations);
        Logger.LogTrace("Exiting DiscoverCertificates()");
        return locations;
    }

    public string[] GetCertificateSigningRequestStatus(string name)
    {
        Logger.LogTrace("Entered GetCertificateSigningRequestStatus()");
        Logger.LogDebug($"Attempting to read {name} certificate signing request from {GetHost()}...");
        var cr = Client.CertificatesV1.ReadCertificateSigningRequest(name);
        Logger.LogDebug($"Successfully read {name} certificate signing request from {GetHost()}.");
        Logger.LogTrace("cr: " + cr);
        Logger.LogTrace("Attempting to parse certificate from certificate resource.");
        var utfCert = cr.Status.Certificate != null ? Encoding.UTF8.GetString(cr.Status.Certificate) : "";
        Logger.LogTrace("utfCert: " + utfCert);

        Logger.LogDebug($"Attempting to parse certificate signing request from certificate resource {name}.");
        var cert = new X509Certificate2(Encoding.UTF8.GetBytes(utfCert));
        Logger.LogTrace("cert: " + cert);
        Logger.LogTrace("Exiting GetCertificateSigningRequestStatus()");
        return new[] { utfCert };
    }

    public List<string> DiscoverSecrets(string[] allowedKeys, string ns = "default")
    {
        // Get a list of all namespaces
        Logger.LogTrace("Entered DiscoverSecrets()");
        V1NamespaceList namespaces;
        Logger.LogDebug("Attempting to list k8s namespaces from " + GetHost());
        namespaces = ns == "all" ? Client.CoreV1.ListNamespace(labelSelector: $"name={ns}") : Client.CoreV1.ListNamespace();
        Logger.LogTrace("namespaces.Items.Count: " + namespaces.Items.Count);
        Logger.LogTrace("namespaces.Items: " + namespaces.Items);

        var secretsList = new List<string>();
        var locations = new List<string>();


        Logger.LogTrace("Entering foreach loop to list all secrets in each returned namespace.");
        foreach (var nsObj in namespaces.Items)
        {
            Logger.LogDebug("Attempting to list secrets in namespace " + nsObj.Metadata.Name);
            // Get a list of all secrets in the namespace
            Logger.LogTrace("Calling CoreV1.ListNamespacedSecret()");
            var secrets = Client.CoreV1.ListNamespacedSecret(nsObj.Metadata.Name);
            Logger.LogTrace("Finished calling CoreV1.ListNamespacedSecret()");

            Logger.LogDebug("Attempting to read each secret in namespace " + nsObj.Metadata.Name);
            Logger.LogTrace("Entering foreach loop to read each secret in namespace " + nsObj.Metadata.Name);
            foreach (var secret in secrets.Items)
            {
                if (secret.Type is "kubernetes.io/tls" or "Opaque")
                {
                    Logger.LogTrace("secret.Type: " + secret.Type);
                    Logger.LogTrace("secret.Metadata.Name: " + secret.Metadata.Name);
                    Logger.LogTrace("Calling CoreV1.ReadNamespacedSecret()");
                    var secretData = Client.CoreV1.ReadNamespacedSecret(secret.Metadata.Name, nsObj.Metadata.Name);
                    Logger.LogTrace("Finished calling CoreV1.ReadNamespacedSecret()");
                    // Logger.LogTrace("secretData: " + secretData);
                    Logger.LogTrace("Entering switch statement to check secret type.");
                    switch (secret.Type)
                    {
                        case "kubernetes.io/tls":
                            Logger.LogDebug("Attempting to parse TLS certificate from secret");
                            var certData = Encoding.UTF8.GetString(secretData.Data["tls.crt"]);
                            Logger.LogTrace("certData: " + certData);

                            Logger.LogDebug("Attempting to parse TLS key from secret");
                            var keyData = Encoding.UTF8.GetString(secretData.Data["tls.key"]);

                            Logger.LogDebug("Attempting to convert TLS certificate to X509Certificate2 object");
                            _ = new X509Certificate2(secretData.Data["tls.crt"]); // Check if cert is valid

                            var cLocation = $"{nsObj.Metadata.Name}/secrets/{secret.Metadata.Name}";
                            Logger.LogDebug($"Adding certificate location {cLocation} to list of discovered certificates");
                            locations.Add(cLocation);
                            secretsList.Add(certData);
                            break;
                        case "Opaque":
                            // Check if a 'certificates' key exists
                            Logger.LogDebug("Attempting to parse certificate from opaque secret");
                            Logger.LogTrace("Entering foreach loop to check if any allowed keys exist in secret");
                            foreach (var allowedKey in allowedKeys)
                            {
                                Logger.LogTrace("allowedKey: " + allowedKey);
                                try
                                {
                                    if (!secretData.Data.ContainsKey(allowedKey)) continue;

                                    Logger.LogDebug("Attempting to parse certificate from opaque secret");
                                    var certs = Encoding.UTF8.GetString(secretData.Data[allowedKey]);
                                    Logger.LogTrace("certs: " + certs);
                                    // var keys = Encoding.UTF8.GetString(secretData.Data["private_keys"]);
                                    Logger.LogTrace("Splitting certs into array by ','.");
                                    var certsArray = certs.Split(",");
                                    // var keysArray = keys.Split(",");
                                    var index = 0;
                                    foreach (var cer in certsArray)
                                    {
                                        Logger.LogTrace("cer: " + cer);
                                        Logger.LogDebug("Attempting to convert certificate to X509Certificate2 object");
                                        _ = new X509Certificate2(Encoding.UTF8.GetBytes(cer)); // Check if cert is valid

                                        Logger.LogDebug("Adding certificate to list of discovered certificates");
                                        secretsList.Append(cer);
                                        index++;
                                    }
                                    locations.Add($"{nsObj.Metadata.Name}/secrets/{secret.Metadata.Name}");
                                }
                                catch (Exception e)
                                {
                                    Logger.LogError("Error parsing certificate from opaque secret: " + e.Message);
                                    Logger.LogTrace(e.ToString());
                                    Logger.LogTrace(e.StackTrace);
                                }
                            }
                            Logger.LogTrace("Exiting foreach loop to check if any allowed keys exist in secret");
                            break;
                    }
                }
            }
        }
        Logger.LogTrace("locations: " + locations);
        Logger.LogTrace("Exiting DiscoverSecrets()");
        return locations;
    }

    public V1CertificateSigningRequest CreateCertificateSigningRequest(string name, string namespaceName, string csr)
    {
        Logger.LogTrace("Entered CreateCertificateSigningRequest()");
        var request = new V1CertificateSigningRequest
        {
            ApiVersion = "certificates.k8s.io/v1",
            Kind = "CertificateSigningRequest",
            Metadata = new V1ObjectMeta
            {
                Name = name,
                NamespaceProperty = namespaceName
            },
            Spec = new V1CertificateSigningRequestSpec
            {
                Request = Encoding.UTF8.GetBytes(csr),
                Groups = new List<string> { "system:authenticated" },
                Usages = new List<string> { "digital signature", "key encipherment", "server auth", "client auth" },
                SignerName = "kubernetes.io/kube-apiserver-client"
            }
        };
        Logger.LogTrace("request: " + request);
        Logger.LogTrace("Calling CertificatesV1.CreateCertificateSigningRequest()");
        return Client.CertificatesV1.CreateCertificateSigningRequest(request);
    }

    public CsrObject GenerateCertificateRequest(string name, string[] sans, IPAddress[] ips,
        string keyType = "RSA", int keyBits = 4096)
    {
        Logger.LogTrace("Entered GenerateCertificateRequest()");
        var sanBuilder = new SubjectAlternativeNameBuilder();
        Logger.LogDebug($"Building IP and SAN lists for CSR {name}");
        
        foreach (var ip in ips) sanBuilder.AddIpAddress(ip);
        foreach (var san in sans) sanBuilder.AddDnsName(san);

        Logger.LogTrace("sanBuilder: " + sanBuilder);
        
        Logger.LogTrace("Setting DN to CN=" + name);
        var distinguishedName = new X500DistinguishedName(name);

        Logger.LogDebug("Generating private key and CSR");
        using var rsa = RSA.Create(4096); // TODO: Make key size and type configurable 
        
        Logger.LogDebug("Exporting private key and public key");
        var pkey = rsa.ExportPkcs8PrivateKey();
        var pubkey = rsa.ExportRSAPublicKey();

        Logger.LogDebug("Building CSR object");
        var request =
            new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        Logger.LogDebug("Adding extensions to CSR");
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature,
            false));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        request.CertificateExtensions.Add(sanBuilder.Build());
        var csr = request.CreateSigningRequest();
        var csrPem = "-----BEGIN CERTIFICATE REQUEST-----\r\n" +
                     Convert.ToBase64String(csr) +
                     "\r\n-----END CERTIFICATE REQUEST-----";
        var keyPem = "-----BEGIN PRIVATE KEY-----\r\n" +
                     Convert.ToBase64String(pkey) +
                     "\r\n-----END PRIVATE KEY-----";
        var pubKeyPem = "-----BEGIN PUBLIC KEY-----\r\n" +
                        Convert.ToBase64String(pubkey) +
                        "\r\n-----END PUBLIC KEY-----";
        return new CsrObject
        {
            Csr = csrPem,
            PrivateKey = keyPem,
            PublicKey = pubKeyPem
        };
    }


    public IEnumerable<CurrentInventoryItem> GetOpaqueSecretCertificateInventory()
    {
        var inventoryItems = new List<CurrentInventoryItem>();
        return inventoryItems;
    }

    public IEnumerable<CurrentInventoryItem> GetTlsSecretCertificateInventory()
    {
        var inventoryItems = new List<CurrentInventoryItem>();
        return inventoryItems;
    }

    public IEnumerable<CurrentInventoryItem> GetCertificateInventory()
    {
        var inventoryItems = new List<CurrentInventoryItem>();
        return inventoryItems;
    }

    public struct CsrObject
    {
        public string Csr;
        public string PrivateKey;
        public string PublicKey;
    }
}
