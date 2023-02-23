// Copyright 2022 Keyfactor
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
using Keyfactor.Orchestrators.Extensions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Keyfactor.Extensions.Orchestrator.Kube;

public class KubeCertificateManagerClient
{
    public KubeCertificateManagerClient(string kubeconfig)
    {
        Client = GetKubeClient(kubeconfig);
    }

    private IKubernetes Client { get; set; }

    public string GetHost()
    {
        return Client.BaseUri.ToString();
    }

    private K8SConfiguration ParseKubeConfig(string kubeconfig)
    {
        var k8SConfiguration = new K8SConfiguration();
        // test if kubeconfig is base64 encoded
        try
        {
            var decodedKubeconfig = Encoding.UTF8.GetString(Convert.FromBase64String(kubeconfig));
            kubeconfig = decodedKubeconfig;
        }
        catch
        {
            // not base64 encoded so do nothing
        }

        // check if json is escaped
        if (kubeconfig.StartsWith("\\"))
        {
            kubeconfig = kubeconfig.Replace("\\", "");
            kubeconfig = kubeconfig.Replace("\\n", "\n");
        }


        // parse kubeconfig as a dictionary of string, string

        if (kubeconfig.StartsWith("{"))
        {
            //load json into dictionary of string, string
            var configDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(kubeconfig);
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
            var cl = configDict["clusters"];

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
                k8SConfiguration.Clusters = new List<Cluster> { clusterObj };
            }


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
                k8SConfiguration.Users = new List<User> { userObj };
            }
            // parse contexts
            foreach (var ctx in JsonConvert.DeserializeObject<JArray>(configDict["contexts"].ToString()))
            {
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
                k8SConfiguration.Contexts = new List<Context> { contextObj };
            }
        }

        return k8SConfiguration;
    }

    private IKubernetes GetKubeClient(string kubeconfig)
    {
        //Credentials file needs to be in the same location of the executing assembly
        var strExeFilePath = Assembly.GetExecutingAssembly().Location;
        var strWorkPath = Path.GetDirectoryName(strExeFilePath);

        var credentialFileName = kubeconfig;
        var k8SConfiguration = ParseKubeConfig(kubeconfig);

        // use k8sConfiguration over credentialFileName
        KubernetesClientConfiguration config;
        if (k8SConfiguration != null) // Config defined in store parameters takes highest precedence
        {
            config = KubernetesClientConfiguration.BuildConfigFromConfigObject(k8SConfiguration);
        }
        else if (credentialFileName == "") // If no config defined in store parameters, use default config. This should never happen though.
        {
            config = KubernetesClientConfiguration.BuildDefaultConfig();
        }
        else
        {
            config = KubernetesClientConfiguration.BuildConfigFromConfigFile(!credentialFileName.Contains(strWorkPath)
                ? Path.Join(strWorkPath, credentialFileName)
                : // Else attempt to load config from file
                credentialFileName); // Else attempt to load config from file

        }

        IKubernetes client = new Kubernetes(config);
        Client = client;
        return client;
    }
    
    public V1Secret CreateOrUpdateCertificateStoreSecret(string[] keyPems, string[] certPems, string[] caCertPems, string[] chainPems, string secretName,
        string namespaceName, string secretType, bool append = false, bool overwrite = false)
    {
        var certPem = string.Join("\n", certPems);
        var keyPem = string.Join("\n", keyPems);
        var caCertPem = string.Join("\n", caCertPems);
        var chainPem = string.Join("\n\n", chainPems);
        var k8SSecretData = CreateNewSecret(secretName, namespaceName, keyPem, certPem, caCertPem, chainPem, secretType);

        try
        {
            var secretResponse = Client.CoreV1.CreateNamespacedSecret(k8SSecretData, namespaceName);
            return secretResponse;
        }
        catch (HttpOperationException e)
        {
            if (e.Message.Contains("Conflict"))
            {
                return UpdateSecretStore(secretName, namespaceName, secretType, certPem, keyPem, k8SSecretData, append, overwrite);
            }
        }
        return null;
    }

    private V1Secret CreateNewSecret(string secretName, string namespaceName, string keyPem, string certPem, string caCertPem, string chainPem, string secretType)
    {
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
                    { "private_keys", Encoding.UTF8.GetBytes(keyPem) },
                    { "certificates", Encoding.UTF8.GetBytes(certPem) },
                    { "ca_certificates", Encoding.UTF8.GetBytes(caCertPem) },
                    { "chain", Encoding.UTF8.GetBytes(chainPem) }
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
        return k8SSecretData;
    }
    
    private V1Secret UpdateOpaqueSecret(string secretName, string namespaceName, V1Secret existingSecret, string certPem, string keyPem)
    {
        var existingCerts = Encoding.UTF8.GetString(existingSecret.Data["certificates"]);
        var existingKeys = Encoding.UTF8.GetString(existingSecret.Data["private_keys"]);
        if (existingCerts.Contains(certPem) && existingKeys.Contains(keyPem))
        {
            // certificate already exists, return existing secret
            return existingSecret;
        }

        if (!existingCerts.Contains(certPem))
        {
            var newCerts = existingCerts;
            if (existingCerts.Length > 0)
            {
                newCerts += ",";
            }
            newCerts += certPem;

            existingSecret.Data["certificates"] = Encoding.UTF8.GetBytes(newCerts);
        }

        if (!existingKeys.Contains(keyPem))
        {
            var newKeys = existingKeys;
            if (existingKeys.Length > 0)
            {
                newKeys += ",";
            }
            newKeys += keyPem;

            existingSecret.Data["private_keys"] = Encoding.UTF8.GetBytes(newKeys);
        }

        var secretResponse = Client.CoreV1.ReplaceNamespacedSecret(existingSecret, secretName, namespaceName);
        return secretResponse;
    }

    private V1Secret UpdateSecretStore(string secretName, string namespaceName, string secretType, string certPem, string keyPem, V1Secret newData, bool append,
        bool overwrite = false)
    {
        if (!append) return Client.CoreV1.ReplaceNamespacedSecret(newData, secretName, namespaceName);

        var existingSecret = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName, true);
        if (existingSecret == null)
        {
            throw new Exception(
                $"Update {secretType} secret {secretName} in Kubernetes namespace {namespaceName} on {GetHost()} failed. Also unable to read secret, please verify credentials have correct access.");
        }

        switch (secretType)
        {
            // check if certificate already exists in "certificates" field
            case "secret":
            {
                return UpdateOpaqueSecret(secretName, namespaceName, existingSecret, certPem, keyPem);
            }
            case "tls_secret" when !overwrite:
                throw new Exception("Overwrite is not specified, cannot add multiple certificates to a Kubernetes secret type 'tls_secret'.");
            case "tls_secret":
            {
                var secretResponse = Client.CoreV1.ReplaceNamespacedSecret(newData, secretName, namespaceName);
                return secretResponse;
            }
            default:
                throw new NotImplementedException(
                    $"Secret type {secretType} not implemented. Unable to create or update certificate store {secretName} in {namespaceName} on {GetHost()}.");
        }
    }
    public V1Secret GetCertificateStoreSecret(string secretName, string namespaceName)
    {
        return Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
    }
    
    private static string CleanOpaqueStore(string existingEntries, string pemString)
    {
        try
        {
            existingEntries = existingEntries.Replace(pemString, "").Replace(",,", ",");
            if (existingEntries.StartsWith(","))
            {
                existingEntries = existingEntries.Substring(1);
            }
            if (existingEntries.EndsWith(","))
            {
                existingEntries = existingEntries.Substring(0, existingEntries.Length - 1);
            }
        }
        catch (Exception)
        {
            // Didn't find existing key for whatever reason so no need to delete.
        }
        return existingEntries;
    }

    private V1Secret DeleteCertificateStoreSecret(string secretName, string namespaceName, string alias)
    {
        var existingSecret = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName, true);
        if (existingSecret == null)
        {
            throw new Exception(
                $"Delete secret {secretName} in Kubernetes namespace {namespaceName} failed. Unable unable to read secret, please verify credentials have correct access.");
        }

        // handle cert removal
        var existingCerts = Encoding.UTF8.GetString(existingSecret.Data["certificates"]);
        var existingKeys = Encoding.UTF8.GetString(existingSecret.Data["private_keys"]);
        var certs = existingCerts.Split(",");
        var keys = existingKeys.Split(",");
        var index = 0; //TODO: Currently keys are assumed to be in the same order as certs.
        foreach (var cer in certs)
        {
            var sCert = new X509Certificate2(Encoding.UTF8.GetBytes(cer));
            if (sCert.Thumbprint == alias)
            {
                existingCerts = CleanOpaqueStore(existingCerts, cer);
                try
                {
                    existingKeys = CleanOpaqueStore(existingKeys, keys[index]);
                }
                catch (IndexOutOfRangeException)
                {
                    // Didn't find existing key for whatever reason so no need to delete.
                    // TODO: Find the corresponding key the the keys array and by checking if the private key corresponds to the cert public key.
                }

            }
            index++; //TODO: Currently keys are assumed to be in the same order as certs.
        }
        existingSecret.Data["certificates"] = Encoding.UTF8.GetBytes(existingCerts);
        existingSecret.Data["private_keys"] = Encoding.UTF8.GetBytes(existingKeys);

        // Update Kubernetes secret
        return Client.CoreV1.ReplaceNamespacedSecret(existingSecret, secretName, namespaceName);
    }

    public V1Status DeleteCertificateStoreSecret(string secretName, string namespaceName, string storeType, string alias)
    {
        switch (storeType)
        {
            case "secret":
                // check the current inventory and only remove the cert if it is found else throw not found exception
                _ = DeleteCertificateStoreSecret(secretName, namespaceName, alias);
                return new V1Status("v1", 0, status: "Success");
            case "tls_secret":
                return Client.CoreV1.DeleteNamespacedSecret(
                    secretName,
                    namespaceName,
                    new V1DeleteOptions()
                );
            case "certificate":
                // TODO: See if this is possible
                Client.CertificatesV1.DeleteCertificateSigningRequest(
                    secretName,
                    new V1DeleteOptions()
                );
                throw new NotImplementedException("DeleteCertificateStoreSecret not implemented for 'certificate' type.");
            default:
                throw new NotImplementedException($"DeleteCertificateStoreSecret not implemented for type '{storeType}'.");
        }
    }
    public List<string> DiscoverCertificates()
    {
        List<string> locations = new List<string>();
        var csr = Client.CertificatesV1.ListCertificateSigningRequest();
        foreach (var cr in csr)
        {
            var utfCert = cr.Status.Certificate != null ? Encoding.UTF8.GetString(cr.Status.Certificate) : "";
            var utfCsr = cr.Spec.Request != null
                ? Encoding.UTF8.GetString(cr.Spec.Request, 0, cr.Spec.Request.Length)
                : "";

            if (utfCsr != "") Console.WriteLine(utfCsr);
            if (utfCert != "")
            {
                var cert = new X509Certificate2(Encoding.UTF8.GetBytes(utfCert));
                var certName = cert.GetNameInfo(X509NameType.SimpleName, false);
            }
            else
            {
                locations.Append(utfCsr);
            }
        }

        return locations;
    }

    public string[] GetCertificateSigningRequestStatus(string name)
    {
        var cr = Client.CertificatesV1.ReadCertificateSigningRequest(name);
        var utfCert = cr.Status.Certificate != null ? Encoding.UTF8.GetString(cr.Status.Certificate) : "";
        var cert = new X509Certificate2(Encoding.UTF8.GetBytes(utfCert));
        return new[] { utfCert };
    }
    
    public List<string> DiscoverSecrets(string ns = "default")
    {
        // Get a list of all namespaces
        V1NamespaceList namespaces;
        namespaces = ns == "all" ? Client.CoreV1.ListNamespace() : Client.CoreV1.ListNamespace(labelSelector: $"name={ns}");

        var secretsList = new string[] { };
        List<string> locations = new List<string>();

        foreach (var nsObj in namespaces.Items)
        {
            // Get a list of all secrets in the namespace
            var secrets = Client.CoreV1.ListNamespacedSecret(nsObj.Metadata.Name);
            foreach (var secret in secrets.Items)
            {
                if (secret.Type is "kubernetes.io/tls" or "Opaque")
                {
                    var secretData = Client.CoreV1.ReadNamespacedSecret(secret.Metadata.Name, nsObj.Metadata.Name);
                    switch (secret.Type)
                    {
                        case "kubernetes.io/tls":
                            var certData = Encoding.UTF8.GetString(secretData.Data["tls.crt"]);
                            var keyData = Encoding.UTF8.GetString(secretData.Data["tls.key"]);
                            
                            _ = new X509Certificate2(secretData.Data["tls.crt"]); // Check if cert is valid
                            locations.Append($"{nsObj.Metadata.Name}/secrets/{secret.Metadata.Name}");
                            secretsList.Append(certData);
                            break;
                        case "Opaque":
                            // Check if a 'certificates' key exists
                            if (secretData.Data.ContainsKey("certificates"))
                            {
                                var certs = Encoding.UTF8.GetString(secretData.Data["certificates"]);
                                // var keys = Encoding.UTF8.GetString(secretData.Data["private_keys"]);
                                var certsArray = certs.Split(",");
                                // var keysArray = keys.Split(",");
                                var index = 0; 
                                foreach (var cer in certsArray)
                                {
                                    _ = new X509Certificate2(Encoding.UTF8.GetBytes(cer)); // Check if cert is valid
                                    secretsList.Append(cer);
                                    index++; 
                                }
                                locations.Append($"{nsObj.Metadata.Name}/secrets/{secret.Metadata.Name}");
                            } else if (secretData.Data.ContainsKey("certs"))
                            {
                                var certs = Encoding.UTF8.GetString(secretData.Data["certs"]);
                                // var keys = Encoding.UTF8.GetString(secretData.Data["private_keys"]);
                                var certsArray = certs.Split(",");
                                // var keysArray = keys.Split(",");
                                var index = 0; 
                                foreach (var cer in certsArray)
                                {
                                    var sCert = new X509Certificate2(Encoding.UTF8.GetBytes(cer));
                                    secretsList.Append(cer);
                                    index++; 
                                }
                                locations.Append($"{nsObj.Metadata.Name}/secrets/{secret.Metadata.Name}");
                            }
                            break;
                    }
                    
                }
            }
        }
        
        return locations;
    }
    
    public V1CertificateSigningRequest CreateCertificateSigningRequest(string name, string namespaceName, string csr)
    {
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
        return Client.CertificatesV1.CreateCertificateSigningRequest(request);
    }

    public CsrObject GenerateCertificateRequest(string name, string[] sans, IPAddress[] ips,
        string keyType = "RSA", int keyBits = 4096)
    {
        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var ip in ips) sanBuilder.AddIpAddress(ip);
        foreach (var san in sans) sanBuilder.AddDnsName(san);

        var distinguishedName = new X500DistinguishedName(name);

        using var rsa = RSA.Create(4096);
        var pkey = rsa.ExportPkcs8PrivateKey();
        var pubkey = rsa.ExportRSAPublicKey();

        var request =
            new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

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

    public struct CsrObject
    {
        public string Csr;
        public string PrivateKey;
        public string PublicKey;
    }


    public IEnumerable<CurrentInventoryItem> GetOpaqueSecretCertificateInventory()
    {
        List<CurrentInventoryItem> inventoryItems = new List<CurrentInventoryItem>();
        return inventoryItems;
    }
    
    public IEnumerable<CurrentInventoryItem> GetTlsSecretCertificateInventory()
    {
        List<CurrentInventoryItem> inventoryItems = new List<CurrentInventoryItem>();
        return inventoryItems;
    }

    public IEnumerable<CurrentInventoryItem> GetCertificateInventory()
    {
        List<CurrentInventoryItem> inventoryItems = new List<CurrentInventoryItem>();
        return inventoryItems;
    }
}
