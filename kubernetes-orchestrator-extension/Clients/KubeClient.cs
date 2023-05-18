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
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.PKI.PrivateKeys;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using ECCurve = Org.BouncyCastle.Math.EC.ECCurve;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Keyfactor.Extensions.Orchestrator.K8S;

public class KubeCertificateManagerClient
{

    internal protected ILogger Logger;

    private string ConfigJson { get; set; }

    private K8SConfiguration ConfigObj { get; set; }

    public KubeCertificateManagerClient(string kubeconfig)
    {
        Logger = LogHandler.GetClassLogger(MethodBase.GetCurrentMethod().DeclaringType);
        Client = GetKubeClient(kubeconfig);
        ConfigJson = kubeconfig;
        try
        {
            ConfigObj = ParseKubeConfig(kubeconfig);
        }
        catch (Exception ex)
        {
            ConfigObj = new K8SConfiguration() { };
        }
    }

    private IKubernetes Client { get; set; }

    public string GetClusterName()
    {
        Logger.LogTrace("Entered GetClusterName()");
        try
        {
            return ConfigObj.Clusters.FirstOrDefault()?.Name;
        }
        catch (Exception ex)
        {
            return GetHost();
        }

    }

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
        // Logger.LogDebug($"credentialFileName: {credentialFileName}");
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
            // Logger.LogDebug($"Attempting to load config from file {credentialFileName}");
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

    public byte[] createPKCS12(string pemPrivateKey, string pemCertificate)
    {
        AsymmetricCipherKeyPair privateKey;
        using (TextReader privateKeyTextReader = new StringReader(pemPrivateKey))
        {
            var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(privateKeyTextReader);
            privateKey = (AsymmetricCipherKeyPair)pemReader.ReadObject();
        }

        // Load the certificate
        X509Certificate certificate;
        using (TextReader certificateTextReader = new StringReader(pemCertificate))
        {
            var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(certificateTextReader);
            certificate = (X509Certificate)pemReader.ReadObject();
        }

        // Create a PKCS12 store
        Pkcs12Store store = new Pkcs12StoreBuilder().Build();
        string alias = "myalias"; // Alias for the private key entry

        // Add the private key and certificate to the store
        X509CertificateEntry certificateEntry = new X509CertificateEntry(certificate);
        store.SetCertificateEntry(alias, certificateEntry);
        store.SetKeyEntry(alias, new AsymmetricKeyEntry(privateKey.Private), new[] { certificateEntry });

        // Save the PKCS12 store to a memory stream
        using (MemoryStream stream = new MemoryStream())
        {
            store.Save(stream, Array.Empty<char>(), new SecureRandom());

            // Get the PKCS12 bytes
            byte[] pkcs12Bytes = stream.ToArray();

            // Use the pkcs12Bytes as desired
            return pkcs12Bytes;
        }
    }

    public X509Certificate2 FindCertificateByCN(X509Certificate2Collection certificates, string cn)
    {
        X509Certificate2 foundCertificate = certificates
            .OfType<X509Certificate2>()
            .FirstOrDefault(cert => cert.SubjectName.Name.Contains($"CN={cn}", StringComparison.OrdinalIgnoreCase));

        return foundCertificate;
    }
    
    public X509Certificate2 FindCertificateByThumbprint(X509Certificate2Collection certificates, string thumbprint)
    {
        X509Certificate2 foundCertificate = certificates
            .OfType<X509Certificate2>()
            .FirstOrDefault(cert => cert.Thumbprint == thumbprint);

        return foundCertificate;
    }
    
    public X509Certificate2 FindCertificateByAlias(X509Certificate2Collection certificates, string alias)
    {
        X509Certificate2 foundCertificate = certificates
            .OfType<X509Certificate2>()
            .FirstOrDefault(cert => cert.SubjectName.Name.Contains(alias));

        return foundCertificate;
    }

    public V1Secret RemoveFromPKCS12SecretStore(K8SJobCertificate jobCertificate, string secretName, string namespaceName, string secretType, string certdataFieldName,
        string storePasswd, V1Secret k8SSecretData,
        bool append = false, bool overwrite = true, bool passwdIsK8sSecret = false, string passwordSecretPath = "", string passwordFieldName = "password",
        string[] certdataFieldNames = null)
    {
        Logger.LogTrace("Entered UpdatePKCS12SecretStore()");
        Logger.LogTrace("Calling GetSecret()");
        var existingPkcs12DataObj = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
        

        // iterate through existingPkcs12DataObj.Data and add to existingPkcs12
        var existingPkcs12 = new X509Certificate2Collection();
        var newPkcs12Collection = new X509Certificate2Collection();
        var k8sCollection = new X509Certificate2Collection();
        byte[] storePasswordBytes = Encoding.UTF8.GetBytes("");

        if (existingPkcs12DataObj?.Data == null)
        {
            Logger.LogTrace("existingPkcs12DataObj.Data is null");
        }
        else
        {
            Logger.LogTrace("existingPkcs12DataObj.Data is not null");

            // KeyValuePair<string, byte[]> updated_data = new KeyValuePair<string, byte[]>();
            
            foreach (var fieldName in existingPkcs12DataObj?.Data.Keys)
            {
                //check if key is in certdataFieldNames
                //if fieldname contains a . then split it and use the last part
                var searchFieldName = fieldName;
                certdataFieldName = fieldName;
                if (fieldName.Contains("."))
                {
                    var splitFieldName = fieldName.Split(".");
                    searchFieldName = splitFieldName[splitFieldName.Length - 1];
                }
                if (certdataFieldNames != null && !certdataFieldNames.Contains(searchFieldName)) continue;

                Logger.LogTrace($"Adding cert '{fieldName}' to existingPkcs12");
                if (jobCertificate.PasswordIsK8SSecret)
                {
                    if (!string.IsNullOrEmpty(jobCertificate.StorePasswordPath))
                    {
                        var passwordPath = jobCertificate.StorePasswordPath.Split("/");
                        var passwordNamespace = passwordPath[0];
                        var passwordSecretName = passwordPath[1];
                        // Get password from k8s secre
                        var k8sPasswordObj = ReadBuddyPass(passwordSecretName, passwordNamespace);
                        storePasswordBytes = k8sPasswordObj.Data[passwordFieldName];  
                        var storePasswdString = Encoding.UTF8.GetString(storePasswordBytes);
                        existingPkcs12.Import(existingPkcs12DataObj.Data[fieldName], storePasswdString, X509KeyStorageFlags.Exportable);        
                    }
                    else
                    {
                        storePasswordBytes = existingPkcs12DataObj.Data[passwordFieldName];
                        existingPkcs12.Import(existingPkcs12DataObj.Data[fieldName], Encoding.UTF8.GetString(storePasswordBytes), X509KeyStorageFlags.Exportable);    
                    }
                }
                else if (!string.IsNullOrEmpty(jobCertificate.StorePassword))
                {
                    storePasswordBytes = Encoding.UTF8.GetBytes(jobCertificate.StorePassword);
                    existingPkcs12.Import(existingPkcs12DataObj.Data[fieldName], Encoding.UTF8.GetString(storePasswordBytes), X509KeyStorageFlags.Exportable);
                }
                else
                {
                    storePasswordBytes = Encoding.UTF8.GetBytes(storePasswd);
                    existingPkcs12.Import(existingPkcs12DataObj.Data[fieldName], Encoding.UTF8.GetString(storePasswordBytes), X509KeyStorageFlags.Exportable);
                }
            }
            if (existingPkcs12.Count > 0)
            {
                // Check if overwrite is true, if so, replace existing cert with new cert
                if (overwrite)
                {
                    Logger.LogTrace("Overwrite is true, replacing existing cert with new cert");

                    X509Certificate2 foundCertificate = FindCertificateByAlias(existingPkcs12, jobCertificate.Alias);
                    if (foundCertificate != null)
                    {
                        // Certificate found
                        // replace the found certificate with the new certificate
                        Logger.LogTrace("Certificate found, replacing the found certificate with the new certificate");
                        existingPkcs12.Remove(foundCertificate);
                    }
                }

                Logger.LogTrace("Importing jobCertificate.CertBytes into existingPkcs12");
                // existingPkcs12.Import(jobCertificate.CertBytes, storePasswd, X509KeyStorageFlags.Exportable);
                k8sCollection = existingPkcs12;
            }
        }
        

        Logger.LogTrace("Creating V1Secret object");

        var p12bytes = k8sCollection.Export(X509ContentType.Pkcs12, Encoding.UTF8.GetString(storePasswordBytes));
        
        var secret = new V1Secret
        {
            ApiVersion = "v1",
            Kind = "Secret",
            Metadata = new V1ObjectMeta
            {
                Name = secretName,
                NamespaceProperty = namespaceName
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { certdataFieldName, p12bytes }
            }
        };
        switch (string.IsNullOrEmpty(storePasswd))
        {
            case false when string.IsNullOrEmpty(passwordSecretPath) && passwdIsK8sSecret: // password is not empty and passwordSecretPath is empty
            {
                Logger.LogDebug("Adding password to secret...");
                if (string.IsNullOrEmpty(passwordFieldName))
                {
                    passwordFieldName = "password";
                }
                secret.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(storePasswd));
                break;
            }
            case false when !string.IsNullOrEmpty(passwordSecretPath) && passwdIsK8sSecret: // password is not empty and passwordSecretPath is not empty
            {
                Logger.LogDebug("Adding password secret path to secret...");
                if (string.IsNullOrEmpty(passwordFieldName))
                {
                    passwordFieldName = "passwordSecretPath";
                }
                secret.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordSecretPath));

                // Lookup password secret path on cluster to see if it exists
                Logger.LogDebug("Attempting to lookup password secret path on cluster...");
                var splitPasswordPath = passwordSecretPath.Split("/");
                // Assume secret pattern is namespace/secretName
                var passwordSecretName = splitPasswordPath[splitPasswordPath.Length - 1];
                var passwordSecretNamespace = splitPasswordPath[0];
                Logger.LogDebug($"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                try
                {
                    var passwordSecret = Client.CoreV1.ReadNamespacedSecret(passwordSecretName, passwordSecretNamespace);
                    // storePasswd = Encoding.UTF8.GetString(passwordSecret.Data[passwordFieldName]);
                    Logger.LogDebug($"Successfully found secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    // Update secret
                    Logger.LogDebug($"Attempting to update secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    passwordSecret.Data[passwordFieldName] = Encoding.UTF8.GetBytes(storePasswd);
                    var updatedPasswordSecret = Client.CoreV1.ReplaceNamespacedSecret(passwordSecret, passwordSecretName, passwordSecretNamespace);
                    Logger.LogDebug($"Successfully updated secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                }
                catch (HttpOperationException e)
                {
                    Logger.LogError($"Unable to find secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    Logger.LogError(e.Message);
                    // Attempt to create a new secret
                    Logger.LogDebug($"Attempting to create secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    var passwordSecretData = new V1Secret
                    {
                        Metadata = new V1ObjectMeta
                        {
                            Name = passwordSecretName,
                            NamespaceProperty = passwordSecretNamespace
                        },
                        Data = new Dictionary<string, byte[]>
                        {
                            { passwordFieldName, Encoding.UTF8.GetBytes(storePasswd) }
                        }
                    };
                    var createdPasswordSecret = Client.CoreV1.CreateNamespacedSecret(passwordSecretData, passwordSecretNamespace);
                    Logger.LogDebug("Successfully created secret " + passwordSecretPath);
                }
                break;
            }
        }

        // Update secret on K8S
        Logger.LogTrace("Calling UpdateSecret()");
        var updatedSecret = Client.CoreV1.ReplaceNamespacedSecret(secret, secretName, namespaceName);

        Logger.LogTrace("Finished creating V1Secret object");

        Logger.LogTrace("Exiting UpdatePKCS12SecretStore()");
        return updatedSecret;
    }

    public V1Secret UpdatePKCS12SecretStore(K8SJobCertificate jobCertificate, string secretName, string namespaceName, string secretType, string certdataFieldName,
        string storePasswd, V1Secret k8SSecretData,
        bool append = false, bool overwrite = true, bool passwdIsK8sSecret = false, string passwordSecretPath = "", string passwordFieldName = "password",
        string[] certdataFieldNames = null, bool remove = false)
    {
        Logger.LogTrace("Entered UpdatePKCS12SecretStore()");
        Logger.LogTrace("Calling GetSecret()");
        var existingPkcs12DataObj = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
        // var existingPkcs12Bytes = existingPkcs12DataObj.Data[certdataFieldName];
        // var existingPkcs12 = new X509Certificate2Collection();
        // existingPkcs12.Import(existingPkcs12Bytes, storePasswd, X509KeyStorageFlags.Exportable);

        // iterate through existingPkcs12DataObj.Data and add to existingPkcs12
        var existingPkcs12 = new X509Certificate2Collection();
        var newPkcs12Collection = new X509Certificate2Collection();
        var k8sCollection = new X509Certificate2Collection();
        byte[] storePasswordBytes = Encoding.UTF8.GetBytes("");

        if (existingPkcs12DataObj?.Data == null)
        {
            Logger.LogTrace("existingPkcs12DataObj.Data is null");
        }
        else
        {
            Logger.LogTrace("existingPkcs12DataObj.Data is not null");

            // KeyValuePair<string, byte[]> updated_data = new KeyValuePair<string, byte[]>();
            
            foreach (var fieldName in existingPkcs12DataObj?.Data.Keys)
            {
                //check if key is in certdataFieldNames
                //if fieldname contains a . then split it and use the last part
                var searchFieldName = fieldName;
                certdataFieldName = fieldName;
                if (fieldName.Contains("."))
                {
                    var splitFieldName = fieldName.Split(".");
                    searchFieldName = splitFieldName[splitFieldName.Length - 1];
                }
                if (certdataFieldNames != null && !certdataFieldNames.Contains(searchFieldName)) continue;

                Logger.LogTrace($"Adding cert '{fieldName}' to existingPkcs12");
                if (jobCertificate.PasswordIsK8SSecret)
                {
                    if (!string.IsNullOrEmpty(jobCertificate.StorePasswordPath))
                    {
                        var passwordPath = jobCertificate.StorePasswordPath.Split("/");
                        var passwordNamespace = passwordPath[0];
                        var passwordSecretName = passwordPath[1];
                        // Get password from k8s secre
                        var k8sPasswordObj = ReadBuddyPass(passwordSecretName, passwordNamespace);
                        storePasswordBytes = k8sPasswordObj.Data[passwordFieldName];  
                        var storePasswdString = Encoding.UTF8.GetString(storePasswordBytes);
                        existingPkcs12.Import(existingPkcs12DataObj.Data[fieldName], storePasswdString, X509KeyStorageFlags.Exportable);        
                    }
                    else
                    {
                        storePasswordBytes = existingPkcs12DataObj.Data[passwordFieldName];
                        existingPkcs12.Import(existingPkcs12DataObj.Data[fieldName], Encoding.UTF8.GetString(storePasswordBytes), X509KeyStorageFlags.Exportable);    
                    }
                }
                else if (!string.IsNullOrEmpty(jobCertificate.StorePassword))
                {
                    storePasswordBytes = Encoding.UTF8.GetBytes(jobCertificate.StorePassword);
                    existingPkcs12.Import(existingPkcs12DataObj.Data[fieldName], Encoding.UTF8.GetString(storePasswordBytes), X509KeyStorageFlags.Exportable);
                }
                else
                {
                    storePasswordBytes = Encoding.UTF8.GetBytes(storePasswd);
                    existingPkcs12.Import(existingPkcs12DataObj.Data[fieldName], Encoding.UTF8.GetString(storePasswordBytes), X509KeyStorageFlags.Exportable);
                }
            }
            if (existingPkcs12.Count > 0)
            {
                // create x509Certificate2 from jobCertificate.CertBytes
                if (remove)
                {
                    X509Certificate2 foundCertificate = FindCertificateByAlias(existingPkcs12, jobCertificate.Alias);
                    if (foundCertificate != null)
                    {
                        // Certificate found
                        // replace the found certificate with the new certificate
                        Logger.LogTrace("Certificate found, replacing the found certificate with the new certificate");
                        existingPkcs12.Remove(foundCertificate);
                    }
                }
                else
                {
                    var newCert = new X509Certificate2(jobCertificate.CertBytes, storePasswd, X509KeyStorageFlags.Exportable);
                    var newCertCn = newCert.GetNameInfo(X509NameType.SimpleName, false);
                    //import jobCertificate.CertBytes into existingPkcs12

                    // Check if overwrite is true, if so, replace existing cert with new cert
                    if (overwrite)
                    {
                        Logger.LogTrace("Overwrite is true, replacing existing cert with new cert");

                        X509Certificate2 foundCertificate = FindCertificateByCN(existingPkcs12, newCertCn);
                        if (foundCertificate != null)
                        {
                            // Certificate found
                            // replace the found certificate with the new certificate
                            Logger.LogTrace("Certificate found, replacing the found certificate with the new certificate");
                            existingPkcs12.Remove(foundCertificate);
                            existingPkcs12.Add(newCert);
                        }
                        else
                        {
                            // Certificate not found
                            // add the new certificate to the existingPkcs12
                            var storePasswordString = Encoding.UTF8.GetString(storePasswordBytes);
                            Logger.LogTrace("Certificate not found, adding the new certificate to the existingPkcs12");
                            existingPkcs12.Import(jobCertificate.Pkcs12, storePasswd, X509KeyStorageFlags.Exportable);
                        }
                    }
                }
                Logger.LogTrace("Importing jobCertificate.CertBytes into existingPkcs12");
                k8sCollection = existingPkcs12;
            }
            else
            {
                newPkcs12Collection.Import(jobCertificate.CertBytes, storePasswd, X509KeyStorageFlags.Exportable);
                k8sCollection = newPkcs12Collection;
            }

        }

        Logger.LogTrace("Creating V1Secret object");

        var p12bytes = k8sCollection.Export(X509ContentType.Pkcs12, Encoding.UTF8.GetString(storePasswordBytes));
        
        var secret = new V1Secret
        {
            ApiVersion = "v1",
            Kind = "Secret",
            Metadata = new V1ObjectMeta
            {
                Name = secretName,
                NamespaceProperty = namespaceName
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { certdataFieldName, p12bytes }
            }
        };
        switch (string.IsNullOrEmpty(storePasswd))
        {
            case false when string.IsNullOrEmpty(passwordSecretPath) && passwdIsK8sSecret: // password is not empty and passwordSecretPath is empty
            {
                Logger.LogDebug("Adding password to secret...");
                if (string.IsNullOrEmpty(passwordFieldName))
                {
                    passwordFieldName = "password";
                }
                secret.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(storePasswd));
                break;
            }
            case false when !string.IsNullOrEmpty(passwordSecretPath) && passwdIsK8sSecret: // password is not empty and passwordSecretPath is not empty
            {
                Logger.LogDebug("Adding password secret path to secret...");
                if (string.IsNullOrEmpty(passwordFieldName))
                {
                    passwordFieldName = "passwordSecretPath";
                }
                secret.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordSecretPath));

                // Lookup password secret path on cluster to see if it exists
                Logger.LogDebug("Attempting to lookup password secret path on cluster...");
                var splitPasswordPath = passwordSecretPath.Split("/");
                // Assume secret pattern is namespace/secretName
                var passwordSecretName = splitPasswordPath[splitPasswordPath.Length - 1];
                var passwordSecretNamespace = splitPasswordPath[0];
                Logger.LogDebug($"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                try
                {
                    var passwordSecret = Client.CoreV1.ReadNamespacedSecret(passwordSecretName, passwordSecretNamespace);
                    // storePasswd = Encoding.UTF8.GetString(passwordSecret.Data[passwordFieldName]);
                    Logger.LogDebug($"Successfully found secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    // Update secret
                    Logger.LogDebug($"Attempting to update secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    passwordSecret.Data[passwordFieldName] = Encoding.UTF8.GetBytes(storePasswd);
                    var updatedPasswordSecret = Client.CoreV1.ReplaceNamespacedSecret(passwordSecret, passwordSecretName, passwordSecretNamespace);
                    Logger.LogDebug($"Successfully updated secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                }
                catch (HttpOperationException e)
                {
                    Logger.LogError($"Unable to find secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    Logger.LogError(e.Message);
                    // Attempt to create a new secret
                    Logger.LogDebug($"Attempting to create secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    var passwordSecretData = new V1Secret
                    {
                        Metadata = new V1ObjectMeta
                        {
                            Name = passwordSecretName,
                            NamespaceProperty = passwordSecretNamespace
                        },
                        Data = new Dictionary<string, byte[]>
                        {
                            { passwordFieldName, Encoding.UTF8.GetBytes(storePasswd) }
                        }
                    };
                    var createdPasswordSecret = Client.CoreV1.CreateNamespacedSecret(passwordSecretData, passwordSecretNamespace);
                    Logger.LogDebug("Successfully created secret " + passwordSecretPath);
                }
                break;
            }
        }

        // Update secret on K8S
        Logger.LogTrace("Calling UpdateSecret()");
        var updatedSecret = Client.CoreV1.ReplaceNamespacedSecret(secret, secretName, namespaceName);

        Logger.LogTrace("Finished creating V1Secret object");

        Logger.LogTrace("Exiting UpdatePKCS12SecretStore()");
        return updatedSecret;
    }

    public V1Secret CreateOrUpdateCertificateStoreSecret(K8SJobCertificate jobCertificate, string secretName,
        string namespaceName, string secretType, bool overwrite = false, string certdataFieldName = "pkcs12", string passwordFieldName = "password",
        string passwordSecretPath = "", bool passwordIsK8SSecret = false, string password = "", string[] allowedKeys = null, bool remove = false)
    {
        var storePasswd = string.IsNullOrEmpty(password) ? jobCertificate.Password : password;
        Logger.LogTrace("Entered CreateOrUpdateCertificateStoreSecret()");
        Logger.LogTrace("Calling CreateNewSecret()");
        V1Secret k8SSecretData;
        switch (secretType)
        {
            case "pkcs12":
            case "pfx":
                if (remove)
                {
                    k8SSecretData = new V1Secret();
                }
                else
                {
                    k8SSecretData = CreateOrUpdatePKCS12Secret(secretName,
                        namespaceName,
                        jobCertificate,
                        certdataFieldName,
                        storePasswd,
                        passwordFieldName,
                        passwordSecretPath,
                        allowedKeys);    
                }
                break;
            default:
                k8SSecretData = new V1Secret();
                break;
        }

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
            if (e.Message.Contains("Conflict") || e.Message.Contains("Unprocessable"))
            {
                Logger.LogDebug($"Secret {secretName} already exists in namespace {namespaceName}, attempting to update secret...");
                Logger.LogTrace("Calling UpdateSecretStore()");
                switch (secretType)
                {
                    case "pkcs12":
                    case "pfx":
                        return UpdatePKCS12SecretStore(jobCertificate,
                            secretName,
                            namespaceName,
                            secretType,
                            certdataFieldName,
                            storePasswd,
                            k8SSecretData,
                            true,
                            overwrite,
                            false, //TODO: FIX THIS BEFORE PRODUCTION
                            passwordSecretPath,
                            passwordFieldName,
                            null,
                            remove);
                    default:
                        return UpdateSecretStore(secretName, namespaceName, secretType, "", "", k8SSecretData, false, overwrite);
                }

            }
        }
        Logger.LogError("Unable to create secret for unknown reason.");
        return k8SSecretData;
    }

    public V1Secret CreateOrUpdateCertificateStoreSecret(string[] keyPems, string[] certPems, string[] caCertPems, string[] chainPems, string secretName,
        string namespaceName, string secretType, bool append = false, bool overwrite = false, bool remove=false)
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

    private AsymmetricKeyParameter ReadPrivateKey(byte[] privateKeyBytes)
    {
        var reader = new PemReader(new StreamReader(new MemoryStream(privateKeyBytes)));
        var keyPair = (AsymmetricCipherKeyPair)reader.ReadObject();
        return keyPair.Private;
    }

    public Pkcs12Store CreatePKCS12Collection(byte[] pkcs12bytes, string currentPassword, string newPassword)
    {
            try
            {
                
                Pkcs12StoreBuilder storeBuilder = new Pkcs12StoreBuilder();
                Pkcs12Store certs = storeBuilder.Build();

                byte[] newCertBytes = pkcs12bytes;

                Pkcs12Store newEntry = storeBuilder.Build();

                X509Certificate2 cert = new X509Certificate2(newCertBytes, currentPassword, X509KeyStorageFlags.Exportable);
                byte[] binaryCert = cert.Export(X509ContentType.Pkcs12, currentPassword);

                using (MemoryStream ms = new MemoryStream(string.IsNullOrEmpty(currentPassword) ? binaryCert : newCertBytes))
                {
                    newEntry.Load(ms, string.IsNullOrEmpty(currentPassword) ? new char[0] : currentPassword.ToCharArray());
                }
                
                string checkAliasExists = string.Empty;
                string alias = cert.Thumbprint;
                foreach (string newEntryAlias in newEntry.Aliases)
                {
                    if (!newEntry.IsKeyEntry(newEntryAlias))
                        continue;

                    checkAliasExists = newEntryAlias;

                    if (certs.ContainsAlias(alias))
                    {
                        certs.DeleteEntry(alias);
                    }
                    certs.SetKeyEntry(alias, newEntry.GetKey(newEntryAlias), newEntry.GetCertificateChain(newEntryAlias));
                }

                if (string.IsNullOrEmpty(checkAliasExists))
                {
                    Org.BouncyCastle.X509.X509Certificate bcCert = DotNetUtilities.FromX509Certificate(cert);
                    X509CertificateEntry bcEntry = new X509CertificateEntry(bcCert);
                    if (certs.ContainsAlias(alias))
                    {
                        certs.DeleteEntry(alias);
                    }
                    certs.SetCertificateEntry(alias, bcEntry);
                }

                using (MemoryStream outStream = new MemoryStream())
                {
                    certs.Save(outStream, string.IsNullOrEmpty(newPassword) ? new char[0] : newPassword.ToCharArray(), new Org.BouncyCastle.Security.SecureRandom());
                }
                return certs; 
            }
            catch (Exception ex)
            {
                throw new Exception($"Error attempting to add certficate for store path=StorePath, file name=StoreFileName.", ex);
            }

    }
    
    public X509Certificate2Collection CreatePKCS12Collection(X509Certificate2Collection  certificateCollection, string currentPassword, string newPassword)
    {
        // Iterate over the certificates in the collection
        foreach (X509Certificate2 certificate in certificateCollection)
        {
            // Export the private key to a byte array
            byte[] privateKeyBytes = certificate.Export(X509ContentType.Pkcs12, currentPassword);

            // Import the private key with the new password
            X509Certificate2 newCertificate = new X509Certificate2(privateKeyBytes, newPassword, X509KeyStorageFlags.Exportable);

            // Replace the certificate in the collection with the new certificate
            int index = certificateCollection.IndexOf(certificate);
            certificateCollection.RemoveAt(index);
            certificateCollection.Insert(index, newCertificate);
        }
        return certificateCollection;
    }

    private V1Secret CreateOrUpdatePKCS12Secret(string secretName, string namespaceName, K8SJobCertificate certObj, string secretFieldName, string password,
        string passwordFieldName, string passwordSecretPath = "", string[] allowedKeys = null)
    {
        Logger.LogTrace("Entered CreateOrUpdatePKCS12Secret()");

        Logger.LogDebug("Attempting to read existing k8s secret...");
        var existingSecret = new V1Secret();
        try
        {
            existingSecret = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
        }
        catch (HttpOperationException e)
        {
            Logger.LogDebug("Error while attempting to read existing secret: " + e.Message);
            if (e.Message.Contains("Not Found"))
            {
                Logger.LogDebug("No existing secret found.");
            }
            existingSecret = null;
        }

        Logger.LogDebug("Finished reading existing k8s secret.");

        if (existingSecret != null)
        {
            Logger.LogDebug("Existing secret found, attempting to update...");
            return UpdatePKCS12SecretStore(certObj,
                secretName,
                namespaceName,
                "pkcs12",
                secretFieldName,
                password,
                existingSecret,
                false,
                true,
                false,
                passwordSecretPath,
                passwordFieldName,
                allowedKeys); //todo: fix overwrite and isk8ssecret params
        }

        Logger.LogDebug("Attempting to create new secret...");

        //convert cert obj pkcs12 to base64
        Logger.LogDebug("Converting certificate to base64...");

        Logger.LogDebug("Creating X509Certificate2 from certificate object...");

        var passwordToWrite = !string.IsNullOrEmpty(certObj.StorePassword) ? certObj.StorePassword : password;
        
        var pkcs12Data = CreatePKCS12Collection(certObj.Pkcs12, password, passwordToWrite);

        byte[] p12Bytes;
        using (MemoryStream stream = new MemoryStream())
        {
            pkcs12Data.Save(stream, passwordToWrite.ToCharArray(), new SecureRandom());

            // Get the PKCS12 bytes
            p12Bytes = stream.ToArray();

            // Use the pkcs12Bytes as desired
        }

        if (string.IsNullOrEmpty(secretFieldName))
        {
            secretFieldName = "pkcs12";
        }
        var k8SSecretData = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = secretName,
                NamespaceProperty = namespaceName
            },
            Data = new Dictionary<string, byte[]>
            {
                { secretFieldName, p12Bytes }
            }
        };

        switch (string.IsNullOrEmpty(password))
        {
            case false when certObj.PasswordIsK8SSecret && string.IsNullOrEmpty(certObj.StorePasswordPath): // This means the password is expected to be on the secret so add it
            {
                Logger.LogDebug("Adding password to secret...");
                if (string.IsNullOrEmpty(passwordFieldName))
                {
                    passwordFieldName = "password";
                }

                // var passwordToWrite = !string.IsNullOrEmpty(certObj.StorePassword) ? certObj.StorePassword : password;
                
                k8SSecretData.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordToWrite));
                break;
            }
            case false when !string.IsNullOrEmpty(passwordSecretPath):
            {
                Logger.LogDebug("Adding password secret path to secret...");
                if (string.IsNullOrEmpty(passwordFieldName))
                {
                    passwordFieldName = "password";
                }
                // k8SSecretData.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordSecretPath));

                // Lookup password secret path on cluster to see if it exists
                Logger.LogDebug("Attempting to lookup password secret path on cluster...");
                var splitPasswordPath = passwordSecretPath.Split("/");
                // Assume secret pattern is namespace/secretName
                var passwordSecretName = splitPasswordPath[splitPasswordPath.Length - 1];
                var passwordSecretNamespace = splitPasswordPath[0];
                Logger.LogDebug($"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                try
                {
                    var passwordSecret = Client.CoreV1.ReadNamespacedSecret(passwordSecretName, passwordSecretNamespace);
                    password = Encoding.UTF8.GetString(passwordSecret.Data[passwordFieldName]);
                }
                catch (HttpOperationException e)
                {
                    Logger.LogError($"Unable to find secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    Logger.LogError(e.Message);
                    // Attempt to create a new secret
                    Logger.LogDebug($"Attempting to create secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    // var passwordToWrite = !string.IsNullOrEmpty(certObj.StorePassword) ? certObj.StorePassword : password;
                    var passwordSecretData = new V1Secret
                    {
                        Metadata = new V1ObjectMeta
                        {
                            Name = passwordSecretName,
                            NamespaceProperty = passwordSecretNamespace
                        },
                        Data = new Dictionary<string, byte[]>
                        {
                            { passwordFieldName, Encoding.UTF8.GetBytes(passwordToWrite) }
                        }
                    };
                    Logger.LogDebug("Calling CreateNamespacedSecret()");
                    var passwordSecretResponse = Client.CoreV1.CreateNamespacedSecret(passwordSecretData, passwordSecretNamespace);
                    Logger.LogDebug("Finished calling CreateNamespacedSecret()");
                    Logger.LogDebug("Successfully created secret " + passwordSecretPath);
                }
                break;
            }
        }
        Logger.LogTrace("Exiting CreateNewSecret()");
        return k8SSecretData;

    }

    public V1Secret ReadBuddyPass(string secretName, string passwordSecretPath)
    {

        // Lookup password secret path on cluster to see if it exists
        Logger.LogDebug("Attempting to lookup password secret path on cluster...");
        var splitPasswordPath = passwordSecretPath.Split("/");
        // Assume secret pattern is namespace/secretName
        var passwordSecretName = splitPasswordPath[splitPasswordPath.Length - 1];
        var passwordSecretNamespace = splitPasswordPath[0];
        Logger.LogDebug($"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
        var passwordSecretResponse = Client.CoreV1.ReadNamespacedSecret(secretName, passwordSecretNamespace);
        return passwordSecretResponse;
    }

    public V1Secret CreateOrUpdateBuddyPass(string secretName, string passwordFieldName, string passwordSecretPath, string password)
    {
        Logger.LogDebug("Adding password secret path to secret...");
        if (string.IsNullOrEmpty(passwordFieldName))
        {
            passwordFieldName = "password";
        }
        // k8SSecretData.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordSecretPath));

        // Lookup password secret path on cluster to see if it exists
        Logger.LogDebug("Attempting to lookup password secret path on cluster...");
        var splitPasswordPath = passwordSecretPath.Split("/");
        // Assume secret pattern is namespace/secretName
        var passwordSecretName = splitPasswordPath[splitPasswordPath.Length - 1];
        var passwordSecretNamespace = splitPasswordPath[0];
        Logger.LogDebug($"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
        var passwordSecretData = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = passwordSecretName,
                NamespaceProperty = passwordSecretNamespace
            },
            Data = new Dictionary<string, byte[]>
            {
                { passwordFieldName, Encoding.UTF8.GetBytes(password) }
            }
        };
        try
        {
            var passwordSecretResponse = Client.CoreV1.CreateNamespacedSecret(passwordSecretData, passwordSecretNamespace);
            return passwordSecretResponse;
        }
        catch (HttpOperationException e)
        {
            Logger.LogError($"Unable to find secret {passwordSecretName} in namespace {passwordSecretNamespace}");
            Logger.LogError(e.Message);
            // Attempt to create a new secret
            Logger.LogDebug($"Attempting to create secret {passwordSecretName} in namespace {passwordSecretNamespace}");

            Logger.LogDebug("Calling CreateNamespacedSecret()");
            var passwordSecretResponse = Client.CoreV1.ReplaceNamespacedSecret(passwordSecretData, secretName, passwordSecretNamespace);
            Logger.LogDebug("Finished calling CreateNamespacedSecret()");
            Logger.LogDebug("Successfully created secret " + passwordSecretPath);
            return passwordSecretResponse;
        }
    }

    private V1Secret CreateNewSecret(string secretName, string namespaceName, string keyPem, string certPem, string caCertPem, string chainPem, string secretType)
    {
        Logger.LogTrace("Entered CreateNewSecret()");
        Logger.LogDebug("Attempting to create new secret...");

        switch (secretType)
        {
            case "secret":
            case "opaque":
            case "opaque_secret":
                secretType = "secret";
                break;
            case "tls_secret":
            case "tls":
                secretType = "tls_secret";
                break;
            case "pfx":
            case "pkcs12":
                secretType = "pkcs12";

                break;
            default:
                Logger.LogError("Unknown secret type: " + secretType);
                break;
        }

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
                    { "tls.key", Encoding.UTF8.GetBytes(keyPem) }, //TODO: Make this configurable
                    { "tls.crt", Encoding.UTF8.GetBytes(certPem) } //TODO: Make this configurable
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

        Logger.LogDebug($"Attempting to update secret {secretName} in namespace {namespaceName}");
        Logger.LogTrace("Calling ReplaceNamespacedSecret()");
        var secretResponse = Client.CoreV1.ReplaceNamespacedSecret(existingSecret, secretName, namespaceName);
        Logger.LogTrace("Finished calling ReplaceNamespacedSecret()");
        Logger.LogTrace("Exiting UpdateOpaqueSecret()");
        return secretResponse;
    }

    private V1Secret UpdateOpaqueSecretMultiple(string secretName, string namespaceName, V1Secret existingSecret, string certPem, string keyPem)
    {
        Logger.LogTrace("Entered UpdateOpaqueSecret()");

        var existingCerts = existingSecret.Data.ContainsKey("certificates")
            ? Encoding.UTF8.GetString(existingSecret.Data["certificates"])
            : ""; //TODO: Make this configurable

        Logger.LogTrace("Existing certificates: " + existingCerts);

        var existingKeys = existingSecret.Data.ContainsKey("tls.key")
            ? Encoding.UTF8.GetString(existingSecret.Data["tls.key"])
            : ""; //TODO: Make this configurable
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
            existingSecret.Data["tls.key"] = Encoding.UTF8.GetBytes(newKeys);
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
            // case "secret" when !overwrite:
            //     Logger.LogInformation($"Attempting to create opaque secret {secretName} in namespace {namespaceName}");
            //     Logger.LogInformation("Overwrite is not specified, checking if certificate already exists in secret");
            //     
            //     
            //     return CreateNewSecret(secretName, namespaceName, keyPem,certPem,"","",secretType);
            case "secret":
            {
                Logger.LogInformation($"Attempting to update opaque secret {secretName} in namespace {namespaceName}");
                Logger.LogTrace("Calling UpdateOpaqueSecret()");
                return UpdateOpaqueSecret(secretName, namespaceName, existingSecret, certPem, keyPem);
            }
            // case "tls_secret" when !overwrite:
            //     var errMsg = "Overwrite is not specified, cannot add multiple certificates to a Kubernetes secret type 'tls_secret'.";
            //     Logger.LogError(errMsg);
            //     Logger.LogTrace("Exiting UpdateSecretStore()");
            //     throw new Exception(errMsg);
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
        foreach (var sKey in existingSecret.Data.Keys)
        {
            var existingCerts = Encoding.UTF8.GetString(existingSecret.Data[sKey]); //TODO: Make this configurable.
            Logger.LogTrace("existingCerts: " + existingCerts);

            Logger.LogDebug("Parsing existing private keys from secret into a string.");
            var existingKeys = Encoding.UTF8.GetString(existingSecret.Data["tls.key"]); //TODO: Make this configurable.
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
                Logger.LogTrace("alias: " + alias);
                if (string.IsNullOrEmpty(cer))
                {
                    Logger.LogDebug("Found empty certificate string. Skipping.");
                    continue;
                }
                Logger.LogDebug("Creating X509Certificate2 from certificate string.");
                var sCert = new X509Certificate2();
                try
                {
                    sCert = new X509Certificate2(Encoding.UTF8.GetBytes(cer));
                }
                catch (Exception e)
                {
                    Logger.LogWarning($"Unable to create X509Certificate2 from string in '{sKey}' field. Skipping. Error: {e.Message}");
                    continue;
                }

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
            existingSecret.Data[sKey] = Encoding.UTF8.GetBytes(existingCerts); //TODO: Make this configurable.
            Logger.LogDebug("Updating existing secret with new key data.");
            try
            {
                existingSecret.Data["tls.key"] = Encoding.UTF8.GetBytes(existingKeys);
            }
            catch (Exception)
            {
                Logger.LogWarning("Unable to update private_keys in opaque secret. This is expected if the secret did not contain private keys to begin with.");
            } //TODO: Make this configurable.


            // Update Kubernetes secret
            Logger.LogDebug($"Updating secret {secretName} in namespace {namespaceName} on {GetHost()} with new certificate data.");
            Logger.LogTrace("Calling ReplaceNamespacedSecret()");
        }

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
            case "opaque":
                // check the current inventory and only remove the cert if it is found else throw not found exception
                Logger.LogDebug($"Attempting to delete certificate from opaque secret {secretName} in namespace {namespaceName} on {GetHost()}");
                Logger.LogTrace("Calling DeleteCertificateStoreSecret()");
                // _ = DeleteCertificateStoreSecret(secretName, namespaceName, alias);
                return Client.CoreV1.DeleteNamespacedSecret(
                    secretName,
                    namespaceName,
                    new V1DeleteOptions()
                );
            // Logger.LogTrace("Finished calling DeleteCertificateStoreSecret()");
            // return new V1Status("v1", 0, status: "Success");
            case "tls_secret":
            case "tls":
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
        var clusterName = GetClusterName();
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
            locations.Add($"{clusterName}/certificate/{certName}");
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

    public List<string> DiscoverSecrets(string[] allowedKeys, string secType, string ns = "default", bool namespaceIsStore = false, bool clusterIsStore = false)
    {
        // Get a list of all namespaces
        Logger.LogTrace("Entered DiscoverSecrets()");
        V1NamespaceList namespaces;
        var clusterName = GetClusterName() ?? GetHost();

        var nsList = new string[] { };

        var locations = new List<string>();

        if (secType == "cluster")
        {
            Logger.LogTrace("Discovering K8S cluster secrets from k8s cluster resources and returning only a single location.");
            locations.Add($"{clusterName}");
            return locations;
        }


        Logger.LogDebug("Attempting to list k8s namespaces from " + clusterName);
        namespaces = Client.CoreV1.ListNamespace();
        Logger.LogTrace("namespaces.Items.Count: " + namespaces.Items.Count);
        Logger.LogTrace("namespaces.Items: " + namespaces.Items);

        nsList = ns.Contains(",") ? ns.Split(",") : new[] { ns };
        foreach (var nsLI in nsList)
        {
            var secretsList = new List<string>();
            Logger.LogTrace("Entering foreach loop to list all secrets in each returned namespace.");
            foreach (var nsObj in namespaces.Items)
            {
                if (nsLI != "all" && nsLI != nsObj.Metadata.Name)
                {
                    Logger.LogWarning("Skipping namespace " + nsObj.Metadata.Name + " because it does not match the namespace filter.");
                    continue;
                }

                Logger.LogDebug("Attempting to list secrets in namespace " + nsObj.Metadata.Name);
                // Get a list of all secrets in the namespace
                Logger.LogTrace("Calling CoreV1.ListNamespacedSecret()");
                var secrets = Client.CoreV1.ListNamespacedSecret(nsObj.Metadata.Name);
                Logger.LogTrace("Finished calling CoreV1.ListNamespacedSecret()");

                Logger.LogDebug("Attempting to read each secret in namespace " + nsObj.Metadata.Name);
                Logger.LogTrace("Entering foreach loop to read each secret in namespace " + nsObj.Metadata.Name);

                if (secType == "namespace")
                {
                    Logger.LogDebug("Discovering K8S secrets at the namespace level");
                    var nsLocation = $"{clusterName}/namespace/{nsObj.Metadata.Name}";
                    locations.Add(nsLocation);
                    Logger.LogTrace("Added namespace location " + nsLocation + " to list of locations.");
                    continue;
                }

                foreach (var secret in secrets.Items)
                {
                    if (secret.Type is "kubernetes.io/tls" or "Opaque" or "pkcs12" or "p12" or "pfx" or "jks")
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
                                if (secType != "kubernetes.io/tls" && secType != "tls")
                                {
                                    Logger.LogWarning("Skipping secret " + secret.Metadata.Name + " because it is not of type " + secType);
                                    continue;
                                }
                                Logger.LogDebug("Attempting to parse TLS certificate from secret");
                                var certData = Encoding.UTF8.GetString(secretData.Data["tls.crt"]);
                                Logger.LogTrace("certData: " + certData);

                                Logger.LogDebug("Attempting to parse TLS key from secret");
                                var keyData = Encoding.UTF8.GetString(secretData.Data["tls.key"]);

                                Logger.LogDebug("Attempting to convert TLS certificate to X509Certificate2 object");
                                // _ = new X509Certificate2(secretData.Data["tls.crt"]); // Check if cert is valid

                                var cLocation = $"{clusterName}/{nsObj.Metadata.Name}/secrets/{secret.Metadata.Name}";
                                Logger.LogDebug($"Adding certificate location {cLocation} to list of discovered certificates");
                                locations.Add(cLocation);
                                secretsList.Add(certData);
                                break;
                            case "Opaque":
                                if (secType != "Opaque" && secType != "pkcs12" && secType != "p12" && secType != "pfx" && secType != "jks")
                                {
                                    Logger.LogWarning("Skipping secret " + secret.Metadata.Name + " because it is not of type " + secType);
                                    continue;
                                }

                                // Check if a 'certificates' key exists
                                Logger.LogDebug("Attempting to parse certificate from opaque secret");
                                Logger.LogTrace("Entering foreach loop to check if any allowed keys exist in secret");
                                if (secretData.Data == null || secret.Data.Keys == null ) continue;
                                foreach (var dataKey in secretData.Data.Keys)
                                {
                                    Logger.LogTrace("dataKey: " + dataKey);
                                    try
                                    {
                                        // split dataKey by '.' and take the last element
                                        var dataKeyArray = dataKey.Split(".");
                                        var extension = dataKeyArray[^1];
                                        
                                        if (!allowedKeys.Contains(extension)) continue;
                                        Logger.LogDebug("Attempting to parse certificate from opaque secret");
                                        var certs = Encoding.UTF8.GetString(secretData.Data[dataKey]);
                                        Logger.LogTrace("certs: " + certs);
                                        // var keys = Encoding.UTF8.GetString(secretData.Data["tls.key"]);
                                        Logger.LogTrace("Splitting certs into array by ','.");
                                        var certsArray = certs.Split(",");
                                        // var keysArray = keys.Split(",");
                                        var index = 0;
                                        foreach (var cer in certsArray)
                                        {
                                            Logger.LogTrace("cer: " + cer);
                                            Logger.LogDebug("Attempting to convert certificate to X509Certificate2 object");
                                            // _ = new X509Certificate2(Encoding.UTF8.GetBytes(cer)); // Check if cert is valid

                                            Logger.LogDebug("Adding certificate to list of discovered certificates");
                                            secretsList.Append(cer);
                                            index++;
                                        }
                                        locations.Add($"{clusterName}/{nsObj.Metadata.Name}/secrets/{secret.Metadata.Name}");
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
