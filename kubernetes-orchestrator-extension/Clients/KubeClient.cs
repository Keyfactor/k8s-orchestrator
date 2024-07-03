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
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Keyfactor.Extensions.Orchestrator.K8S.Clients;

public class KubeCertificateManagerClient
{

    private ILogger _logger;

    private string ConfigJson { get; set; }

    private K8SConfiguration ConfigObj { get; set; }

    public KubeCertificateManagerClient(string kubeconfig)
    {
        _logger = LogHandler.GetClassLogger(MethodBase.GetCurrentMethod()?.DeclaringType);
        Client = GetKubeClient(kubeconfig);
        ConfigJson = kubeconfig;
        try
        {
            ConfigObj = ParseKubeConfig(kubeconfig);
        }
        catch (Exception)
        {
            ConfigObj = new K8SConfiguration();
        }
    }

    private IKubernetes Client { get; set; }

    public string GetClusterName()
    {
        _logger.LogTrace("Entered GetClusterName()");
        try
        {
            return ConfigObj.Clusters.FirstOrDefault()?.Name;
        }
        catch (Exception)
        {
            return GetHost();
        }

    }

    public string GetHost()
    {
        _logger.LogTrace("Entered GetHost()");
        return Client.BaseUri.ToString();
    }

    private K8SConfiguration ParseKubeConfig(string kubeconfig)
    {
        _logger.LogTrace("Entered ParseKubeConfig()");
        var k8SConfiguration = new K8SConfiguration();
        // test if kubeconfig is base64 encoded
        _logger.LogDebug("Testing if kubeconfig is base64 encoded");
        try
        {
            var decodedKubeconfig = Encoding.UTF8.GetString(Convert.FromBase64String(kubeconfig));
            kubeconfig = decodedKubeconfig;
            _logger.LogDebug("Successfully decoded kubeconfig from base64");
        }
        catch
        {
            // not base64 encoded so do nothing
        }

        // check if json is escaped
        if (kubeconfig.StartsWith("\\"))
        {
            _logger.LogDebug("Unescaping kubeconfig JSON");
            kubeconfig = kubeconfig.Replace("\\", "");
            kubeconfig = kubeconfig.Replace("\\n", "\n");
        }

        // parse kubeconfig as a dictionary of string, string
        if (!kubeconfig.StartsWith("{")) return k8SConfiguration;

        _logger.LogDebug("Parsing kubeconfig as a dictionary of string, string");

        //load json into dictionary of string, string
        _logger.LogTrace("Deserializing kubeconfig JSON");
        var configDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(kubeconfig);
        _logger.LogTrace("Deserialized kubeconfig JSON successfully");

        _logger.LogTrace("Creating K8SConfiguration object");
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
        _logger.LogDebug("Parsing clusters");
        var cl = configDict["clusters"];

        _logger.LogTrace("Entering foreach loop to parse clusters...");
        foreach (var clusterMetadata in JsonConvert.DeserializeObject<JArray>(cl.ToString() ?? string.Empty))
        {
            var clusterObj = new Cluster
            {
                Name = clusterMetadata["name"]?.ToString(),
                ClusterEndpoint = new ClusterEndpoint
                {
                    Server = clusterMetadata["cluster"]?["server"]?.ToString(),
                    CertificateAuthorityData = clusterMetadata["cluster"]?["certificate-authority-data"]?.ToString(),
                    SkipTlsVerify = false
                }
            };
            _logger.LogTrace("Adding cluster '{Name}'({@Endpoint}) to K8SConfiguration", clusterObj.Name, clusterObj.ClusterEndpoint);
            k8SConfiguration.Clusters = new List<Cluster> { clusterObj };
        }
        _logger.LogTrace("Finished parsing clusters");

        _logger.LogDebug("Parsing users");
        _logger.LogTrace("Entering foreach loop to parse users...");
        // parse users
        foreach (var user in JsonConvert.DeserializeObject<JArray>(configDict["users"].ToString() ?? string.Empty))
        {
            var userObj = new User
            {
                Name = user["name"]?.ToString(),
                UserCredentials = new UserCredentials
                {
                    UserName = user["name"]?.ToString(),
                    Token = user["user"]?["token"]?.ToString()
                }
            };
            _logger.LogTrace("Adding user {Name} to K8SConfiguration object", userObj.Name);
            k8SConfiguration.Users = new List<User> { userObj };
        }
        _logger.LogTrace("Finished parsing users");

        _logger.LogDebug("Parsing contexts");
        _logger.LogTrace("Entering foreach loop to parse contexts...");
        foreach (var ctx in JsonConvert.DeserializeObject<JArray>(configDict["contexts"].ToString() ?? string.Empty))
        {
            _logger.LogTrace("Creating Context object");
            var contextObj = new Context
            {
                Name = ctx["name"]?.ToString(),
                ContextDetails = new ContextDetails
                {
                    Cluster = ctx["context"]?["cluster"]?.ToString(),
                    Namespace = ctx["context"]?["namespace"]?.ToString(),
                    User = ctx["context"]?["user"]?.ToString()
                }
            };
            _logger.LogTrace("Adding context '{Name}' to K8SConfiguration object", contextObj.Name);
            k8SConfiguration.Contexts = new List<Context> { contextObj };
        }
        _logger.LogTrace("Finished parsing contexts");
        _logger.LogDebug("Finished parsing kubeconfig");
        return k8SConfiguration;
    }

    private IKubernetes GetKubeClient(string kubeconfig)
    {
        _logger.LogTrace("Entered GetKubeClient()");
        _logger.LogTrace("Getting executing assembly location");
        var strExeFilePath = Assembly.GetExecutingAssembly().Location;
        _logger.LogTrace("Executing assembly location: {ExeFilePath}", strExeFilePath);

        _logger.LogTrace("Getting executing assembly directory");
        var strWorkPath = Path.GetDirectoryName(strExeFilePath);
        _logger.LogTrace("Executing assembly directory: {WorkPath}", strWorkPath);

        var credentialFileName = kubeconfig;
        // Logger.LogDebug($"credentialFileName: {credentialFileName}");
        _logger.LogDebug("Calling ParseKubeConfig()");
        var k8SConfiguration = ParseKubeConfig(kubeconfig);
        _logger.LogDebug("Finished calling ParseKubeConfig()");

        // use k8sConfiguration over credentialFileName
        KubernetesClientConfiguration config;
        if (k8SConfiguration != null) // Config defined in store parameters takes highest precedence
        {
            _logger.LogDebug("Config defined in store parameters takes highest precedence - calling BuildConfigFromConfigObject()");
            config = KubernetesClientConfiguration.BuildConfigFromConfigObject(k8SConfiguration);
            _logger.LogDebug("Finished calling BuildConfigFromConfigObject()");
        }
        else if (credentialFileName == "") // If no config defined in store parameters, use default config. This should never happen though.
        {
            _logger.LogWarning("No config defined in store parameters, using default config. This should never happen though");
            config = KubernetesClientConfiguration.BuildDefaultConfig();
            _logger.LogDebug("Finished calling BuildDefaultConfig()");
        }
        else
        {
            // Logger.LogDebug($"Attempting to load config from file {credentialFileName}");
            config = KubernetesClientConfiguration.BuildConfigFromConfigFile(strWorkPath != null && !credentialFileName.Contains(strWorkPath)
                ? Path.Join(strWorkPath, credentialFileName)
                : // Else attempt to load config from file
                credentialFileName); // Else attempt to load config from file
            _logger.LogDebug("Finished calling BuildConfigFromConfigFile()");

        }

        _logger.LogDebug("Creating Kubernetes client");
        IKubernetes client = new Kubernetes(config);
        _logger.LogDebug("Finished creating Kubernetes client");

        _logger.LogTrace("Setting Client property");
        Client = client;
        _logger.LogTrace("Exiting GetKubeClient()");
        return client;
    }

    public X509Certificate2 FindCertificateByCN(X509Certificate2Collection certificates, string cn)
    {
        var foundCertificate = certificates
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
        _logger.LogTrace("Entered UpdatePKCS12SecretStore()");
        _logger.LogTrace("Calling GetSecret()");
        var existingPkcs12DataObj = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);


        // iterate through existingPkcs12DataObj.Data and add to existingPkcs12
        var existingPkcs12 = new X509Certificate2Collection();
        var newPkcs12Collection = new X509Certificate2Collection();
        var k8sCollection = new X509Certificate2Collection();
        byte[] storePasswordBytes = Encoding.UTF8.GetBytes("");

        if (existingPkcs12DataObj?.Data == null)
        {
            _logger.LogTrace("existingPkcs12DataObj.Data is null");
        }
        else
        {
            _logger.LogTrace("existingPkcs12DataObj.Data is not null");

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

                _logger.LogTrace($"Adding cert '{fieldName}' to existingPkcs12");
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
                    _logger.LogTrace("Overwrite is true, replacing existing cert with new cert");

                    X509Certificate2 foundCertificate = FindCertificateByAlias(existingPkcs12, jobCertificate.Alias);
                    if (foundCertificate != null)
                    {
                        // Certificate found
                        // replace the found certificate with the new certificate
                        _logger.LogTrace("Certificate found, replacing the found certificate with the new certificate");
                        existingPkcs12.Remove(foundCertificate);
                    }
                }

                _logger.LogTrace("Importing jobCertificate.CertBytes into existingPkcs12");
                // existingPkcs12.Import(jobCertificate.CertBytes, storePasswd, X509KeyStorageFlags.Exportable);
                k8sCollection = existingPkcs12;
            }
        }


        _logger.LogTrace("Creating V1Secret object");

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
                _logger.LogDebug("Adding password to secret...");
                if (string.IsNullOrEmpty(passwordFieldName))
                {
                    passwordFieldName = "password";
                }
                secret.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(storePasswd));
                break;
            }
            case false when !string.IsNullOrEmpty(passwordSecretPath) && passwdIsK8sSecret: // password is not empty and passwordSecretPath is not empty
            {
                _logger.LogDebug("Adding password secret path to secret...");
                if (string.IsNullOrEmpty(passwordFieldName))
                {
                    passwordFieldName = "passwordSecretPath";
                }
                secret.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordSecretPath));

                // Lookup password secret path on cluster to see if it exists
                _logger.LogDebug("Attempting to lookup password secret path on cluster...");
                var splitPasswordPath = passwordSecretPath.Split("/");
                // Assume secret pattern is namespace/secretName
                var passwordSecretName = splitPasswordPath[splitPasswordPath.Length - 1];
                var passwordSecretNamespace = splitPasswordPath[0];
                _logger.LogDebug($"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                try
                {
                    var passwordSecret = Client.CoreV1.ReadNamespacedSecret(passwordSecretName, passwordSecretNamespace);
                    // storePasswd = Encoding.UTF8.GetString(passwordSecret.Data[passwordFieldName]);
                    _logger.LogDebug($"Successfully found secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    // Update secret
                    _logger.LogDebug($"Attempting to update secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    passwordSecret.Data[passwordFieldName] = Encoding.UTF8.GetBytes(storePasswd);
                    var updatedPasswordSecret = Client.CoreV1.ReplaceNamespacedSecret(passwordSecret, passwordSecretName, passwordSecretNamespace);
                    _logger.LogDebug($"Successfully updated secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                }
                catch (HttpOperationException e)
                {
                    _logger.LogError($"Unable to find secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    _logger.LogError(e.Message);
                    // Attempt to create a new secret
                    _logger.LogDebug($"Attempting to create secret {passwordSecretName} in namespace {passwordSecretNamespace}");
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
                    _logger.LogDebug("Successfully created secret " + passwordSecretPath);
                }
                break;
            }
        }

        // Update secret on K8S
        _logger.LogTrace("Calling UpdateSecret()");
        var updatedSecret = Client.CoreV1.ReplaceNamespacedSecret(secret, secretName, namespaceName);

        _logger.LogTrace("Finished creating V1Secret object");

        _logger.LogTrace("Exiting UpdatePKCS12SecretStore()");
        return updatedSecret;
    }

    public V1Secret UpdatePKCS12SecretStore(K8SJobCertificate jobCertificate, string secretName, string namespaceName, string secretType, string certdataFieldName,
        string storePasswd, V1Secret k8SSecretData,
        bool append = false, bool overwrite = true, bool passwdIsK8sSecret = false, string passwordSecretPath = "", string passwordFieldName = "password",
        string[] certdataFieldNames = null, bool remove = false)
    {
        _logger.LogTrace("Entered UpdatePKCS12SecretStore()");
        _logger.LogTrace("Calling GetSecret()");
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
            _logger.LogTrace("existingPkcs12DataObj.Data is null");
        }
        else
        {
            _logger.LogTrace("existingPkcs12DataObj.Data is not null");

            // KeyValuePair<string, byte[]> updated_data = new KeyValuePair<string, byte[]>();

            foreach (var fieldName in existingPkcs12DataObj?.Data.Keys)
            {
                //check if key is in certdataFieldNames
                //if fieldname contains a . then split it and use the last part
                var searchFieldName = fieldName;
                if (fieldName.Contains("."))
                {
                    var splitFieldName = fieldName.Split(".");
                    searchFieldName = splitFieldName[splitFieldName.Length - 1];
                }
                if (certdataFieldNames != null && !certdataFieldNames.Contains(searchFieldName)) continue;

                certdataFieldName = fieldName;
                _logger.LogTrace($"Adding cert '{fieldName}' to existingPkcs12");
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
                        _logger.LogTrace("Certificate found, replacing the found certificate with the new certificate");
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
                        _logger.LogTrace("Overwrite is true, replacing existing cert with new cert");

                        X509Certificate2 foundCertificate = FindCertificateByCN(existingPkcs12, newCertCn);
                        if (foundCertificate != null)
                        {
                            // Certificate found
                            // replace the found certificate with the new certificate
                            _logger.LogTrace("Certificate found, replacing the found certificate with the new certificate");
                            existingPkcs12.Remove(foundCertificate);
                            existingPkcs12.Add(newCert);
                        }
                        else
                        {
                            // Certificate not found
                            // add the new certificate to the existingPkcs12
                            var storePasswordString = Encoding.UTF8.GetString(storePasswordBytes);
                            _logger.LogTrace("Certificate not found, adding the new certificate to the existingPkcs12");
                            existingPkcs12.Import(jobCertificate.Pkcs12, storePasswd, X509KeyStorageFlags.Exportable);
                        }
                    }
                }
                _logger.LogTrace("Importing jobCertificate.CertBytes into existingPkcs12");
                k8sCollection = existingPkcs12;
            }
            else
            {
                newPkcs12Collection.Import(jobCertificate.CertBytes, storePasswd, X509KeyStorageFlags.Exportable);
                k8sCollection = newPkcs12Collection;
            }

        }

        _logger.LogTrace("Creating V1Secret object");

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

        if (existingPkcs12DataObj?.Data != null)
        {
            secret.Data = existingPkcs12DataObj.Data;
            secret.Data[certdataFieldName] = p12bytes;
        }

        // Convert p12bytes to pkcs12store
        var pkcs12StoreBuilder = new Pkcs12StoreBuilder();
        var pkcs12Store = pkcs12StoreBuilder.Build();
        pkcs12Store.Load(new MemoryStream(p12bytes), storePasswd.ToCharArray());


        switch (string.IsNullOrEmpty(storePasswd))
        {
            case false when string.IsNullOrEmpty(passwordSecretPath) && passwdIsK8sSecret: // password is not empty and passwordSecretPath is empty
            {
                _logger.LogDebug("Adding password to secret...");
                if (string.IsNullOrEmpty(passwordFieldName))
                {
                    passwordFieldName = "password";
                }
                secret.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(storePasswd));
                break;
            }
            case false when !string.IsNullOrEmpty(passwordSecretPath) && passwdIsK8sSecret: // password is not empty and passwordSecretPath is not empty
            {
                _logger.LogDebug("Adding password secret path to secret...");
                if (string.IsNullOrEmpty(passwordFieldName))
                {
                    passwordFieldName = "passwordSecretPath";
                }
                secret.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordSecretPath));

                // Lookup password secret path on cluster to see if it exists
                _logger.LogDebug("Attempting to lookup password secret path on cluster...");
                var splitPasswordPath = passwordSecretPath.Split("/");
                // Assume secret pattern is namespace/secretName
                var passwordSecretName = splitPasswordPath[splitPasswordPath.Length - 1];
                var passwordSecretNamespace = splitPasswordPath[0];
                _logger.LogDebug($"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                try
                {
                    var passwordSecret = Client.CoreV1.ReadNamespacedSecret(passwordSecretName, passwordSecretNamespace);
                    // storePasswd = Encoding.UTF8.GetString(passwordSecret.Data[passwordFieldName]);
                    _logger.LogDebug($"Successfully found secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    // Update secret
                    _logger.LogDebug($"Attempting to update secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    passwordSecret.Data[passwordFieldName] = Encoding.UTF8.GetBytes(storePasswd);
                    var updatedPasswordSecret = Client.CoreV1.ReplaceNamespacedSecret(passwordSecret, passwordSecretName, passwordSecretNamespace);
                    _logger.LogDebug($"Successfully updated secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                }
                catch (HttpOperationException e)
                {
                    _logger.LogError($"Unable to find secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    _logger.LogError(e.Message);
                    // Attempt to create a new secret
                    _logger.LogDebug($"Attempting to create secret {passwordSecretName} in namespace {passwordSecretNamespace}");
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
                    _logger.LogDebug("Successfully created secret " + passwordSecretPath);
                }
                break;
            }
        }

        // Update secret on K8S
        _logger.LogTrace("Calling UpdateSecret()");
        var updatedSecret = Client.CoreV1.ReplaceNamespacedSecret(secret, secretName, namespaceName);

        _logger.LogTrace("Finished creating V1Secret object");

        _logger.LogTrace("Exiting UpdatePKCS12SecretStore()");
        return updatedSecret;
    }

    public V1Secret CreateOrUpdateCertificateStoreSecret(K8SJobCertificate jobCertificate, string secretName,
        string namespaceName, string secretType, bool overwrite = false, string certDataFieldName = "pkcs12", string passwordFieldName = "password",
        string passwordSecretPath = "", bool passwordIsK8SSecret = false, string password = "", string[] allowedKeys = null, bool remove = false)
    {
        var storePasswd = string.IsNullOrEmpty(password) ? jobCertificate.Password : password;
        _logger.LogTrace("Entered CreateOrUpdateCertificateStoreSecret()");
        _logger.LogTrace("Calling CreateNewSecret()");
        V1Secret k8SSecretData;
        switch (secretType)
        {
            case "pkcs12":
            case "pfx":
            case "jks":
                if (remove)
                {
                    k8SSecretData = new V1Secret();
                }
                else
                {
                    k8SSecretData = CreateOrUpdatePKCS12Secret(secretName,
                        namespaceName,
                        jobCertificate,
                        certDataFieldName,
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

        _logger.LogTrace("Finished calling CreateNewSecret()");

        _logger.LogTrace("Entering try/catch block to create secret...");
        try
        {
            _logger.LogDebug("Calling CreateNamespacedSecret()");
            var secretResponse = Client.CoreV1.CreateNamespacedSecret(k8SSecretData, namespaceName);
            _logger.LogDebug("Finished calling CreateNamespacedSecret()");
            _logger.LogTrace(secretResponse.ToString());
            _logger.LogTrace("Exiting CreateOrUpdateCertificateStoreSecret()");
            return secretResponse;
        }
        catch (HttpOperationException e)
        {
            _logger.LogWarning("Error while attempting to create secret: " + e.Message);
            if (e.Message.Contains("Conflict") || e.Message.Contains("Unprocessable"))
            {
                _logger.LogDebug($"Secret {secretName} already exists in namespace {namespaceName}, attempting to update secret...");
                _logger.LogTrace("Calling UpdateSecretStore()");
                switch (secretType)
                {
                    case "pkcs12":
                    case "pfx":
                    case "jks":
                        return UpdatePKCS12SecretStore(jobCertificate,
                            secretName,
                            namespaceName,
                            secretType,
                            certDataFieldName,
                            storePasswd,
                            k8SSecretData,
                            true,
                            overwrite,
                            passwordIsK8SSecret,
                            passwordSecretPath,
                            passwordFieldName,
                            null,
                            remove);
                    default:
                        return UpdateSecretStore(secretName, namespaceName, secretType, "", "", k8SSecretData, false, overwrite);
                }

            }
        }
        _logger.LogError("Unable to create secret for unknown reason.");
        return k8SSecretData;
    }

    public V1Secret CreateOrUpdateCertificateStoreSecret(string keyPem, string certPem, List<string> chainPem, string secretName,
        string namespaceName, string secretType, bool append = false, bool overwrite = false, bool remove = false)
    {
        _logger.LogTrace("Entered CreateOrUpdateCertificateStoreSecret()");

        _logger.LogDebug($"Attempting to create new secret {secretName} in namespace {namespaceName}");
        _logger.LogTrace("Calling CreateNewSecret()");
        var k8SSecretData = CreateNewSecret(secretName, namespaceName, keyPem, certPem, chainPem, secretType);
        _logger.LogTrace("Finished calling CreateNewSecret()");

        _logger.LogTrace("Entering try/catch block to create secret...");
        try
        {
            _logger.LogDebug("Calling CreateNamespacedSecret()");
            var secretResponse = Client.CoreV1.CreateNamespacedSecret(k8SSecretData, namespaceName);
            _logger.LogDebug("Finished calling CreateNamespacedSecret()");
            if (secretResponse != null)
            {
                _logger.LogTrace(secretResponse.ToString());
                _logger.LogTrace("Exiting CreateOrUpdateCertificateStoreSecret()");
                return secretResponse;
            }
        }
        catch (HttpOperationException e)
        {
            _logger.LogWarning("Error while attempting to create secret: " + e.Message);
            if (e.Message.Contains("Conflict"))
            {
                _logger.LogDebug($"Secret {secretName} already exists in namespace {namespaceName}, attempting to update secret...");
                _logger.LogTrace("Calling UpdateSecretStore()");
                return UpdateSecretStore(secretName, namespaceName, secretType, certPem, keyPem, k8SSecretData, append, overwrite);
            }
        }
        _logger.LogError("Unable to create secret for unknown reason.");
        return null;
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

    public X509Certificate2Collection CreatePKCS12Collection(X509Certificate2Collection certificateCollection, string currentPassword, string newPassword)
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
        _logger.LogTrace("Entered CreateOrUpdatePKCS12Secret()");

        _logger.LogDebug("Attempting to read existing k8s secret...");
        var existingSecret = new V1Secret();
        try
        {
            existingSecret = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
        }
        catch (HttpOperationException e)
        {
            _logger.LogDebug("Error while attempting to read existing secret: " + e.Message);
            if (e.Message.Contains("Not Found"))
            {
                _logger.LogDebug("No existing secret found.");
            }
            existingSecret = null;
        }

        _logger.LogDebug("Finished reading existing k8s secret.");

        if (existingSecret != null)
        {
            _logger.LogDebug("Existing secret found, attempting to update...");
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
                allowedKeys); 
        }

        _logger.LogDebug("Attempting to create new secret...");

        //convert cert obj pkcs12 to base64
        _logger.LogDebug("Converting certificate to base64...");

        _logger.LogDebug("Creating X509Certificate2 from certificate object...");

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
            case false
                when certObj.PasswordIsK8SSecret && string.IsNullOrEmpty(certObj.StorePasswordPath): // This means the password is expected to be on the secret so add it
            {
                _logger.LogDebug("Adding password to secret...");
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
                _logger.LogDebug("Adding password secret path to secret...");
                if (string.IsNullOrEmpty(passwordFieldName))
                {
                    passwordFieldName = "password";
                }
                // k8SSecretData.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordSecretPath));

                // Lookup password secret path on cluster to see if it exists
                _logger.LogDebug("Attempting to lookup password secret path on cluster...");
                var splitPasswordPath = passwordSecretPath.Split("/");
                // Assume secret pattern is namespace/secretName
                var passwordSecretName = splitPasswordPath[splitPasswordPath.Length - 1];
                var passwordSecretNamespace = splitPasswordPath[0];
                _logger.LogDebug($"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                try
                {
                    var passwordSecret = Client.CoreV1.ReadNamespacedSecret(passwordSecretName, passwordSecretNamespace);
                    password = Encoding.UTF8.GetString(passwordSecret.Data[passwordFieldName]);
                }
                catch (HttpOperationException e)
                {
                    _logger.LogError($"Unable to find secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    _logger.LogError(e.Message);
                    // Attempt to create a new secret
                    _logger.LogDebug($"Attempting to create secret {passwordSecretName} in namespace {passwordSecretNamespace}");
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
                    _logger.LogDebug("Calling CreateNamespacedSecret()");
                    var passwordSecretResponse = Client.CoreV1.CreateNamespacedSecret(passwordSecretData, passwordSecretNamespace);
                    _logger.LogDebug("Finished calling CreateNamespacedSecret()");
                    _logger.LogDebug("Successfully created secret " + passwordSecretPath);
                }
                break;
            }
        }
        _logger.LogTrace("Exiting CreateNewSecret()");
        return k8SSecretData;

    }

    public V1Secret ReadBuddyPass(string secretName, string passwordSecretPath)
    {

        // Lookup password secret path on cluster to see if it exists
        _logger.LogDebug("Attempting to lookup password secret path on cluster...");
        var splitPasswordPath = passwordSecretPath.Split("/");
        // Assume secret pattern is namespace/secretName
        var passwordSecretName = splitPasswordPath[splitPasswordPath.Length - 1];
        var passwordSecretNamespace = splitPasswordPath[0];
        _logger.LogDebug($"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
        var passwordSecretResponse = Client.CoreV1.ReadNamespacedSecret(secretName, passwordSecretNamespace);
        return passwordSecretResponse;
    }

    public V1Secret CreateOrUpdateBuddyPass(string secretName, string passwordFieldName, string passwordSecretPath, string password)
    {
        _logger.LogDebug("Adding password secret path to secret...");
        if (string.IsNullOrEmpty(passwordFieldName))
        {
            passwordFieldName = "password";
        }
        // k8SSecretData.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordSecretPath));

        // Lookup password secret path on cluster to see if it exists
        _logger.LogDebug("Attempting to lookup password secret path on cluster...");
        var splitPasswordPath = passwordSecretPath.Split("/");
        // Assume secret pattern is namespace/secretName
        var passwordSecretName = splitPasswordPath[splitPasswordPath.Length - 1];
        var passwordSecretNamespace = splitPasswordPath[0];
        _logger.LogDebug($"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
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
            _logger.LogError($"Unable to find secret {passwordSecretName} in namespace {passwordSecretNamespace}");
            _logger.LogError(e.Message);
            // Attempt to create a new secret
            _logger.LogDebug($"Attempting to create secret {passwordSecretName} in namespace {passwordSecretNamespace}");

            _logger.LogDebug("Calling CreateNamespacedSecret()");
            var passwordSecretResponse = Client.CoreV1.ReplaceNamespacedSecret(passwordSecretData, secretName, passwordSecretNamespace);
            _logger.LogDebug("Finished calling CreateNamespacedSecret()");
            _logger.LogDebug("Successfully created secret " + passwordSecretPath);
            return passwordSecretResponse;
        }
    }

    private V1Secret CreateNewSecret(string secretName, string namespaceName, string keyPem, string certPem, List<string> chainPem, string secretType, bool separateChain = false)
    {
        _logger.LogTrace("Entered CreateNewSecret()");
        _logger.LogDebug("Attempting to create new secret...");

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
                _logger.LogError("Unknown secret type: " + secretType);
                break;
        }

        var k8SSecretData = new V1Secret();

        switch (secretType)
        {
            case "secret":
                k8SSecretData = new V1Secret
                {
                    Metadata = new V1ObjectMeta
                    {
                        Name = secretName,
                        NamespaceProperty = namespaceName
                    },

                    Data = new Dictionary<string, byte[]>
                    {
                        { "tls.key", Encoding.UTF8.GetBytes(keyPem) }, 
                        { "tls.crt", Encoding.UTF8.GetBytes(certPem) } 
                    }
                };
                break;
            case "tls_secret":
                k8SSecretData = new V1Secret
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
                };
                break;
            default:
                throw new NotImplementedException(
                    $"Secret type {secretType} not implemented. Unable to create or update certificate store {secretName} in {namespaceName} on {GetHost()}.");

        }
        if (chainPem is { Count: > 0 })
        {
            var caCert = chainPem.Where(cer => cer != certPem).Aggregate("", (current, cer) => current + cer);
            if (separateChain)
            {
                k8SSecretData.Data.Add("ca.crt", Encoding.UTF8.GetBytes(caCert));    
            }
            else
            {
                //update tls.crt w/ full chain
                k8SSecretData.Data["tls.crt"] = Encoding.UTF8.GetBytes(certPem + caCert);
            }
            
        }

        _logger.LogTrace("Exiting CreateNewSecret()");
        return k8SSecretData;

    }

    private V1Secret UpdateOpaqueSecret(string secretName, string namespaceName, V1Secret existingSecret, V1Secret newSecret)
    {
        _logger.LogTrace("Entered UpdateOpaqueSecret()");

        existingSecret.Data["tls.key"] = newSecret.Data["tls.key"];
        existingSecret.Data["tls.crt"] = newSecret.Data["tls.crt"];

        //check if existing secret has ca.crt and if new secret has ca.crt
        if (existingSecret.Data.ContainsKey("ca.crt") && newSecret.Data.ContainsKey("ca.crt"))
        {
            _logger.LogDebug("Existing secret '{Namespace}/{Name}' has ca.crt adding chain to this field", namespaceName, secretName);
            _logger.LogTrace("existing ca.crt:\n {CaCrt}", existingSecret.Data["ca.crt"]);
            existingSecret.Data["ca.crt"] = newSecret.Data["ca.crt"];
            _logger.LogTrace("new ca.crt:\n {CaCrt}", newSecret.Data["ca.crt"]);
            
        }
        else
        {
            //Append to tls.crt
            _logger.LogDebug("Existing secret '{Namespace}/{Name}' does not have ca.crt, appending to tls.crt", namespaceName, secretName);
            if (newSecret.Data.TryGetValue("ca.crt", out var value))
            {
                _logger.LogDebug("Appending ca.crt to tls.crt");
                existingSecret.Data["tls.crt"] =
                    Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(newSecret.Data["tls.crt"]) + Encoding.UTF8.GetString(value));
                _logger.LogTrace("New tls.crt:\n {TlsCrt}", existingSecret.Data["tls.crt"]);
            }
            else
            {
                _logger.LogDebug("No chain was provided, only updating leaf certificate for '{Namespace}/{Name}'", namespaceName, secretName);
                _logger.LogTrace("existing tls.crt:\n {TlsCrt}", existingSecret.Data["tls.crt"]);
                existingSecret.Data["tls.crt"] = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(newSecret.Data["tls.crt"]));
                _logger.LogTrace("updated tls.crt:\n {TlsCrt}", existingSecret.Data["tls.crt"]);
            }
        }

        _logger.LogDebug($"Attempting to update secret {secretName} in namespace {namespaceName}");
        _logger.LogTrace("Calling ReplaceNamespacedSecret()");
        var secretResponse = Client.CoreV1.ReplaceNamespacedSecret(existingSecret, secretName, namespaceName);
        _logger.LogTrace("Finished calling ReplaceNamespacedSecret()");
        _logger.LogTrace("Exiting UpdateOpaqueSecret()");
        return secretResponse;
    }

    private V1Secret UpdateOpaqueSecretMultiple(string secretName, string namespaceName, V1Secret existingSecret, string certPem, string keyPem)
    {
        _logger.LogTrace("Entered UpdateOpaqueSecret()");

        var existingCerts = existingSecret.Data.ContainsKey("certificates")
            ? Encoding.UTF8.GetString(existingSecret.Data["certificates"])
            : ""; 

        _logger.LogTrace("Existing certificates: " + existingCerts);

        var existingKeys = existingSecret.Data.ContainsKey("tls.key")
            ? Encoding.UTF8.GetString(existingSecret.Data["tls.key"])
            : ""; 
        // Logger.LogTrace("Existing private keys: " + existingKeys);

        if (existingCerts.Contains(certPem) && existingKeys.Contains(keyPem))
        {
            // certificate already exists, return existing secret
            _logger.LogDebug($"Certificate already exists in secret {secretName} in namespace {namespaceName}");
            _logger.LogTrace("Exiting UpdateOpaqueSecret()");
            return existingSecret;
        }

        if (!existingCerts.Contains(certPem))
        {
            _logger.LogDebug("Certificate does not exist in secret, adding certificate to secret");
            var newCerts = existingCerts;
            if (existingCerts.Length > 0)
            {
                _logger.LogTrace("Adding comma to existing certificates");
                newCerts += ",";
            }
            _logger.LogTrace("Adding certificate to existing certificates");
            newCerts += certPem;

            _logger.LogTrace("Updating 'certificates' secret data");
            existingSecret.Data["certificates"] = Encoding.UTF8.GetBytes(newCerts);
        }

        if (!existingKeys.Contains(keyPem))
        {
            _logger.LogDebug("Private key does not exist in secret, adding private key to secret");
            var newKeys = existingKeys;
            if (existingKeys.Length > 0)
            {
                _logger.LogTrace("Adding comma to existing private keys");
                newKeys += ",";
            }
            _logger.LogTrace("Adding private key to existing private keys");
            newKeys += keyPem;

            _logger.LogTrace("Updating 'private_keys' secret data");
            existingSecret.Data["tls.key"] = Encoding.UTF8.GetBytes(newKeys);
        }

        _logger.LogDebug($"Attempting to update secret {secretName} in namespace {namespaceName}");
        _logger.LogTrace("Calling ReplaceNamespacedSecret()");
        var secretResponse = Client.CoreV1.ReplaceNamespacedSecret(existingSecret, secretName, namespaceName);
        _logger.LogTrace("Finished calling ReplaceNamespacedSecret()");
        _logger.LogTrace("Exiting UpdateOpaqueSecret()");
        return secretResponse;
    }

    private V1Secret UpdateSecretStore(string secretName, string namespaceName, string secretType, string certPem, string keyPem, V1Secret newData, bool append,
        bool overwrite = false)
    {
        _logger.LogTrace("Entered UpdateSecretStore()");
        _logger.LogTrace("Calling ReadNamespacedSecret()");
        var existingSecret = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName, true);
        _logger.LogTrace("Finished calling ReadNamespacedSecret()");
        if (existingSecret == null)
        {
            var errMsg =
                $"Update {secretType} secret {secretName} in Kubernetes namespace {namespaceName} on {GetHost()} failed. Also unable to read secret, please verify credentials have correct access.";
            _logger.LogError(errMsg);
            throw new Exception(errMsg);
        }

        _logger.LogTrace($"Entering switch statement for secret type {secretType}");
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
                _logger.LogInformation($"Attempting to update opaque secret {secretName} in namespace {namespaceName}");
                _logger.LogTrace("Calling UpdateOpaqueSecret()");
                return UpdateOpaqueSecret(secretName, namespaceName, existingSecret, newData);
            }
            // case "tls_secret" when !overwrite:
            //     var errMsg = "Overwrite is not specified, cannot add multiple certificates to a Kubernetes secret type 'tls_secret'.";
            //     Logger.LogError(errMsg);
            //     Logger.LogTrace("Exiting UpdateSecretStore()");
            //     throw new Exception(errMsg);
            case "tls_secret":
            {
                _logger.LogInformation($"Attempting to update tls secret {secretName} in namespace {namespaceName}");
                _logger.LogTrace("Calling ReplaceNamespacedSecret()");
                var secretResponse = Client.CoreV1.ReplaceNamespacedSecret(newData, secretName, namespaceName);
                _logger.LogTrace("Finished calling ReplaceNamespacedSecret()");
                _logger.LogTrace("Exiting UpdateSecretStore()");
                return secretResponse;
            }
            default:
                var dErrMsg = $"Secret type not implemented. Unable to create or update certificate store {secretName} in {namespaceName} on {GetHost()}.";
                _logger.LogError(dErrMsg);
                _logger.LogTrace("Exiting UpdateSecretStore()");
                throw new NotImplementedException(dErrMsg);
        }
    }
    public V1Secret GetCertificateStoreSecret(string secretName, string namespaceName)
    {
        _logger.LogTrace("Entered GetCertificateStoreSecret()");
        _logger.LogTrace("Calling ReadNamespacedSecret()");
        _logger.LogDebug($"Attempting to read secret {secretName} in namespace {namespaceName} from {GetHost()}");
        return Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
    }

    private string CleanOpaqueStore(string existingEntries, string pemString)
    {
        _logger.LogTrace("Entered CleanOpaqueStore()");
        // Logger.LogTrace($"pemString: {pemString}");
        _logger.LogTrace("Entering try/catch block to remove existing certificate from opaque secret");
        try
        {
            _logger.LogDebug("Attempting to remove existing certificate from opaque secret");
            existingEntries = existingEntries.Replace(pemString, "").Replace(",,", ",");

            if (existingEntries.StartsWith(","))
            {
                _logger.LogDebug("Removing leading comma from existing certificates.");
                existingEntries = existingEntries.Substring(1);
            }
            if (existingEntries.EndsWith(","))
            {
                _logger.LogDebug("Removing trailing comma from existing certificates.");
                existingEntries = existingEntries.Substring(0, existingEntries.Length - 1);
            }
        }
        catch (Exception)
        {
            // Didn't find existing key for whatever reason so no need to delete.
            _logger.LogWarning("Unable to find existing certificate in opaque secret. No need to remove.");
        }
        _logger.LogTrace("Exiting CleanOpaqueStore()");
        return existingEntries;
    }

    private V1Secret DeleteCertificateStoreSecret(string secretName, string namespaceName, string alias)
    {
        _logger.LogTrace("Entered DeleteCertificateStoreSecret()");
        _logger.LogTrace("secretName: " + secretName);
        _logger.LogTrace("namespaceName: " + namespaceName);
        _logger.LogTrace("alias: " + alias);

        _logger.LogDebug($"Attempting to read secret {secretName} in namespace {namespaceName} from {GetHost()}");
        _logger.LogTrace("Calling ReadNamespacedSecret()");
        var existingSecret = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName, true);
        _logger.LogTrace("Finished calling ReadNamespacedSecret()");
        if (existingSecret == null)
        {
            var errMsg =
                $"Delete secret {secretName} in Kubernetes namespace {namespaceName} failed. Unable unable to read secret, please verify credentials have correct access.";
            _logger.LogError(errMsg);
            throw new Exception(errMsg);
        }

        // handle cert removal
        _logger.LogDebug("Parsing existing certificates from secret into a string.");
        foreach (var sKey in existingSecret.Data.Keys)
        {
            var existingCerts = Encoding.UTF8.GetString(existingSecret.Data[sKey]); 
            _logger.LogTrace("existingCerts: " + existingCerts);

            _logger.LogDebug("Parsing existing private keys from secret into a string.");
            var existingKeys = Encoding.UTF8.GetString(existingSecret.Data["tls.key"]); 
            // Logger.LogTrace("existingKeys: " + existingKeys);

            _logger.LogDebug("Splitting existing certificates into an array.");
            var certs = existingCerts.Split(",");
            _logger.LogTrace("certs: " + certs);

            _logger.LogDebug("Splitting existing private keys into an array.");
            var keys = existingKeys.Split(",");
            // Logger.LogTrace("keys: " + keys);

            var index = 0; //Currently keys are assumed to be in the same order as certs. 
            _logger.LogTrace("Entering foreach loop to remove existing certificate from opaque secret");
            foreach (var cer in certs)
            {
                _logger.LogTrace("pkey index: " + index);
                _logger.LogTrace("cer: " + cer);
                _logger.LogTrace("alias: " + alias);
                if (string.IsNullOrEmpty(cer))
                {
                    _logger.LogDebug("Found empty certificate string. Skipping.");
                    continue;
                }
                _logger.LogDebug("Creating X509Certificate2 from certificate string.");
                var sCert = new X509Certificate2();
                try
                {
                    sCert = new X509Certificate2(Encoding.UTF8.GetBytes(cer));
                }
                catch (Exception e)
                {
                    _logger.LogWarning($"Unable to create X509Certificate2 from string in '{sKey}' field. Skipping. Error: {e.Message}");
                    continue;
                }

                _logger.LogDebug("sCert.Thumbprint: " + sCert.Thumbprint);

                if (sCert.Thumbprint == alias)
                {
                    _logger.LogDebug("Found matching certificate thumbprint. Removing certificate from opaque secret.");
                    _logger.LogTrace("Calling CleanOpaqueStore()");
                    existingCerts = CleanOpaqueStore(existingCerts, cer);
                    _logger.LogTrace("Finished calling CleanOpaqueStore()");
                    _logger.LogTrace("Updated existingCerts: " + existingCerts);
                    _logger.LogTrace("Calling CleanOpaqueStore()");
                    try
                    {
                        existingKeys = CleanOpaqueStore(existingKeys, keys[index]);
                    }
                    catch (IndexOutOfRangeException)
                    {
                        // Didn't find existing key for whatever reason so no need to delete.
                        // Find the corresponding key the the keys array and by checking if the private key corresponds to the cert public key.
                        _logger.LogWarning($"Unable to find corresponding private key in opaque secret for certificate {sCert.Thumbprint}. No need to remove.");
                    }

                }
                _logger.LogTrace("Incrementing pkey index...");
                index++; //Currently keys are assumed to be in the same order as certs.
            }

            _logger.LogDebug("Updating existing secret with new certificate data.");
            existingSecret.Data[sKey] = Encoding.UTF8.GetBytes(existingCerts); 
            _logger.LogDebug("Updating existing secret with new key data.");
            try
            {
                existingSecret.Data["tls.key"] = Encoding.UTF8.GetBytes(existingKeys);
            }
            catch (Exception)
            {
                _logger.LogWarning("Unable to update private_keys in opaque secret. This is expected if the secret did not contain private keys to begin with.");
            } 


            // Update Kubernetes secret
            _logger.LogDebug($"Updating secret {secretName} in namespace {namespaceName} on {GetHost()} with new certificate data.");
            _logger.LogTrace("Calling ReplaceNamespacedSecret()");
        }

        return Client.CoreV1.ReplaceNamespacedSecret(existingSecret, secretName, namespaceName);
    }

    public V1Status DeleteCertificateStoreSecret(string secretName, string namespaceName, string storeType, string alias)
    {
        _logger.LogTrace("Entered DeleteCertificateStoreSecret()");
        _logger.LogTrace("secretName: " + secretName);
        _logger.LogTrace("namespaceName: " + namespaceName);
        _logger.LogTrace("storeType: " + storeType);
        _logger.LogTrace("alias: " + alias);
        _logger.LogTrace("Entering switch statement to determine which delete method to use.");
        switch (storeType)
        {
            case "secret":
            case "opaque":
                // check the current inventory and only remove the cert if it is found else throw not found exception
                _logger.LogDebug($"Attempting to delete certificate from opaque secret {secretName} in namespace {namespaceName} on {GetHost()}");
                _logger.LogTrace("Calling DeleteCertificateStoreSecret()");
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
                _logger.LogDebug($"Deleting TLS secret {secretName} in namespace {namespaceName} on {GetHost()}");
                _logger.LogTrace("Calling DeleteNamespacedSecret()");
                return Client.CoreV1.DeleteNamespacedSecret(
                    secretName,
                    namespaceName,
                    new V1DeleteOptions()
                );
            case "certificate":
                _logger.LogDebug($"Deleting Certificate Signing Request {secretName} on {GetHost()}");
                _logger.LogTrace("Calling CertificatesV1.DeleteCertificateSigningRequest()");
                _ = Client.CertificatesV1.DeleteCertificateSigningRequest(
                    secretName,
                    new V1DeleteOptions()
                );
                var errMsg = "DeleteCertificateStoreSecret not implemented for 'certificate' type.";
                _logger.LogError(errMsg);
                throw new NotImplementedException(errMsg);
            default:
                var dErrMsg = $"DeleteCertificateStoreSecret not implemented for type '{storeType}'.";
                _logger.LogError(dErrMsg);
                throw new NotImplementedException(dErrMsg);
        }
    }
    public List<string> DiscoverCertificates()
    {
        _logger.LogTrace("Entered DiscoverCertificates()");
        var locations = new List<string>();
        _logger.LogDebug("Discovering certificates from k8s certificate resources.");
        _logger.LogTrace("Calling CertificatesV1.ListCertificateSigningRequest()");
        var csr = Client.CertificatesV1.ListCertificateSigningRequest();
        _logger.LogTrace("Finished calling CertificatesV1.ListCertificateSigningRequest()");
        _logger.LogTrace("csr.Items.Count: " + csr.Items.Count);

        _logger.LogTrace("Entering foreach loop to add certificate locations to list.");
        var clusterName = GetClusterName();
        foreach (var cr in csr)
        {
            _logger.LogTrace("cr.Metadata.Name: " + cr.Metadata.Name);
            _logger.LogDebug("Parsing certificate from certificate resource.");
            var utfCert = cr.Status.Certificate != null ? Encoding.UTF8.GetString(cr.Status.Certificate) : "";
            _logger.LogDebug("Parsing certificate signing request from certificate resource.");
            var utfCsr = cr.Spec.Request != null
                ? Encoding.UTF8.GetString(cr.Spec.Request, 0, cr.Spec.Request.Length)
                : "";

            if (utfCsr != "")
            {
                _logger.LogTrace("utfCsr: " + utfCsr);
            }
            if (utfCert == "")
            {
                _logger.LogWarning("CSR has not been signed yet. Skipping.");
                continue;
            }

            _logger.LogDebug("Converting UTF8 encoded certificate to X509Certificate2 object.");
            var cert = new X509Certificate2(Encoding.UTF8.GetBytes(utfCert));
            _logger.LogTrace("cert: " + cert);

            _logger.LogDebug("Getting certificate name from X509Certificate2 object.");
            var certName = cert.GetNameInfo(X509NameType.SimpleName, false);
            _logger.LogTrace("certName: " + certName);

            _logger.LogDebug($"Adding certificate {certName} discovered location to list.");
            locations.Add($"{clusterName}/certificate/{certName}");
        }

        _logger.LogDebug("Completed discovering certificates from k8s certificate resources.");
        _logger.LogTrace("locations.Count: " + locations.Count);
        _logger.LogTrace("locations: " + locations);
        _logger.LogTrace("Exiting DiscoverCertificates()");
        return locations;
    }

    public string[] GetCertificateSigningRequestStatus(string name)
    {
        _logger.LogTrace("Entered GetCertificateSigningRequestStatus()");
        _logger.LogDebug($"Attempting to read {name} certificate signing request from {GetHost()}...");
        var cr = Client.CertificatesV1.ReadCertificateSigningRequest(name);
        _logger.LogDebug($"Successfully read {name} certificate signing request from {GetHost()}.");
        _logger.LogTrace("cr: " + cr);
        _logger.LogTrace("Attempting to parse certificate from certificate resource.");
        var utfCert = cr.Status.Certificate != null ? Encoding.UTF8.GetString(cr.Status.Certificate) : "";
        _logger.LogTrace("utfCert: " + utfCert);

        _logger.LogDebug($"Attempting to parse certificate signing request from certificate resource {name}.");
        var cert = new X509Certificate2(Encoding.UTF8.GetBytes(utfCert));
        _logger.LogTrace("cert: " + cert);
        _logger.LogTrace("Exiting GetCertificateSigningRequestStatus()");
        return new[] { utfCert };
    }

    public X509Certificate ReadDerCertificate(string derString)
    {
        var derData = Convert.FromBase64String(derString);
        var certificateParser = new X509CertificateParser();
        return certificateParser.ReadCertificate(derData);
    }
    public X509Certificate ReadPemCertificate(string pemString)
    {
        using var reader = new StringReader(pemString);
        var pemReader = new PemReader(reader);
        var pemObject = pemReader.ReadPemObject();
        if (pemObject is not { Type: "CERTIFICATE" }) return null;

        var certificateBytes = pemObject.Content;
        var certificateParser = new X509CertificateParser();
        return certificateParser.ReadCertificate(certificateBytes);

    }

    public string ExtractPrivateKeyAsPem(Pkcs12Store store, string password)
    {
        // Get the first private key entry
        // Get the first private key entry
        var alias = store.Aliases.FirstOrDefault(entryAlias => store.IsKeyEntry(entryAlias));

        if (alias == null)
        {
            throw new Exception("No private key found in the provided PFX/P12 file.");
        }

        // Get the private key
        var keyEntry = store.GetKey(alias);
        var privateKeyParams = keyEntry.Key;

        var pemType = privateKeyParams switch
        {
            RsaPrivateCrtKeyParameters => "RSA PRIVATE KEY",
            ECPrivateKeyParameters => "EC PRIVATE KEY",
            _ => throw new Exception("Unsupported private key type.")
        };

        // Convert the private key to PEM format
        var sw = new StringWriter();
        var pemWriter = new PemWriter(sw);
        var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParams);
        var privateKeyBytes = privateKeyInfo.ToAsn1Object().GetEncoded();
        var pemObject = new PemObject(pemType, privateKeyBytes);
        pemWriter.WriteObject(pemObject);
        pemWriter.Writer.Flush();

        return sw.ToString();
    }

    public List<X509Certificate> LoadCertificateChain(string pemData)
    {
        var pemReader = new PemReader(new StringReader(pemData));
        var certificates = new List<X509Certificate>();

        PemObject pemObject;
        while ((pemObject = pemReader.ReadPemObject()) != null)
        {
            if (pemObject.Type == "CERTIFICATE")
            {
                var certificateParser = new X509CertificateParser();
                var certificate = certificateParser.ReadCertificate(pemObject.Content);
                certificates.Add(certificate);
            }
        }

        return certificates;
    }

    public string ConvertToPem(X509Certificate certificate)
    {
        var pemObject = new PemObject("CERTIFICATE", certificate.GetEncoded());
        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);
        pemWriter.WriteObject(pemObject);
        pemWriter.Writer.Flush();
        return stringWriter.ToString();

    }

    public List<string> DiscoverSecrets(string[] allowedKeys, string secType, string ns = "default", bool namespaceIsStore = false, bool clusterIsStore = false)
    {
        // Get a list of all namespaces
        _logger.LogTrace("Entered DiscoverSecrets()");
        V1NamespaceList namespaces;
        var clusterName = GetClusterName() ?? GetHost();

        var nsList = new string[] { };

        var locations = new List<string>();

        if (secType == "cluster")
        {
            _logger.LogTrace("Discovering K8S cluster secrets from k8s cluster resources and returning only a single location.");
            locations.Add($"{clusterName}");
            return locations;
        }


        _logger.LogDebug("Attempting to list k8s namespaces from " + clusterName);
        namespaces = Client.CoreV1.ListNamespace();
        _logger.LogTrace("namespaces.Items.Count: " + namespaces.Items.Count);
        _logger.LogTrace("namespaces.Items: " + namespaces.Items);

        nsList = ns.Contains(",") ? ns.Split(",") : new[] { ns };
        foreach (var nsLI in nsList)
        {
            var secretsList = new List<string>();
            _logger.LogTrace("Entering foreach loop to list all secrets in each returned namespace.");
            foreach (var nsObj in namespaces.Items)
            {
                if (nsLI != "all" && nsLI != nsObj.Metadata.Name)
                {
                    _logger.LogWarning("Skipping namespace " + nsObj.Metadata.Name + " because it does not match the namespace filter.");
                    continue;
                }

                _logger.LogDebug("Attempting to list secrets in namespace " + nsObj.Metadata.Name);
                // Get a list of all secrets in the namespace
                _logger.LogTrace("Calling CoreV1.ListNamespacedSecret()");
                var secrets = Client.CoreV1.ListNamespacedSecret(nsObj.Metadata.Name);
                _logger.LogTrace("Finished calling CoreV1.ListNamespacedSecret()");

                _logger.LogDebug("Attempting to read each secret in namespace " + nsObj.Metadata.Name);
                _logger.LogTrace("Entering foreach loop to read each secret in namespace " + nsObj.Metadata.Name);

                if (secType == "namespace")
                {
                    _logger.LogDebug("Discovering K8S secrets at the namespace level");
                    var nsLocation = $"{clusterName}/namespace/{nsObj.Metadata.Name}";
                    locations.Add(nsLocation);
                    _logger.LogTrace("Added namespace location " + nsLocation + " to list of locations.");
                    continue;
                }

                foreach (var secret in secrets.Items)
                {
                    if (secret.Type.ToLower() is "kubernetes.io/tls" or "opaque" or "pkcs12" or "p12" or "pfx" or "jks")
                    {
                        _logger.LogTrace("secret.Type: " + secret.Type);
                        _logger.LogTrace("secret.Metadata.Name: " + secret.Metadata.Name);
                        _logger.LogTrace("Calling CoreV1.ReadNamespacedSecret()");
                        var secretData = Client.CoreV1.ReadNamespacedSecret(secret.Metadata.Name, nsObj.Metadata.Name);
                        _logger.LogTrace("Finished calling CoreV1.ReadNamespacedSecret()");
                        // Logger.LogTrace("secretData: " + secretData);
                        _logger.LogTrace("Entering switch statement to check secret type.");

                        switch (secret.Type)
                        {
                            case "kubernetes.io/tls":
                                if (secType != "kubernetes.io/tls" && secType != "tls")
                                {
                                    _logger.LogWarning("Skipping secret " + secret.Metadata.Name + " because it is not of type " + secType);
                                    continue;
                                }
                                _logger.LogDebug("Attempting to parse TLS certificate from secret");
                                var certData = Encoding.UTF8.GetString(secretData.Data["tls.crt"]);
                                _logger.LogTrace("certData: " + certData);

                                _logger.LogDebug("Attempting to parse TLS key from secret");
                                var keyData = Encoding.UTF8.GetString(secretData.Data["tls.key"]);

                                _logger.LogDebug("Attempting to convert TLS certificate to X509Certificate2 object");
                                // _ = new X509Certificate2(secretData.Data["tls.crt"]); // Check if cert is valid

                                var cLocation = $"{clusterName}/{nsObj.Metadata.Name}/secrets/{secret.Metadata.Name}";
                                _logger.LogDebug($"Adding certificate location {cLocation} to list of discovered certificates");
                                locations.Add(cLocation);
                                secretsList.Add(certData);
                                break;
                            case "Opaque":
                                if (secType != "Opaque" && secType != "pkcs12" && secType != "p12" && secType != "pfx" && secType != "jks")
                                {
                                    _logger.LogWarning("Skipping secret " + secret.Metadata.Name + " because it is not of type " + secType);
                                    continue;
                                }

                                // Check if a 'certificates' key exists
                                _logger.LogDebug("Attempting to parse certificate from opaque secret");
                                if (secretData.Data == null || secret.Data.Keys == null)
                                {
                                    _logger.LogWarning("secretData.Data is null for secret '" + secret.Metadata.Name + "'. Skipping secret.");
                                    continue;
                                }
                                _logger.LogTrace("Entering foreach loop to check if any allowed keys exist in secret");
                                foreach (var dataKey in secretData.Data.Keys)
                                {
                                    _logger.LogDebug("Checking if secret key " + dataKey + " is in list of allowed keys" + allowedKeys);
                                    _logger.LogTrace("dataKey: " + dataKey);
                                    try
                                    {
                                        // split dataKey by '.' and take the last element
                                        var dataKeyArray = dataKey.Split(".");
                                        var extension = dataKeyArray[^1];

                                        _logger.LogDebug("Checking if key " + extension + " is in list of allowed keys" + allowedKeys);
                                        _logger.LogTrace("extension: " + extension);


                                        if (!allowedKeys.Contains(extension))
                                        {
                                            _logger.LogTrace("Extension " + extension + " is not in list of allowed keys" + allowedKeys);
                                            if (!allowedKeys.Contains(dataKey))
                                            {
                                                _logger.LogDebug("Skipping secret field" + dataKey + " because it is not in the list of allowed keys" + allowedKeys);
                                                continue;
                                            }
                                        }
                                        
                                        _logger.LogDebug("Secret field '" + dataKey + "' is an allowed key.");
                                        _logger.LogDebug("Attempting to parse certificate from opaque secret data");
                                        // Attempt to read data as PEM
                                        if (secType != "pkcs12" && secType != "jks")
                                        {
                                            
                                            var certs = Encoding.UTF8.GetString(secretData.Data[dataKey]);
                                            _logger.LogTrace("certs: " + certs);
                                            var certObj = ReadPemCertificate(certs);
                                            if (certObj == null)
                                            {
                                                _logger.LogDebug("Failed to parse certificate from opaque secret data as PEM. Attempting to parse as DER");
                                                // Attempt to read data as DER
                                                certObj = ReadDerCertificate(certs);
                                                if (certObj == null)
                                                {
                                                    _logger.LogDebug("Failed to parse certificate from opaque secret data as DER. Skipping secret {Name}", secret?.Metadata?.Name);
                                                    continue;
                                                }
                                            }    
                                        }
                                        else if (secType == "pkcs12" || secType == "jks")
                                        {
                                            _logger.LogDebug("Discovery does not support store password for pkcs12 or jks secrets. Assuming secret '{Name}' with matching key '{Key} is valid ", secret?.Metadata?.Name, dataKey);
                                        }
                                        

                                        locations.Add($"{clusterName}/{nsObj.Metadata.Name}/secrets/{secret.Metadata.Name}");

                                    }
                                    catch (Exception e)
                                    {
                                        _logger.LogError("Error parsing certificate from opaque secret: " + e.Message);
                                        _logger.LogTrace(e.ToString());
                                        _logger.LogTrace(e.StackTrace);
                                    }
                                }
                                _logger.LogTrace("Exiting foreach loop to check if any allowed keys exist in secret");
                                break;
                        }
                    }
                }
            }

        }

        _logger.LogTrace("locations: " + locations);
        _logger.LogTrace("Exiting DiscoverSecrets()");
        return locations;
    }

    public struct JksSecret
    {
        public string SecretPath;
        public string SecretFieldName;
        public V1Secret Secret;
        public string Password;
        public string PasswordPath;
        public List<string> AllowedKeys;
        public Dictionary<string, byte[]> Inventory;
    }

    public struct Pkcs12Secret
    {
        public string SecretPath;
        public string SecretFieldName;
        public V1Secret Secret;
        public string Password;
        public string PasswordPath;
        public List<string> AllowedKeys;
        public Dictionary<string, byte[]> Inventory;
    }

    public JksSecret GetJksSecret(string secretName, string namespaceName, string password = null, string passwordPath = null, List<string> allowedKeys = null)
    {
        _logger.LogTrace("Entered GetJKSSecret()");
        _logger.LogTrace("secretName: " + secretName);
        // Read k8s secret
        _logger.LogTrace("Calling CoreV1.ReadNamespacedSecret()");
        try
        {
            var secret = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
            _logger.LogTrace("Finished calling CoreV1.ReadNamespacedSecret()");
            // Logger.LogTrace("secret: " + secret);
            // Logger.LogTrace("secret.Data: " + secret.Data);
            if (secret.Data != null)
            {
                _logger.LogTrace("secret.Data.Keys: {Name}", secret.Data.Keys);
                _logger.LogTrace("secret.Data.Keys.Count: " + secret.Data.Keys.Count);

                allowedKeys ??= new List<string>() { "jks", "JKS", "Jks" };
                
                var secretData = new Dictionary<string, byte[]>();

                foreach (var secretFieldName in secret?.Data.Keys)
                {
                    _logger.LogTrace("secretFieldName: {Name}", secretFieldName);
                    var sField = secretFieldName;
                    if (secretFieldName.Contains('.'))
                    {
                        sField = secretFieldName.Split(".")[^1];
                    }
                    var isJksField = allowedKeys.Any(allowedKey => sField.Contains(allowedKey));

                    if (!isJksField) continue;

                    _logger.LogTrace("Key " + secretFieldName + " is in list of allowed keys" + allowedKeys);
                    var data = secret.Data[secretFieldName];
                    _logger.LogTrace("data: " + data);
                    secretData.Add(secretFieldName, data);
                }
                var output = new JksSecret()
                {
                    Secret = secret,
                    SecretPath = $"{namespaceName}/secrets/{secretName}",
                    SecretFieldName = secret.Data.Keys.FirstOrDefault(),
                    Password = password,
                    PasswordPath = passwordPath,
                    AllowedKeys = allowedKeys,
                    Inventory = secretData
                };
                _logger.LogTrace("Exiting GetJKSSecret()");
                return output;
            }

            throw new InvalidK8SSecretException($"K8S secret {namespaceName}/secrets/{secretName} is empty.");

        }
        catch (HttpOperationException e)
        {

            if (e.Response.StatusCode != HttpStatusCode.NotFound) throw e;

            // var output = new JksSecret()
            // {
            //     Secret = new V1Secret(),
            //     SecretPath = $"{namespaceName}/secrets/{secretName}",
            //     SecretFieldName = "jks",
            //     Password = password,
            //     PasswordPath = passwordPath,
            //     AllowedKeys = allowedKeys,
            //     Inventory = new Dictionary<string, byte[]>()
            // };
            // _logger.LogTrace("Exiting GetJKSSecret()");
            // return output;
            _logger.LogError("K8S secret {SecretName} not found in namespace {NamespaceName}", secretName, namespaceName);
            throw new StoreNotFoundException($"K8S secret not found {namespaceName}/secrets/{secretName}");
        }
        return new JksSecret();
    }

    public Pkcs12Secret GetPkcs12Secret(string secretName, string namespaceName, string password = null, string passwordPath = null, List<string> allowedKeys = null)
    {
        _logger.LogTrace("Entered GetPKCS12Secret()");
        _logger.LogTrace("secretName: " + secretName);
        // Read k8s secret
        _logger.LogTrace("Calling CoreV1.ReadNamespacedSecret()");
        try
        {
            var secret = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
            _logger.LogTrace("Finished calling CoreV1.ReadNamespacedSecret()");
            // Logger.LogTrace("secret: " + secret);
            // Logger.LogTrace("secret.Data: " + secret.Data);
            _logger.LogTrace("secret.Data.Keys: " + secret.Data.Keys);
            _logger.LogTrace("secret.Data.Keys.Count: " + secret.Data.Keys.Count);

            allowedKeys ??= new List<string>() { "pkcs12", "p12", "P12", "PKCS12", "pfx", "PFX" };


            var secretData = new Dictionary<string, byte[]>();

            foreach (var secretFieldName in secret?.Data.Keys)
            {
                _logger.LogTrace("secretFieldName: " + secretFieldName);
                var sField = secretFieldName;
                if (secretFieldName.Contains('.'))
                {
                    sField = secretFieldName.Split(".")[^1];
                }
                var isPkcs12Field = allowedKeys.Any(allowedKey => sField.Contains(allowedKey));

                if (!isPkcs12Field) continue;

                _logger.LogTrace("Key " + secretFieldName + " is in list of allowed keys" + allowedKeys);
                var data = secret.Data[secretFieldName];
                _logger.LogTrace("data: " + data);
                secretData.Add(secretFieldName, data);
            }
            var output = new Pkcs12Secret()
            {
                Secret = secret,
                SecretPath = $"{namespaceName}/secrets/{secretName}",
                SecretFieldName = secret.Data.Keys.FirstOrDefault(),
                Password = password,
                PasswordPath = passwordPath,
                AllowedKeys = allowedKeys,
                Inventory = secretData
            };
            _logger.LogTrace("Exiting GetPkcs12Secret()");
            return output;
        }
        catch (HttpOperationException e)
        {
            _logger.LogError("K8S secret not found {NamespaceName}/secrets/{SecretName}", namespaceName, secretName);
            if (e.Response.StatusCode != HttpStatusCode.NotFound) throw e;

            throw new StoreNotFoundException($"K8S secret not found {namespaceName}/secrets/{secretName}");
        }
        return new Pkcs12Secret();
    }

    public V1CertificateSigningRequest CreateCertificateSigningRequest(string name, string namespaceName, string csr)
    {
        _logger.LogTrace("Entered CreateCertificateSigningRequest()");
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
        _logger.LogTrace("request: " + request);
        _logger.LogTrace("Calling CertificatesV1.CreateCertificateSigningRequest()");
        return Client.CertificatesV1.CreateCertificateSigningRequest(request);
    }

    public CsrObject GenerateCertificateRequest(string name, string[] sans, IPAddress[] ips,
        string keyType = "RSA", int keyBits = 4096)
    {
        _logger.LogTrace("Entered GenerateCertificateRequest()");
        var sanBuilder = new SubjectAlternativeNameBuilder();
        _logger.LogDebug($"Building IP and SAN lists for CSR {name}");

        foreach (var ip in ips) sanBuilder.AddIpAddress(ip);
        foreach (var san in sans) sanBuilder.AddDnsName(san);

        _logger.LogTrace("sanBuilder: " + sanBuilder);

        _logger.LogTrace("Setting DN to CN=" + name);
        var distinguishedName = new X500DistinguishedName(name);

        _logger.LogDebug("Generating private key and CSR");
        using var rsa = RSA.Create(4096);  

        _logger.LogDebug("Exporting private key and public key");
        var pkey = rsa.ExportPkcs8PrivateKey();
        var pubkey = rsa.ExportRSAPublicKey();

        _logger.LogDebug("Building CSR object");
        var request =
            new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        _logger.LogDebug("Adding extensions to CSR");
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

    public V1Secret CreateOrUpdateJksSecret(JksSecret k8SData, string kubeSecretName, string kubeNamespace)
    {
        // Create V1Secret object and replace existing secret
        _logger.LogDebug("Entered CreateOrUpdateJksSecret()");
        _logger.LogTrace("kubeSecretName: {Name}", kubeSecretName);
        _logger.LogTrace("kubeNamespace: {Namespace}", kubeNamespace);
        var s1 = new V1Secret
        {
            ApiVersion = "v1",
            Kind = "Secret",
            Type = "Opaque",
            Metadata = new V1ObjectMeta
            {
                Name = kubeSecretName,
                NamespaceProperty = kubeNamespace
            },
            Data = k8SData.Secret?.Data //This preserves any existing data/fields we didn't modify
        };


        // Update the fields/data we did modify
        s1.Data ??= new Dictionary<string, byte[]>();
        foreach (var inventoryItem in k8SData.Inventory)
        {
            _logger.LogTrace("Adding inventory item {Key} to secret", inventoryItem.Key);
            s1.Data[inventoryItem.Key] = inventoryItem.Value;
        }

        // Create secret if it doesn't exist
        try
        {
            _logger.LogDebug("Checking if secret {Name} exists in namespace {Namespace}", kubeSecretName,
                kubeNamespace);
            Client.CoreV1.ReadNamespacedSecret(kubeSecretName, kubeNamespace);
        }
        catch (HttpOperationException e)
        {
            if (e.Response.StatusCode == HttpStatusCode.NotFound)
            {
                return Client.CoreV1.CreateNamespacedSecret(s1, kubeNamespace);
            }
            _logger.LogError("Error checking if secret {Name} exists in namespace {Namespace}: {Message}",
                kubeSecretName, kubeNamespace, e.Message);
        }

        // Replace existing secret
        _logger.LogDebug("Replacing secret {Name} in namespace {Namespace}", kubeSecretName, kubeNamespace);
        return Client.CoreV1.ReplaceNamespacedSecret(s1, kubeSecretName, kubeNamespace);
    }

    public V1Secret CreateOrUpdatePkcs12Secret(Pkcs12Secret k8SData, string kubeSecretName, string kubeNamespace)
    {
        // Create V1Secret object and replace existing secret
        var s1 = new V1Secret
        {
            ApiVersion = "v1",
            Kind = "Secret",
            Type = "Opaque",
            Metadata = new V1ObjectMeta
            {
                Name = kubeSecretName,
                NamespaceProperty = kubeNamespace
            },
            Data = k8SData.Secret?.Data
        };

        s1.Data ??= new Dictionary<string, byte[]>();
        foreach (var inventoryItem in k8SData.Inventory)
        {
            s1.Data[inventoryItem.Key] = inventoryItem.Value;
        }

        // Create secret if it doesn't exist
        try
        {
            Client.CoreV1.ReadNamespacedSecret(kubeSecretName, kubeNamespace);
        }
        catch (HttpOperationException e)
        {
            if (e.Response.StatusCode == HttpStatusCode.NotFound)
            {
                return Client.CoreV1.CreateNamespacedSecret(s1, kubeNamespace);
            }
        }

        // Replace existing secret
        return Client.CoreV1.ReplaceNamespacedSecret(s1, kubeSecretName, kubeNamespace);
    }
}
