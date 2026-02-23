// Copyright 2024 Keyfactor
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
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using k8s;
using k8s.Autorest;
using k8s.Exceptions;
using k8s.KubeConfigModels;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Exceptions;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
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

/// <summary>
/// Provides Kubernetes API client operations for certificate management.
/// Handles authentication, secret CRUD operations, certificate signing requests,
/// and discovery of certificate stores across namespaces and clusters.
/// </summary>
public partial class KubeCertificateManagerClient
{
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="KubeCertificateManagerClient"/> class.
    /// </summary>
    /// <param name="kubeconfig">JSON-formatted kubeconfig containing cluster, user, and context information.</param>
    /// <param name="useSSL">When true, validates TLS certificates; when false, skips TLS verification.</param>
    public KubeCertificateManagerClient(string kubeconfig, bool useSSL = true)
    {
        _logger = LogHandler.GetClassLogger(MethodBase.GetCurrentMethod()?.DeclaringType);
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("Kubeconfig: {Kubeconfig}", LoggingUtilities.RedactKubeconfig(kubeconfig));
        _logger.LogTrace("UseSSL: {UseSSL}", useSSL);

        Client = GetKubeClient(kubeconfig);
        ConfigJson = kubeconfig;
        try
        {
            ConfigObj = ParseKubeConfig(kubeconfig, !useSSL); // invert useSSL to skip TLS verification
            _logger.LogDebug("Successfully parsed kubeconfig for cluster: {ClusterName}", ConfigObj.CurrentContext ?? "unknown");
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to parse kubeconfig, using empty configuration: {Message}", ex.Message);
            ConfigObj = new K8SConfiguration();
        }
        _logger.MethodExit(LogLevel.Debug);
    }

    /// <summary>
    /// Gets or sets the raw JSON kubeconfig string.
    /// </summary>
    private string ConfigJson { get; set; }

    /// <summary>
    /// Gets the parsed Kubernetes configuration object.
    /// </summary>
    private K8SConfiguration ConfigObj { get; }

    /// <summary>
    /// Gets or sets the Kubernetes API client instance.
    /// </summary>
    private IKubernetes Client { get; set; }

    /// <summary>
    /// Gets the name of the Kubernetes cluster from the configuration.
    /// Falls back to the host URL if the cluster name cannot be determined.
    /// </summary>
    /// <returns>The cluster name or host URL.</returns>
    public string GetClusterName()
    {
        _logger.MethodEntry(LogLevel.Debug);
        try
        {
            if (ConfigObj == null)
            {
                _logger.LogWarning("ConfigObj is null, falling back to GetHost()");
                var host = GetHost();
                _logger.MethodExit(LogLevel.Debug);
                return host;
            }
            if (ConfigObj.Clusters == null)
            {
                _logger.LogWarning("ConfigObj.Clusters is null, falling back to GetHost()");
                var host = GetHost();
                _logger.MethodExit(LogLevel.Debug);
                return host;
            }
            var clusterName = ConfigObj.Clusters.FirstOrDefault()?.Name;
            _logger.LogDebug("Returning cluster name: {ClusterName}", clusterName);
            _logger.MethodExit(LogLevel.Debug);
            return clusterName;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting cluster name from ConfigObj, attempting to return client base uri");
            var host = GetHost();
            _logger.MethodExit(LogLevel.Debug);
            return host;
        }
    }

    /// <summary>
    /// Gets the base URL of the Kubernetes API server.
    /// </summary>
    /// <returns>The API server base URL as a string.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the client or its BaseUri is null.</exception>
    public string GetHost()
    {
        _logger.MethodEntry(LogLevel.Debug);
        if (Client == null)
        {
            _logger.LogError("Client is null in GetHost()");
            throw new InvalidOperationException("Kubernetes client is not initialized. Check kubeconfig configuration.");
        }
        if (Client.BaseUri == null)
        {
            _logger.LogError("Client.BaseUri is null in GetHost()");
            throw new InvalidOperationException("Kubernetes client BaseUri is null. Check kubeconfig configuration.");
        }
        var host = Client.BaseUri.ToString();
        _logger.LogDebug("Returning host: {Host}", host);
        _logger.MethodExit(LogLevel.Debug);
        return host;
    }

    /// <summary>
    /// Parses a kubeconfig JSON string into a K8SConfiguration object.
    /// Extracts cluster, user, and context information for API authentication.
    /// </summary>
    /// <param name="kubeconfig">JSON-formatted kubeconfig string.</param>
    /// <param name="skipTLSVerify">When true, skips TLS certificate verification.</param>
    /// <returns>Parsed K8SConfiguration object.</returns>
    private K8SConfiguration ParseKubeConfig(string kubeconfig, bool skipTLSVerify = false)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("Kubeconfig length: {Length}, skipTLSVerify: {SkipTLS}", kubeconfig?.Length ?? 0, skipTLSVerify);
        _logger.LogTrace("Kubeconfig: {Kubeconfig}", LoggingUtilities.RedactKubeconfig(kubeconfig));

        try
        {
            var k8SConfiguration = new K8SConfiguration();
            _logger.LogTrace("K8SConfiguration object created");

            _logger.LogTrace("Checking if kubeconfig is null or empty");
            if (string.IsNullOrEmpty(kubeconfig))
            {
                _logger.LogError("kubeconfig is null or empty");
                throw new KubeConfigException(
                    "kubeconfig is null or empty, please provide a valid kubeconfig in JSON format. For more information on how to create a kubeconfig file, please visit https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json");
            }

            try
            {
                // test if kubeconfig is base64 encoded
                _logger.LogDebug("Testing if kubeconfig is base64 encoded");
                var decodedKubeconfig = Encoding.UTF8.GetString(Convert.FromBase64String(kubeconfig));
                kubeconfig = decodedKubeconfig;
                _logger.LogDebug("Successfully decoded kubeconfig from base64");
            }
            catch
            {
                _logger.LogTrace("Kubeconfig is not base64 encoded");
            }

            _logger.LogTrace("Checking if kubeconfig is escaped JSON");
            if (kubeconfig.StartsWith("\\"))
            {
                _logger.LogDebug("Un-escaping kubeconfig JSON");
                kubeconfig = kubeconfig.Replace("\\", "");
                kubeconfig = kubeconfig.Replace("\\n", "\n");
                _logger.LogDebug("Successfully un-escaped kubeconfig JSON");
            }

            // parse kubeconfig as a dictionary of string, string
            if (!kubeconfig.StartsWith("{"))
            {
                _logger.LogError("kubeconfig is not a JSON object");
                throw new KubeConfigException(
                    "kubeconfig is not a JSON object, please provide a valid kubeconfig in JSON format. For more information on how to create a kubeconfig file, please visit: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#get_service_account_credssh");
                // return k8SConfiguration;
            }


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
                _logger.LogTrace("Creating Cluster object for cluster '{Name}'", clusterMetadata["name"]?.ToString());
                // get environment variable for skip tls verify and convert to bool
                var skipTlsEnvStr = Environment.GetEnvironmentVariable("KEYFACTOR_ORCHESTRATOR_SKIP_TLS_VERIFY");
                _logger.LogTrace("KEYFACTOR_ORCHESTRATOR_SKIP_TLS_VERIFY environment variable: {SkipTlsVerify}",
                    skipTlsEnvStr);
                if (!string.IsNullOrEmpty(skipTlsEnvStr) &&
                    (bool.TryParse(skipTlsEnvStr, out var skipTlsVerifyEnv) || skipTlsEnvStr == "1"))
                {
                    if (skipTlsEnvStr == "1") skipTlsVerifyEnv = true;
                    _logger.LogDebug("Setting skip-tls-verify to {SkipTlsVerify}", skipTlsVerifyEnv);
                    if (skipTlsVerifyEnv && !skipTLSVerify)
                    {
                        _logger.LogWarning(
                            "Skipping TLS verification is enabled in environment variable KEYFACTOR_ORCHESTRATOR_SKIP_TLS_VERIFY this takes the highest precedence and verification will be skipped. To disable this, set the environment variable to 'false' or remove it");
                        skipTLSVerify = true;
                    }
                }

                var clusterObj = new Cluster
                {
                    Name = clusterMetadata["name"]?.ToString(),
                    ClusterEndpoint = new ClusterEndpoint
                    {
                        Server = clusterMetadata["cluster"]?["server"]?.ToString(),
                        CertificateAuthorityData = clusterMetadata["cluster"]?["certificate-authority-data"]?.ToString(),
                        SkipTlsVerify = skipTLSVerify
                    }
                };
                _logger.LogDebug("Cluster metadata - Name: {Name}, Server: {Server}, SkipTlsVerify: {SkipTls}",
                    clusterObj.Name, clusterObj.ClusterEndpoint?.Server, skipTLSVerify);
                _logger.LogTrace("Certificate authority data: {CaDataPresence}",
                    LoggingUtilities.GetFieldPresence("certificate-authority-data", clusterObj.ClusterEndpoint?.CertificateAuthorityData));
                k8SConfiguration.Clusters = new List<Cluster> { clusterObj };
            }

            _logger.LogTrace("Finished parsing clusters");

            _logger.LogDebug("Parsing users");
            _logger.LogTrace("Entering foreach loop to parse users...");
            // parse users
            foreach (var user in JsonConvert.DeserializeObject<JArray>(configDict["users"].ToString() ?? string.Empty))
            {
                var token = user["user"]?["token"]?.ToString();
                var userObj = new User
                {
                    Name = user["name"]?.ToString(),
                    UserCredentials = new UserCredentials
                    {
                        UserName = user["name"]?.ToString(),
                        Token = token
                    }
                };
                _logger.LogDebug("User metadata - Name: {Name}, HasToken: {HasToken}",
                    userObj.Name, !string.IsNullOrEmpty(token));
                _logger.LogTrace("Token: {Token}", LoggingUtilities.RedactToken(token));
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
                _logger.LogDebug("Context metadata - Name: {Name}, Cluster: {Cluster}, Namespace: {Namespace}, User: {User}",
                    contextObj.Name, contextObj.ContextDetails?.Cluster, contextObj.ContextDetails?.Namespace, contextObj.ContextDetails?.User);
                k8SConfiguration.Contexts = new List<Context> { contextObj };
            }

            _logger.LogTrace("Finished parsing contexts");
            _logger.LogDebug("Finished parsing kubeconfig");

            _logger.MethodExit(LogLevel.Debug);
            return k8SConfiguration;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "CRITICAL ERROR in ParseKubeConfig: {Message}", ex.Message);
            _logger.LogError("Exception Type: {Type}", ex.GetType().FullName);
            _logger.LogError("Stack Trace: {StackTrace}", ex.StackTrace);
            throw;
        }
    }

    /// <summary>
    /// Creates and configures a Kubernetes API client from the provided kubeconfig.
    /// Implements retry logic for transient connection failures.
    /// </summary>
    /// <param name="kubeconfig">JSON-formatted kubeconfig string.</param>
    /// <returns>Configured IKubernetes client instance.</returns>
    private IKubernetes GetKubeClient(string kubeconfig)
    {
        _logger.MethodEntry(LogLevel.Debug);
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
            try
            {
                _logger.LogDebug(
                    "Config defined in store parameters takes highest precedence - calling BuildConfigFromConfigObject()");
                config = KubernetesClientConfiguration.BuildConfigFromConfigObject(k8SConfiguration);
                _logger.LogDebug("Finished calling BuildConfigFromConfigObject()");
            }
            catch (Exception e)
            {
                _logger.LogError("Error building config from config object: {Error}", e.Message);
                config = KubernetesClientConfiguration.BuildDefaultConfig();
            }
        }
        else if
            (string.IsNullOrEmpty(
                 credentialFileName)) // If no config defined in store parameters, use default config. This should never happen though.
        {
            _logger.LogWarning(
                "No config defined in store parameters, using default config. This should never happen!");
            config = KubernetesClientConfiguration.BuildDefaultConfig();
            _logger.LogDebug("Finished calling BuildDefaultConfig()");
        }
        else
        {
            _logger.LogDebug("Calling BuildConfigFromConfigFile()");
            config = KubernetesClientConfiguration.BuildConfigFromConfigFile(
                strWorkPath != null && !credentialFileName.Contains(strWorkPath)
                    ? Path.Join(strWorkPath, credentialFileName)
                    : // Else attempt to load config from file
                    credentialFileName); // Else attempt to load config from file
            _logger.LogDebug("Finished calling BuildConfigFromConfigFile()");
        }

        _logger.LogDebug("Creating Kubernetes client");
        try
        {
            IKubernetes client = new Kubernetes(config);
            _logger.LogDebug("Finished creating Kubernetes client");

            _logger.LogTrace("Setting Client property");
            Client = client;
            _logger.MethodExit(LogLevel.Debug);
            return client;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create Kubernetes client: {Message}", ex.Message);
            _logger.LogError("Config Host: {Host}", config?.Host ?? "null");
            throw new InvalidOperationException($"Failed to create Kubernetes client. Check kubeconfig configuration. Error: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Finds an alias in a PKCS12 store by matching the certificate's Common Name.
    /// </summary>
    /// <param name="store">The PKCS12 store to search.</param>
    /// <param name="cn">The Common Name to match (case-insensitive, partial match).</param>
    /// <returns>The matching alias, or null if not found.</returns>
    private string FindAliasByCN(Pkcs12Store store, string cn)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("Searching for CN: {CN}", cn);
        if (store == null || string.IsNullOrEmpty(cn))
        {
            _logger.LogDebug("Store or CN is null/empty, returning null");
            _logger.MethodExit(LogLevel.Debug);
            return null;
        }

        foreach (var alias in store.Aliases)
        {
            if (!store.IsKeyEntry(alias))
                continue;

            var certEntry = store.GetCertificate(alias);
            if (certEntry?.Certificate == null)
                continue;

            var subjectCN = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.GetSubjectCN(certEntry.Certificate);
            if (!string.IsNullOrEmpty(subjectCN) && subjectCN.Contains(cn, StringComparison.OrdinalIgnoreCase))
                return alias;
        }

        return null;
    }

    /// <summary>
    /// Find an alias in a PKCS12 store by thumbprint
    /// </summary>
    private string FindAliasByThumbprint(Pkcs12Store store, string thumbprint)
    {
        if (store == null || string.IsNullOrEmpty(thumbprint))
            return null;

        foreach (var alias in store.Aliases)
        {
            var certEntry = store.GetCertificate(alias);
            if (certEntry?.Certificate == null)
                continue;

            var certThumbprint = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.GetThumbprint(certEntry.Certificate);
            if (certThumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                return alias;
        }

        return null;
    }

    /// <summary>
    /// Find an alias in a PKCS12 store by alias name (partial match on subject DN)
    /// </summary>
    private string FindAliasByName(Pkcs12Store store, string aliasSearch)
    {
        if (store == null || string.IsNullOrEmpty(aliasSearch))
            return null;

        // First try exact match
        if (store.ContainsAlias(aliasSearch))
            return aliasSearch;

        // Then try partial match on subject DN
        foreach (var alias in store.Aliases)
        {
            var certEntry = store.GetCertificate(alias);
            if (certEntry?.Certificate == null)
                continue;

            var subjectDN = certEntry.Certificate.SubjectDN.ToString();
            if (!string.IsNullOrEmpty(subjectDN) && subjectDN.Contains(aliasSearch, StringComparison.OrdinalIgnoreCase))
                return alias;
        }

        return null;
    }

    /// <summary>
    /// Removes a certificate from a PKCS12 secret store in Kubernetes.
    /// Loads the existing store, removes the matching certificate entry, and updates the secret.
    /// </summary>
    /// <param name="jobCertificate">The certificate to remove, containing thumbprint or alias for matching.</param>
    /// <param name="secretName">Name of the Kubernetes secret containing the PKCS12 store.</param>
    /// <param name="namespaceName">Kubernetes namespace where the secret resides.</param>
    /// <param name="secretType">Type of secret (e.g., "pkcs12", "pfx").</param>
    /// <param name="certDataFieldName">Field name within the secret containing the PKCS12 data.</param>
    /// <param name="storePasswd">Password for the PKCS12 store.</param>
    /// <param name="k8SSecretData">Existing secret data object.</param>
    /// <param name="append">When true, appends to existing entries.</param>
    /// <param name="overwrite">When true, overwrites existing entries.</param>
    /// <param name="passwdIsK8SSecret">When true, password is stored in a separate Kubernetes secret.</param>
    /// <param name="passwordSecretPath">Path to the password secret if passwdIsK8SSecret is true.</param>
    /// <param name="passwordFieldName">Field name containing the password in the password secret.</param>
    /// <param name="certdataFieldNames">Array of allowed field names to process.</param>
    /// <returns>The updated V1Secret object.</returns>
    public V1Secret RemoveFromPKCS12SecretStore(K8SJobCertificate jobCertificate, string secretName,
        string namespaceName, string secretType, string certDataFieldName,
        string storePasswd, V1Secret k8SSecretData,
        bool append = false, bool overwrite = true, bool passwdIsK8SSecret = false, string passwordSecretPath = "",
        string passwordFieldName = "password",
        string[] certdataFieldNames = null)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("Parameters - SecretName: {SecretName}, Namespace: {Namespace}, SecretType: {SecretType}",
            secretName, namespaceName, secretType);
        _logger.LogTrace("Password: {Password}", LoggingUtilities.RedactPassword(storePasswd));
        _logger.LogTrace("Calling GetSecret()");
        var existingPkcs12DataObj = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);


        // Load existing PKCS12 store
        var storeBuilder = new Pkcs12StoreBuilder();
        Pkcs12Store existingStore = null;
        var storePasswordBytes = Encoding.UTF8.GetBytes("");

        if (existingPkcs12DataObj?.Data == null)
        {
            _logger.LogTrace("existingPkcs12DataObj.Data is null");
        }
        else
        {
            _logger.LogTrace("existingPkcs12DataObj.Data is not null");

            foreach (var fieldName in existingPkcs12DataObj?.Data.Keys)
            {
                //check if key is in certdataFieldNames
                //if fieldname contains a . then split it and use the last part
                var searchFieldName = fieldName;
                certDataFieldName = fieldName;
                if (fieldName.Contains("."))
                {
                    var splitFieldName = fieldName.Split(".");
                    searchFieldName = splitFieldName[splitFieldName.Length - 1];
                }

                if (certdataFieldNames != null && !certdataFieldNames.Contains(searchFieldName)) continue;

                _logger.LogTrace($"Loading PKCS12 store from field '{fieldName}'");
                if (jobCertificate.PasswordIsK8SSecret)
                {
                    if (!string.IsNullOrEmpty(jobCertificate.StorePasswordPath))
                    {
                        _logger.LogDebug("Password is stored in K8S secret at path: {Path}", jobCertificate.StorePasswordPath);
                        var passwordPath = jobCertificate.StorePasswordPath.Split("/");
                        var passwordNamespace = passwordPath[0];
                        var passwordSecretName = passwordPath[1];
                        _logger.LogDebug("Buddy secret metadata - Name: {Name}, Namespace: {Namespace}, Field: {Field}",
                            passwordSecretName, passwordNamespace, passwordFieldName);

                        // Get password from k8s secret
                        var k8sPasswordObj = ReadBuddyPass(passwordSecretName, passwordNamespace);
                        _logger.LogTrace("Buddy secret: {Summary}", LoggingUtilities.GetSecretSummary(k8sPasswordObj));

                        storePasswordBytes = k8sPasswordObj.Data[passwordFieldName];
                        var storePasswdString = Encoding.UTF8.GetString(storePasswordBytes).TrimEnd('\r', '\n');
                        _logger.LogTrace("Password from buddy secret: {Password}", LoggingUtilities.RedactPassword(storePasswdString));
                        _logger.LogTrace("Password correlation: {CorrelationId}", LoggingUtilities.GetPasswordCorrelationId(storePasswdString));

                        existingStore = storeBuilder.Build();
                        using var ms = new MemoryStream(existingPkcs12DataObj.Data[fieldName]);
                        existingStore.Load(ms, storePasswdString.ToCharArray());
                    }
                    else
                    {
                        _logger.LogDebug("Password is stored in same secret, field: {Field}", passwordFieldName);
                        storePasswordBytes = existingPkcs12DataObj.Data[passwordFieldName];
                        var storePasswdString = Encoding.UTF8.GetString(storePasswordBytes).TrimEnd('\r', '\n');
                        _logger.LogTrace("Password from secret field: {Password}", LoggingUtilities.RedactPassword(storePasswdString));
                        _logger.LogTrace("Password correlation: {CorrelationId}", LoggingUtilities.GetPasswordCorrelationId(storePasswdString));

                        existingStore = storeBuilder.Build();
                        using var ms = new MemoryStream(existingPkcs12DataObj.Data[fieldName]);
                        existingStore.Load(ms, storePasswdString.ToCharArray());
                    }
                }
                else if (!string.IsNullOrEmpty(jobCertificate.StorePassword))
                {
                    _logger.LogDebug("Using password from job configuration");
                    storePasswordBytes = Encoding.UTF8.GetBytes(jobCertificate.StorePassword);
                    var storePasswdString = Encoding.UTF8.GetString(storePasswordBytes);
                    _logger.LogTrace("Password: {Password}", LoggingUtilities.RedactPassword(storePasswdString));
                    _logger.LogTrace("Password correlation: {CorrelationId}", LoggingUtilities.GetPasswordCorrelationId(storePasswdString));

                    existingStore = storeBuilder.Build();
                    using var ms = new MemoryStream(existingPkcs12DataObj.Data[fieldName]);
                    existingStore.Load(ms, storePasswdString.ToCharArray());
                }
                else
                {
                    _logger.LogDebug("Using default store password");
                    storePasswordBytes = Encoding.UTF8.GetBytes(storePasswd);
                    var storePasswdString = Encoding.UTF8.GetString(storePasswordBytes);
                    _logger.LogTrace("Password: {Password}", LoggingUtilities.RedactPassword(storePasswdString));
                    _logger.LogTrace("Password correlation: {CorrelationId}", LoggingUtilities.GetPasswordCorrelationId(storePasswdString));

                    existingStore = storeBuilder.Build();
                    using var ms = new MemoryStream(existingPkcs12DataObj.Data[fieldName]);
                    existingStore.Load(ms, storePasswdString.ToCharArray());
                }
            }

            if (existingStore != null && existingStore.Count > 0)
            {
                // Check if overwrite is true, if so, remove the certificate
                if (overwrite)
                {
                    _logger.LogTrace("Overwrite is true, removing existing cert");

                    var foundAlias = FindAliasByName(existingStore, jobCertificate.Alias);
                    if (foundAlias != null)
                    {
                        // Certificate found
                        // remove the found certificate
                        _logger.LogTrace($"Certificate found with alias '{foundAlias}', removing it");
                        existingStore.DeleteEntry(foundAlias);
                    }
                }
            }
        }


        _logger.LogTrace("Creating V1Secret object");

        byte[] p12bytes;
        if (existingStore != null)
        {
            using var outStream = new MemoryStream();
            existingStore.Save(outStream, Encoding.UTF8.GetString(storePasswordBytes).ToCharArray(), new SecureRandom());
            p12bytes = outStream.ToArray();
        }
        else
        {
            p12bytes = Array.Empty<byte>();
        }

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
                { certDataFieldName, p12bytes }
            }
        };
        switch (string.IsNullOrEmpty(storePasswd))
        {
            case false
                when string.IsNullOrEmpty(passwordSecretPath) && passwdIsK8SSecret
                : // password is not empty and passwordSecretPath is empty
                {
                    _logger.LogDebug("Adding password to secret...");
                    if (string.IsNullOrEmpty(passwordFieldName)) passwordFieldName = "password";
                    secret.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(storePasswd));
                    break;
                }
            case false
                when !string.IsNullOrEmpty(passwordSecretPath) && passwdIsK8SSecret
                : // password is not empty and passwordSecretPath is not empty
                {
                    _logger.LogDebug("Adding password secret path to secret...");
                    if (string.IsNullOrEmpty(passwordFieldName)) passwordFieldName = "passwordSecretPath";
                    secret.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordSecretPath));

                    // Lookup password secret path on cluster to see if it exists
                    _logger.LogDebug("Attempting to lookup password secret path on cluster...");
                    var splitPasswordPath = passwordSecretPath.Split("/");
                    // Assume secret pattern is namespace/secretName
                    var passwordSecretName = splitPasswordPath[^1];
                    var passwordSecretNamespace = splitPasswordPath[0];
                    _logger.LogDebug(
                        $"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    try
                    {
                        var passwordSecret =
                            Client.CoreV1.ReadNamespacedSecret(passwordSecretName, passwordSecretNamespace);
                        // storePasswd = Encoding.UTF8.GetString(passwordSecret.Data[passwordFieldName]);
                        _logger.LogDebug(
                            $"Successfully found secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                        // Update secret
                        _logger.LogDebug(
                            $"Attempting to update secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                        passwordSecret.Data[passwordFieldName] = Encoding.UTF8.GetBytes(storePasswd);
                        var updatedPasswordSecret = Client.CoreV1.ReplaceNamespacedSecret(passwordSecret,
                            passwordSecretName, passwordSecretNamespace);
                        _logger.LogDebug(
                            $"Successfully updated secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    }
                    catch (HttpOperationException e)
                    {
                        _logger.LogError(
                            $"Unable to find secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                        _logger.LogError(e.Message);
                        // Attempt to create a new secret
                        _logger.LogDebug(
                            $"Attempting to create secret {passwordSecretName} in namespace {passwordSecretNamespace}");
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
                        var createdPasswordSecret =
                            Client.CoreV1.CreateNamespacedSecret(passwordSecretData, passwordSecretNamespace);
                        _logger.LogDebug("Successfully created secret " + passwordSecretPath);
                    }

                    break;
                }
        }

        // Update secret on K8S
        _logger.LogTrace("Calling UpdateSecret()");
        var updatedSecret = Client.CoreV1.ReplaceNamespacedSecret(secret, secretName, namespaceName);

        _logger.LogTrace("Finished creating V1Secret object");

        _logger.MethodExit(LogLevel.Debug);
        return updatedSecret;
    }

    /// <summary>
    /// Updates a PKCS12 secret store in Kubernetes by adding or modifying certificate entries.
    /// Supports password storage in a separate "buddy" secret for security.
    /// </summary>
    /// <param name="jobCertificate">The certificate to add/update in the store.</param>
    /// <param name="secretName">Name of the Kubernetes secret containing the PKCS12 store.</param>
    /// <param name="namespaceName">Kubernetes namespace where the secret resides.</param>
    /// <param name="secretType">Type of secret (e.g., "pkcs12", "pfx").</param>
    /// <param name="certdataFieldName">Field name within the secret containing the PKCS12 data.</param>
    /// <param name="storePasswd">Password for the PKCS12 store.</param>
    /// <param name="k8SSecretData">Existing secret data object.</param>
    /// <param name="append">When true, appends to existing entries.</param>
    /// <param name="overwrite">When true, overwrites existing entries with same alias.</param>
    /// <param name="passwdIsK8sSecret">When true, password is stored in a separate Kubernetes secret.</param>
    /// <param name="passwordSecretPath">Path to the password secret if passwdIsK8sSecret is true.</param>
    /// <param name="passwordFieldName">Field name containing the password in the password secret.</param>
    /// <param name="certdataFieldNames">Array of allowed field names to process.</param>
    /// <param name="remove">When true, removes the certificate instead of adding.</param>
    /// <returns>The updated V1Secret object.</returns>
    public V1Secret UpdatePKCS12SecretStore(K8SJobCertificate jobCertificate, string secretName, string namespaceName,
        string secretType, string certdataFieldName,
        string storePasswd, V1Secret k8SSecretData,
        bool append = false, bool overwrite = true, bool passwdIsK8sSecret = false, string passwordSecretPath = "",
        string passwordFieldName = "password",
        string[] certdataFieldNames = null, bool remove = false)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("Parameters - SecretName: {SecretName}, Namespace: {Namespace}, Overwrite: {Overwrite}, Append: {Append}",
            secretName, namespaceName, overwrite, append);
        _logger.LogTrace("Calling GetSecret()");
        var existingPkcs12DataObj = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
        // var existingPkcs12Bytes = existingPkcs12DataObj.Data[certdataFieldName];
        // var existingPkcs12 = new X509Certificate2Collection();
        // existingPkcs12.Import(existingPkcs12Bytes, storePasswd, X509KeyStorageFlags.Exportable);

        // Load existing PKCS12 store
        var storeBuilder = new Pkcs12StoreBuilder();
        Pkcs12Store existingStore = null;
        var storePasswordBytes = Encoding.UTF8.GetBytes("");

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
                _logger.LogTrace("Adding cert '{FieldName}' to existingPkcs12", fieldName);
                if (jobCertificate.PasswordIsK8SSecret)
                {
                    _logger.LogDebug("Job certificate password is a K8S secret");
                    if (!string.IsNullOrEmpty(jobCertificate.StorePasswordPath))
                    {
                        _logger.LogDebug("Job certificate store password path is {StorePasswordPath}",
                            jobCertificate.StorePasswordPath);

                        _logger.LogDebug("Splitting store password path into namespace and secret name");
                        var passwordPath = jobCertificate.StorePasswordPath.Split("/");

                        string passwordNamespace;
                        string passwordSecretName;

                        if (passwordPath.Length == 1)
                        {
                            _logger.LogDebug("Password path length is 1, using KubeNamespace");
                            passwordNamespace = namespaceName;
                            _logger.LogTrace("Password namespace: {Namespace}", passwordNamespace);
                            passwordSecretName = passwordPath[0];
                        }
                        else
                        {
                            _logger.LogDebug(
                                "Password path length is not 1, using passwordPath[0] and passwordPath[^1]");
                            passwordNamespace = passwordPath[0];
                            _logger.LogTrace("Password namespace: {Namespace}", passwordNamespace);
                            passwordSecretName = passwordPath[^1];
                        }

                        _logger.LogDebug("Password namespace: {PasswordNamespace}", passwordNamespace);
                        _logger.LogDebug("Password secret name: {PasswordSecretName}", passwordSecretName);

                        var k8sPasswordObj = ReadBuddyPass(passwordSecretName, passwordNamespace);
                        _logger.LogDebug(
                            "Successfully read password secret {PasswordSecretName} in namespace {PasswordNamespace}",
                            passwordSecretName, passwordNamespace);

                        if (k8sPasswordObj?.Data == null)
                        {
                            _logger.LogError("Unable to read K8S buddy secret {SecretName} in namespace {Namespace}",
                                passwordSecretName, passwordNamespace);
                            throw new InvalidK8SSecretException(
                                $"Unable to read K8S buddy secret {passwordSecretName} in namespace {passwordNamespace}");
                        }

                        _logger.LogTrace("Secret response fields: {Keys}", k8sPasswordObj.Data.Keys);

                        if (!k8sPasswordObj.Data.TryGetValue(passwordFieldName, out storePasswordBytes) ||
                            storePasswordBytes == null)
                        {
                            _logger.LogError("Unable to find password field {FieldName}", passwordFieldName);
                            throw new InvalidK8SSecretException(
                                $"Unable to find password field '{passwordFieldName}' in secret '{passwordSecretName}' in namespace '{passwordNamespace}'"
                            );
                        }

                        // storePasswordBytes = k8sPasswordObj.Data[passwordFieldName];
                        if (storePasswordBytes == null || storePasswordBytes.Length == 0)
                        {
                            _logger.LogError(
                                "Password field {FieldName} in secret {SecretName} in namespace {Namespace} is empty",
                                passwordFieldName, passwordSecretName, passwordNamespace);
                            throw new InvalidK8SSecretException(
                                $"Password field '{passwordFieldName}' in secret '{passwordSecretName}' in namespace '{passwordNamespace}' is empty"
                            );
                        }

                        var storePasswdString = Encoding.UTF8.GetString(storePasswordBytes);
                        // _logger.LogTrace("Loading existing PKCS12 store with password");

                        existingStore = storeBuilder.Build();
                        using var ms = new MemoryStream(existingPkcs12DataObj.Data[fieldName]);
                        existingStore.Load(ms, storePasswdString.ToCharArray());
                    }
                    else
                    {
                        _logger.LogDebug("Job certificate store password path is empty, using existing secret data");
                        storePasswordBytes = existingPkcs12DataObj.Data[passwordFieldName];
                        if (storePasswordBytes == null || storePasswordBytes.Length == 0)
                        {
                            _logger.LogError(
                                "Password field {FieldName} in secret {SecretName} in namespace {Namespace} is empty",
                                passwordFieldName, secretName, namespaceName);
                            throw new InvalidK8SSecretException(
                                $"Password field '{passwordFieldName}' in secret '{secretName}' in namespace '{namespaceName}' is empty"
                            );
                        }

                        // _logger.LogTrace("Loading existing PKCS12 store with password");
                        existingStore = storeBuilder.Build();
                        using var ms = new MemoryStream(existingPkcs12DataObj.Data[fieldName]);
                        existingStore.Load(ms, Encoding.UTF8.GetString(storePasswordBytes).ToCharArray());
                    }
                }
                else if (!string.IsNullOrEmpty(jobCertificate.StorePassword))
                {
                    _logger.LogDebug(
                        "Job certificate store password is not empty, using job certificate store password");
                    storePasswordBytes = Encoding.UTF8.GetBytes(jobCertificate.StorePassword);
                    // _logger.LogTrace("Loading existing PKCS12 store with password");

                    existingStore = storeBuilder.Build();
                    using var ms = new MemoryStream(existingPkcs12DataObj.Data[fieldName]);
                    existingStore.Load(ms, Encoding.UTF8.GetString(storePasswordBytes).ToCharArray());
                }
                else
                {
                    _logger.LogDebug("Job certificate store password is empty, using provided store password");
                    storePasswordBytes = Encoding.UTF8.GetBytes(storePasswd);
                    // _logger.LogTrace("Loading existing PKCS12 store with password");

                    existingStore = storeBuilder.Build();
                    using var ms = new MemoryStream(existingPkcs12DataObj.Data[fieldName]);
                    existingStore.Load(ms, Encoding.UTF8.GetString(storePasswordBytes).ToCharArray());
                }
            }

            if (existingStore != null && existingStore.Count > 0)
            {
                // Process existing store
                if (remove)
                {
                    var foundAlias = FindAliasByName(existingStore, jobCertificate.Alias);
                    if (foundAlias != null)
                    {
                        // Certificate found - remove it
                        _logger.LogTrace($"Certificate found with alias '{foundAlias}', removing it");
                        existingStore.DeleteEntry(foundAlias);
                    }
                }
                else
                {
                    // Load new certificate to get its CN
                    var newCertStore = storeBuilder.Build();
                    using var newCertMs = new MemoryStream(jobCertificate.Pkcs12 ?? jobCertificate.CertBytes);
                    newCertStore.Load(newCertMs, storePasswd.ToCharArray());

                    var newCertAlias = newCertStore.Aliases.FirstOrDefault(newCertStore.IsKeyEntry);
                    if (newCertAlias != null)
                    {
                        var newCertEntry = newCertStore.GetCertificate(newCertAlias);
                        var newCertCn = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.GetSubjectCN(newCertEntry.Certificate);

                        // Check if overwrite is true, if so, replace existing cert with new cert
                        if (overwrite)
                        {
                            _logger.LogTrace("Overwrite is true, replacing existing cert with new cert");

                            var foundAlias = FindAliasByCN(existingStore, newCertCn);
                            if (foundAlias != null)
                            {
                                // Certificate found - replace it
                                _logger.LogTrace($"Certificate found with alias '{foundAlias}', replacing it");
                                existingStore.DeleteEntry(foundAlias);
                            }

                            // Add new certificate with its alias or jobCertificate.Alias
                            var targetAlias = string.IsNullOrEmpty(jobCertificate.Alias) ? newCertAlias : jobCertificate.Alias;
                            var newKey = newCertStore.GetKey(newCertAlias);
                            var newChain = newCertStore.GetCertificateChain(newCertAlias);
                            existingStore.SetKeyEntry(targetAlias, newKey, newChain);
                        }
                        else
                        {
                            // Check if certificate doesn't exist, then add
                            var foundAlias = FindAliasByCN(existingStore, newCertCn);
                            if (foundAlias == null)
                            {
                                _logger.LogDebug("Certificate not found, adding the new certificate to the store");
                                var targetAlias = string.IsNullOrEmpty(jobCertificate.Alias) ? newCertAlias : jobCertificate.Alias;
                                var newKey = newCertStore.GetKey(newCertAlias);
                                var newChain = newCertStore.GetCertificateChain(newCertAlias);
                                existingStore.SetKeyEntry(targetAlias, newKey, newChain);
                            }
                        }
                    }
                }
            }
            else
            {
                // No existing store - create new one from jobCertificate data
                _logger.LogDebug("No existing PKCS12 data found, creating new PKCS12 store");
                existingStore = storeBuilder.Build();
                using var newStoreMs = new MemoryStream(jobCertificate.Pkcs12 ?? jobCertificate.CertBytes);
                existingStore.Load(newStoreMs, storePasswd.ToCharArray());
            }
        }

        // Export PKCS12 store to bytes
        byte[] p12Bytes;
        if (existingStore != null)
        {
            using var outStream = new MemoryStream();
            existingStore.Save(outStream, Encoding.UTF8.GetString(storePasswordBytes).ToCharArray(), new SecureRandom());
            p12Bytes = outStream.ToArray();
        }
        else
        {
            p12Bytes = Array.Empty<byte>();
        }

        _logger.LogDebug("Creating V1Secret object for PKCS12 data with name {SecretName} in namespace {NamespaceName}",
            secretName, namespaceName);
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
                { certdataFieldName, p12Bytes }
            }
        };

        if (existingPkcs12DataObj?.Data != null)
        {
            secret.Data = existingPkcs12DataObj.Data;
            secret.Data[certdataFieldName] = p12Bytes;
        }

        // Convert p12bytes to pkcs12store
        var pkcs12StoreBuilder = new Pkcs12StoreBuilder();
        var pkcs12Store = pkcs12StoreBuilder.Build();
        pkcs12Store.Load(new MemoryStream(p12Bytes), storePasswd.ToCharArray());


        switch (string.IsNullOrEmpty(storePasswd))
        {
            case false
                when string.IsNullOrEmpty(passwordSecretPath) && passwdIsK8sSecret
                : // password is not empty and passwordSecretPath is empty
                {
                    _logger.LogDebug("Adding password to secret...");
                    if (string.IsNullOrEmpty(passwordFieldName)) passwordFieldName = "password";
                    secret.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(storePasswd));
                    break;
                }
            case false
                when !string.IsNullOrEmpty(passwordSecretPath) && passwdIsK8sSecret
                : // password is not empty and passwordSecretPath is not empty
                {
                    _logger.LogDebug("Adding password secret path to secret...");
                    if (string.IsNullOrEmpty(passwordFieldName)) passwordFieldName = "passwordSecretPath";
                    secret.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordSecretPath));

                    // Lookup password secret path on cluster to see if it exists
                    _logger.LogDebug("Attempting to lookup password secret path on cluster...");
                    var splitPasswordPath = passwordSecretPath.Split("/");
                    // Assume secret pattern is namespace/secretName
                    var passwordSecretName = splitPasswordPath[^1];
                    var passwordSecretNamespace = splitPasswordPath[0];
                    _logger.LogDebug(
                        $"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    try
                    {
                        var passwordSecret =
                            Client.CoreV1.ReadNamespacedSecret(passwordSecretName, passwordSecretNamespace);
                        // storePasswd = Encoding.UTF8.GetString(passwordSecret.Data[passwordFieldName]);
                        _logger.LogDebug(
                            $"Successfully found secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                        // Update secret
                        _logger.LogDebug(
                            $"Attempting to update secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                        passwordSecret.Data[passwordFieldName] = Encoding.UTF8.GetBytes(storePasswd);
                        var updatedPasswordSecret = Client.CoreV1.ReplaceNamespacedSecret(passwordSecret,
                            passwordSecretName, passwordSecretNamespace);
                        _logger.LogDebug(
                            $"Successfully updated secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    }
                    catch (HttpOperationException e)
                    {
                        _logger.LogError(
                            $"Unable to find secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                        _logger.LogError(e.Message);
                        // Attempt to create a new secret
                        _logger.LogDebug(
                            $"Attempting to create secret {passwordSecretName} in namespace {passwordSecretNamespace}");
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
                        var createdPasswordSecret =
                            Client.CoreV1.CreateNamespacedSecret(passwordSecretData, passwordSecretNamespace);
                        _logger.LogDebug("Successfully created secret " + passwordSecretPath);
                    }

                    break;
                }
        }

        // Update secret on K8S
        _logger.LogTrace("Calling UpdateSecret()");
        var updatedSecret = Client.CoreV1.ReplaceNamespacedSecret(secret, secretName, namespaceName);

        _logger.LogTrace("Finished creating V1Secret object");

        _logger.MethodExit(LogLevel.Debug);
        return updatedSecret;
    }

    /// <summary>
    /// Creates or updates a certificate store secret in Kubernetes.
    /// Routes to appropriate handler based on secret type (PKCS12, PFX, JKS).
    /// </summary>
    /// <param name="jobCertificate">The certificate to store.</param>
    /// <param name="secretName">Name of the Kubernetes secret.</param>
    /// <param name="namespaceName">Kubernetes namespace.</param>
    /// <param name="secretType">Type of store (pkcs12, pfx, jks).</param>
    /// <param name="overwrite">When true, overwrites existing entries.</param>
    /// <param name="certDataFieldName">Field name for certificate data.</param>
    /// <param name="passwordFieldName">Field name for password.</param>
    /// <param name="passwordSecretPath">Path to password secret if stored separately.</param>
    /// <param name="passwordIsK8SSecret">When true, password is in a separate secret.</param>
    /// <param name="password">Store password.</param>
    /// <param name="allowedKeys">Allowed field names to process.</param>
    /// <param name="remove">When true, removes instead of adds.</param>
    /// <returns>The created or updated V1Secret.</returns>
    public V1Secret CreateOrUpdateCertificateStoreSecret(K8SJobCertificate jobCertificate, string secretName,
        string namespaceName, string secretType, bool overwrite = false, string certDataFieldName = "pkcs12",
        string passwordFieldName = "password",
        string passwordSecretPath = "", bool passwordIsK8SSecret = false, string password = "",
        string[] allowedKeys = null, bool remove = false)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("Parameters - SecretName: {SecretName}, Namespace: {Namespace}, SecretType: {SecretType}, Remove: {Remove}",
            secretName, namespaceName, secretType, remove);
        var storePasswd = string.IsNullOrEmpty(password) ? jobCertificate.Password : password;
        _logger.LogTrace("Password: {Password}", LoggingUtilities.RedactPassword(storePasswd));
        _logger.LogTrace("Calling CreateNewSecret()");
        V1Secret k8SSecretData;
        switch (secretType)
        {
            case "pkcs12":
            case "pfx":
            case "jks":
                if (remove)
                    k8SSecretData = new V1Secret();
                else
                    k8SSecretData = CreateOrUpdatePKCS12Secret(secretName,
                        namespaceName,
                        jobCertificate,
                        certDataFieldName,
                        storePasswd,
                        passwordFieldName,
                        passwordSecretPath,
                        allowedKeys);
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
                _logger.LogDebug(
                    $"Secret {secretName} already exists in namespace {namespaceName}, attempting to update secret...");
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
                        return UpdateSecretStore(secretName, namespaceName, secretType, "", "", k8SSecretData, false,
                            overwrite);
                }
            }
        }

        _logger.LogError("Unable to create secret for unknown reason.");
        return k8SSecretData;
    }

    public V1Secret CreateOrUpdateCertificateStoreSecret(string keyPem, string certPem, List<string> chainPem,
        string secretName,
        string namespaceName, string secretType, bool append = false, bool overwrite = false, bool remove = false, bool separateChain = true, bool includeChain = true)
    {
        _logger.LogTrace("Entered CreateOrUpdateCertificateStoreSecret()");

        _logger.LogDebug($"Attempting to create new secret {secretName} in namespace {namespaceName}");
        _logger.LogTrace("Calling CreateNewSecret()");
        var k8SSecretData = CreateNewSecret(secretName, namespaceName, keyPem, certPem, chainPem, secretType, separateChain, includeChain);
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
                _logger.LogDebug(
                    $"Secret {secretName} already exists in namespace {namespaceName}, attempting to update secret...");
                _logger.LogTrace("Calling UpdateSecretStore()");
                return UpdateSecretStore(secretName, namespaceName, secretType, certPem, keyPem, k8SSecretData, append,
                    overwrite);
            }
        }

        _logger.LogError("Unable to create secret for unknown reason.");
        return null;
    }


    public Pkcs12Store CreatePKCS12Collection(byte[] pkcs12bytes, string currentPassword, string newPassword)
    {
        try
        {
            var storeBuilder = new Pkcs12StoreBuilder();
            var certs = storeBuilder.Build();

            var newEntry = storeBuilder.Build();

            // Load the PKCS12 data directly with BouncyCastle
            using (var ms = new MemoryStream(pkcs12bytes))
            {
                newEntry.Load(ms, string.IsNullOrEmpty(currentPassword) ? new char[0] : currentPassword.ToCharArray());
            }

            var checkAliasExists = string.Empty;
            string alias = null;

            // Get the first certificate to use its thumbprint as alias
            foreach (var newEntryAlias in newEntry.Aliases)
            {
                var certEntry = newEntry.GetCertificate(newEntryAlias);
                if (certEntry?.Certificate != null && alias == null)
                {
                    // Use thumbprint as alias
                    alias = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.GetThumbprint(certEntry.Certificate);
                }

                if (!newEntry.IsKeyEntry(newEntryAlias))
                    continue;

                checkAliasExists = newEntryAlias;

                if (certs.ContainsAlias(alias)) certs.DeleteEntry(alias);
                certs.SetKeyEntry(alias, newEntry.GetKey(newEntryAlias), newEntry.GetCertificateChain(newEntryAlias));
            }

            if (string.IsNullOrEmpty(checkAliasExists))
            {
                // No private key found, add certificate only
                var firstAlias = newEntry.Aliases.FirstOrDefault();
                if (firstAlias != null)
                {
                    var certEntry = newEntry.GetCertificate(firstAlias);
                    if (certEntry != null)
                    {
                        if (certs.ContainsAlias(alias)) certs.DeleteEntry(alias);
                        certs.SetCertificateEntry(alias, certEntry);
                    }
                }
            }

            using (var outStream = new MemoryStream())
            {
                certs.Save(outStream, string.IsNullOrEmpty(newPassword) ? new char[0] : newPassword.ToCharArray(),
                    new SecureRandom());
            }

            return certs;
        }
        catch (Exception ex)
        {
            throw new Exception("Error attempting to add certficate for store path=StorePath, file name=StoreFileName.",
                ex);
        }
    }

    private V1Secret CreateOrUpdatePKCS12Secret(string secretName, string namespaceName, K8SJobCertificate certObj,
        string secretFieldName, string password,
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
            if (e.Message.Contains("Not Found")) _logger.LogDebug("No existing secret found.");
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
        using (var stream = new MemoryStream())
        {
            pkcs12Data.Save(stream, passwordToWrite.ToCharArray(), new SecureRandom());

            // Get the PKCS12 bytes
            p12Bytes = stream.ToArray();

            // Use the pkcs12Bytes as desired
        }

        if (string.IsNullOrEmpty(secretFieldName)) secretFieldName = "pkcs12";
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
                when certObj.PasswordIsK8SSecret && string.IsNullOrEmpty(certObj.StorePasswordPath)
                : // This means the password is expected to be on the secret so add it
                {
                    _logger.LogDebug("Adding password to secret...");
                    if (string.IsNullOrEmpty(passwordFieldName)) passwordFieldName = "password";

                    // var passwordToWrite = !string.IsNullOrEmpty(certObj.StorePassword) ? certObj.StorePassword : password;

                    k8SSecretData.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordToWrite));
                    break;
                }
            case false when !string.IsNullOrEmpty(passwordSecretPath):
                {
                    _logger.LogDebug("Adding password secret path to secret...");
                    if (string.IsNullOrEmpty(passwordFieldName)) passwordFieldName = "password";
                    // k8SSecretData.Data.Add(passwordFieldName, Encoding.UTF8.GetBytes(passwordSecretPath));

                    // Lookup password secret path on cluster to see if it exists
                    _logger.LogDebug("Attempting to lookup password secret path on cluster...");
                    var splitPasswordPath = passwordSecretPath.Split("/");
                    // Assume secret pattern is namespace/secretName
                    var passwordSecretName = splitPasswordPath[splitPasswordPath.Length - 1];
                    var passwordSecretNamespace = splitPasswordPath[0];
                    _logger.LogDebug(
                        $"Attempting to lookup secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                    try
                    {
                        var passwordSecret =
                            Client.CoreV1.ReadNamespacedSecret(passwordSecretName, passwordSecretNamespace);
                        password = Encoding.UTF8.GetString(passwordSecret.Data[passwordFieldName]);
                    }
                    catch (HttpOperationException e)
                    {
                        _logger.LogError(
                            $"Unable to find secret {passwordSecretName} in namespace {passwordSecretNamespace}");
                        _logger.LogError(e.Message);
                        // Attempt to create a new secret
                        _logger.LogDebug(
                            $"Attempting to create secret {passwordSecretName} in namespace {passwordSecretNamespace}");
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
                        var passwordSecretResponse =
                            Client.CoreV1.CreateNamespacedSecret(passwordSecretData, passwordSecretNamespace);
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
        _logger.MethodEntry();
        // Lookup password secret path on cluster to see if it exists
        _logger.LogDebug("Attempting to lookup password secret path on cluster...");
        var splitPasswordPath = passwordSecretPath.Split("/");
        _logger.LogDebug("Split password secret path: {SplitPasswordPath}", string.Join("/", splitPasswordPath));
        var passwordSecretName = splitPasswordPath[^1];
        var passwordSecretNamespace = splitPasswordPath[0];
        _logger.LogDebug("Attempting to lookup secret {PasswordSecretName} in namespace {PasswordSecretNamespace}",
            passwordSecretName, passwordSecretNamespace);
        var passwordSecretResponse = Client.CoreV1.ReadNamespacedSecret(secretName, passwordSecretNamespace);
        _logger.LogDebug("Successfully found secret {PasswordSecretName} in namespace {PasswordSecretNamespace}",
            passwordSecretName, passwordSecretNamespace);
        _logger.MethodExit();
        return passwordSecretResponse;
    }

    public V1Secret CreateOrUpdateBuddyPass(string secretName, string passwordFieldName, string passwordSecretPath,
        string password)
    {
        _logger.LogDebug("Adding password secret path to secret...");
        if (string.IsNullOrEmpty(passwordFieldName)) passwordFieldName = "password";
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
            var passwordSecretResponse =
                Client.CoreV1.CreateNamespacedSecret(passwordSecretData, passwordSecretNamespace);
            return passwordSecretResponse;
        }
        catch (HttpOperationException e)
        {
            _logger.LogError($"Unable to find secret {passwordSecretName} in namespace {passwordSecretNamespace}");
            _logger.LogError(e.Message);
            // Attempt to create a new secret
            _logger.LogDebug(
                $"Attempting to create secret {passwordSecretName} in namespace {passwordSecretNamespace}");

            _logger.LogDebug("Calling CreateNamespacedSecret()");
            var passwordSecretResponse =
                Client.CoreV1.ReplaceNamespacedSecret(passwordSecretData, secretName, passwordSecretNamespace);
            _logger.LogDebug("Finished calling CreateNamespacedSecret()");
            _logger.LogDebug("Successfully created secret " + passwordSecretPath);
            return passwordSecretResponse;
        }
    }

    private V1Secret CreateNewSecret(string secretName, string namespaceName, string keyPem, string certPem,
        List<string> chainPem, string secretType, bool separateChain = true, bool includeChain = true)
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

        if (chainPem is { Count: > 0 } && includeChain)
        {
            var caCert = chainPem.Where(cer => cer != certPem).Aggregate("", (current, cer) => current + cer);
            if (separateChain)
                k8SSecretData.Data.Add("ca.crt", Encoding.UTF8.GetBytes(caCert));
            else
                //update tls.crt w/ full chain
                k8SSecretData.Data["tls.crt"] = Encoding.UTF8.GetBytes(certPem + caCert);
        }

        _logger.LogTrace("Exiting CreateNewSecret()");
        return k8SSecretData;
    }

    private V1Secret UpdateOpaqueSecret(string secretName, string namespaceName, V1Secret existingSecret,
        V1Secret newSecret)
    {
        _logger.LogTrace("Entered UpdateOpaqueSecret()");

        existingSecret.Data["tls.key"] = newSecret.Data["tls.key"];
        existingSecret.Data["tls.crt"] = newSecret.Data["tls.crt"];

        //check if existing secret has ca.crt and if new secret has ca.crt
        if (existingSecret.Data.ContainsKey("ca.crt") && newSecret.Data.ContainsKey("ca.crt"))
        {
            _logger.LogDebug("Existing secret '{Namespace}/{Name}' has ca.crt adding chain to this field",
                namespaceName, secretName);
            _logger.LogTrace("existing ca.crt:\n {CaCrt}", existingSecret.Data["ca.crt"]);
            existingSecret.Data["ca.crt"] = newSecret.Data["ca.crt"];
            _logger.LogTrace("new ca.crt:\n {CaCrt}", newSecret.Data["ca.crt"]);
        }
        else
        {
            //Append to tls.crt
            _logger.LogDebug("Existing secret '{Namespace}/{Name}' does not have ca.crt, appending to tls.crt",
                namespaceName, secretName);
            if (newSecret.Data.TryGetValue("ca.crt", out var value))
            {
                _logger.LogDebug("Appending ca.crt to tls.crt");
                existingSecret.Data["tls.crt"] =
                    Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(newSecret.Data["tls.crt"]) +
                                           Encoding.UTF8.GetString(value));
                _logger.LogTrace("New tls.crt:\n {TlsCrt}", existingSecret.Data["tls.crt"]);
            }
            else
            {
                _logger.LogDebug("No chain was provided, only updating leaf certificate for '{Namespace}/{Name}'",
                    namespaceName, secretName);
                _logger.LogTrace("existing tls.crt:\n {TlsCrt}", existingSecret.Data["tls.crt"]);
                existingSecret.Data["tls.crt"] =
                    Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(newSecret.Data["tls.crt"]));
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

    private V1Secret UpdateOpaqueSecretMultiple(string secretName, string namespaceName, V1Secret existingSecret,
        string certPem, string keyPem)
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

    private V1Secret UpdateSecretStore(string secretName, string namespaceName, string secretType, string certPem,
        string keyPem, V1Secret newData, bool append,
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
                var dErrMsg =
                    $"Secret type not implemented. Unable to create or update certificate store {secretName} in {namespaceName} on {GetHost()}.";
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
                    _logger.LogWarning(
                        $"Unable to create X509Certificate2 from string in '{sKey}' field. Skipping. Error: {e.Message}");
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
                        _logger.LogWarning(
                            $"Unable to find corresponding private key in opaque secret for certificate {sCert.Thumbprint}. No need to remove.");
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
                _logger.LogWarning(
                    "Unable to update private_keys in opaque secret. This is expected if the secret did not contain private keys to begin with.");
            }


            // Update Kubernetes secret
            _logger.LogDebug(
                $"Updating secret {secretName} in namespace {namespaceName} on {GetHost()} with new certificate data.");
            _logger.LogTrace("Calling ReplaceNamespacedSecret()");
        }

        return Client.CoreV1.ReplaceNamespacedSecret(existingSecret, secretName, namespaceName);
    }

    public V1Status DeleteCertificateStoreSecret(string secretName, string namespaceName, string storeType,
        string alias)
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
                _logger.LogDebug(
                    $"Attempting to delete certificate from opaque secret {secretName} in namespace {namespaceName} on {GetHost()}");
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

            if (utfCsr != "") _logger.LogTrace("utfCsr: " + utfCsr);
            if (utfCert == "")
            {
                _logger.LogWarning("CSR has not been signed yet. Skipping.");
                continue;
            }

            _logger.LogDebug("Parsing certificate using BouncyCastle.");
            var cert = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.ParseCertificateFromPem(utfCert);
            _logger.LogTrace("cert: " + cert);

            _logger.LogDebug("Getting certificate Common Name.");
            var certName = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.GetSubjectCN(cert);
            _logger.LogTrace("certName: " + certName);

            _logger.LogDebug($"Adding certificate {certName} discovered location to list.");
            locations.Add($"{clusterName}/certificate/{certName}");
        }

        _logger.LogDebug("Completed discovering certificates from k8s certificate resources.");
        _logger.LogTrace("locations.Count: " + locations.Count);
        _logger.LogTrace("locations: " + locations);
        _logger.MethodExit(LogLevel.Debug);
        return locations;
    }

    /// <summary>
    /// Gets the status of a Kubernetes Certificate Signing Request.
    /// Returns the signed certificate PEM if the CSR has been approved and signed.
    /// </summary>
    /// <param name="name">Name of the CSR resource.</param>
    /// <returns>Array containing the certificate PEM, or empty if not yet signed.</returns>
    public string[] GetCertificateSigningRequestStatus(string name)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("CSR Name: {Name}", name);
        _logger.LogDebug("Attempting to read {Name} certificate signing request from {Host}...", name, GetHost());
        var cr = Client.CertificatesV1.ReadCertificateSigningRequest(name);
        _logger.LogDebug($"Successfully read {name} certificate signing request from {GetHost()}.");
        _logger.LogTrace("cr: " + cr);
        _logger.LogTrace("Attempting to parse certificate from certificate resource.");

        // Check if CSR has been signed yet
        if (cr.Status?.Certificate == null || cr.Status.Certificate.Length == 0)
        {
            _logger.LogInformation($"CSR {name} has no certificate yet (pending or denied). Returning empty inventory.");
            _logger.LogTrace("Exiting GetCertificateSigningRequestStatus() - no certificate");
            return Array.Empty<string>();
        }

        var utfCert = Encoding.UTF8.GetString(cr.Status.Certificate);
        _logger.LogTrace("utfCert: " + utfCert);

        _logger.LogDebug($"Attempting to parse certificate from certificate resource {name}.");
        var cert = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.ParseCertificateFromPem(utfCert);
        _logger.LogTrace("cert: " + cert);
        _logger.MethodExit(LogLevel.Debug);
        return new[] { utfCert };
    }

    /// <summary>
    /// Reads a DER-encoded certificate from a base64 string.
    /// </summary>
    /// <param name="derString">Base64-encoded DER certificate data.</param>
    /// <returns>Parsed X509Certificate object.</returns>
    public X509Certificate ReadDerCertificate(string derString)
    {
        _logger.MethodEntry(LogLevel.Debug);
        var derData = Convert.FromBase64String(derString);
        var certificateParser = new X509CertificateParser();
        var cert = certificateParser.ReadCertificate(derData);
        _logger.LogDebug("Parsed DER certificate: {Summary}", LoggingUtilities.GetCertificateSummary(cert));
        _logger.MethodExit(LogLevel.Debug);
        return cert;
    }

    /// <summary>
    /// Reads a PEM-encoded certificate from a string.
    /// </summary>
    /// <param name="pemString">PEM-encoded certificate string.</param>
    /// <returns>Parsed X509Certificate object, or null if not a valid certificate.</returns>
    public X509Certificate ReadPemCertificate(string pemString)
    {
        _logger.MethodEntry(LogLevel.Debug);
        using var reader = new StringReader(pemString);
        var pemReader = new PemReader(reader);
        var pemObject = pemReader.ReadPemObject();
        if (pemObject is not { Type: "CERTIFICATE" })
        {
            _logger.LogDebug("PEM object is not a certificate, returning null");
            _logger.MethodExit(LogLevel.Debug);
            return null;
        }

        var certificateBytes = pemObject.Content;
        var certificateParser = new X509CertificateParser();
        var cert = certificateParser.ReadCertificate(certificateBytes);
        _logger.LogDebug("Parsed PEM certificate: {Summary}", LoggingUtilities.GetCertificateSummary(cert));
        _logger.MethodExit(LogLevel.Debug);
        return cert;
    }

    /// <summary>
    /// Extracts a private key from a PKCS12 store and converts it to PEM format.
    /// Supports RSA and EC private keys.
    /// </summary>
    /// <param name="store">The PKCS12 store containing the private key.</param>
    /// <param name="password">Password for the store (currently unused, key is already decrypted).</param>
    /// <returns>PEM-formatted private key string.</returns>
    /// <exception cref="Exception">Thrown when no private key is found or key type is unsupported.</exception>
    public string ExtractPrivateKeyAsPem(Pkcs12Store store, string password)
    {
        _logger.MethodEntry(LogLevel.Debug);
        // Get the first private key entry
        var alias = store.Aliases.FirstOrDefault(entryAlias => store.IsKeyEntry(entryAlias));

        if (alias == null)
        {
            _logger.LogError("No private key found in the provided PFX/P12 file");
            throw new Exception("No private key found in the provided PFX/P12 file.");
        }

        _logger.LogDebug("Found private key with alias: {Alias}", alias);
        // Get the private key
        var keyEntry = store.GetKey(alias);
        var privateKeyParams = keyEntry.Key;

        var pemType = privateKeyParams switch
        {
            RsaPrivateCrtKeyParameters => "RSA PRIVATE KEY",
            ECPrivateKeyParameters => "EC PRIVATE KEY",
            _ => throw new Exception("Unsupported private key type.")
        };
        _logger.LogDebug("Private key type: {KeyType}", pemType);

        // Convert the private key to PEM format
        var sw = new StringWriter();
        var pemWriter = new PemWriter(sw);
        var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParams);
        var privateKeyBytes = privateKeyInfo.ToAsn1Object().GetEncoded();
        var pemObject = new PemObject(pemType, privateKeyBytes);
        pemWriter.WriteObject(pemObject);
        pemWriter.Writer.Flush();

        _logger.LogTrace("Private key: {Key}", LoggingUtilities.RedactPrivateKeyPem(sw.ToString()));
        _logger.MethodExit(LogLevel.Debug);
        return sw.ToString();
    }

    /// <summary>
    /// Loads a certificate chain from PEM data containing multiple certificates.
    /// </summary>
    /// <param name="pemData">PEM string potentially containing multiple certificates.</param>
    /// <returns>List of parsed X509Certificate objects.</returns>
    public List<X509Certificate> LoadCertificateChain(string pemData)
    {
        _logger.MethodEntry(LogLevel.Debug);
        var pemReader = new PemReader(new StringReader(pemData));
        var certificates = new List<X509Certificate>();

        PemObject pemObject;
        while ((pemObject = pemReader.ReadPemObject()) != null)
            if (pemObject.Type == "CERTIFICATE")
            {
                var certificateParser = new X509CertificateParser();
                var certificate = certificateParser.ReadCertificate(pemObject.Content);
                certificates.Add(certificate);
            }

        _logger.LogDebug("Loaded {Count} certificates from chain", certificates.Count);
        _logger.MethodExit(LogLevel.Debug);
        return certificates;
    }

    /// <summary>
    /// Converts a BouncyCastle X509Certificate to PEM format.
    /// </summary>
    /// <param name="certificate">The certificate to convert.</param>
    /// <returns>PEM-formatted certificate string.</returns>
    public string ConvertToPem(X509Certificate certificate)
    {
        _logger.MethodEntry(LogLevel.Debug);
        var pemObject = new PemObject("CERTIFICATE", certificate.GetEncoded());
        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);
        pemWriter.WriteObject(pemObject);
        pemWriter.Writer.Flush();
        _logger.MethodExit(LogLevel.Debug);
        return stringWriter.ToString();
    }

    /// <summary>
    /// Discovers secrets across namespaces in the Kubernetes cluster.
    /// Filters by secret type and allowed keys.
    /// </summary>
    /// <param name="allowedKeys">Array of allowed secret data field names.</param>
    /// <param name="secType">Secret type filter (e.g., "Opaque", "kubernetes.io/tls").</param>
    /// <param name="ns">Namespace to search, or "default".</param>
    /// <param name="namespaceIsStore">When true, treats entire namespace as a single store.</param>
    /// <param name="clusterIsStore">When true, treats entire cluster as a single store.</param>
    /// <returns>List of discovered secret locations.</returns>
    public List<string> DiscoverSecrets(
        string[] allowedKeys, string secType, string ns = "default",
        bool namespaceIsStore = false, bool clusterIsStore = false)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("Parameters - AllowedKeys: [{Keys}], SecType: {SecType}, Namespace: {Ns}",
            string.Join(", ", allowedKeys ?? Array.Empty<string>()), secType, ns);
        var locations = new List<string>();
        var clusterName = GetClusterName() ?? GetHost();
        _logger.LogTrace("ClusterName: {ClusterName}", clusterName);

        // Cluster-level discovery shortcut
        if (secType == "cluster")
        {
            _logger.LogTrace("Discovering cluster-level secrets");
            locations.Add(clusterName);
            return locations;
        }

        // Fetch namespaces and selected namespaces based on the ns parameter
        var namespaces = FetchNamespaces(clusterName);
        var nsList = ns.Contains(',') ? ns.Split(',') : new[] { ns };

        foreach (var nsObj in FilterNamespaces(namespaces, nsList))
        {
            if (secType == "namespace")
            {
                AddNamespaceLocation(locations, clusterName, nsObj.Metadata.Name);
                continue;
            }

            DiscoverSecretsInNamespace(
                nsObj.Metadata.Name, allowedKeys, secType, locations, clusterName);
        }

        _logger.LogDebug("Discovered {Count} locations", locations.Count);
        _logger.MethodExit(LogLevel.Debug);
        return locations;
    }

    /// <summary>
    /// Fetches all namespaces from the Kubernetes cluster.
    /// </summary>
    /// <param name="clusterName">Name of the cluster for logging.</param>
    /// <returns>Enumerable of V1Namespace objects.</returns>
    private IEnumerable<V1Namespace> FetchNamespaces(string clusterName)
    {
        _logger.MethodEntry(LogLevel.Debug);
        var result = RetryPolicy(() =>
        {
            _logger.LogDebug("Attempting to list Kubernetes namespaces from {ClusterName}", clusterName);
            return Client.CoreV1.ListNamespace().Items;
        });
        _logger.MethodExit(LogLevel.Debug);
        return result;
    }

    /// <summary>
    /// Filters namespaces based on the provided list.
    /// </summary>
    /// <param name="namespaces">All available namespaces.</param>
    /// <param name="nsList">List of namespace names to include, or "all" for all namespaces.</param>
    /// <returns>Filtered enumerable of namespaces.</returns>
    private IEnumerable<V1Namespace> FilterNamespaces(IEnumerable<V1Namespace> namespaces, string[] nsList)
    {
        foreach (var nsObj in namespaces)
            if (nsList.Contains("all") || nsList.Contains(nsObj.Metadata.Name))
            {
                _logger.LogDebug("Processing namespace: {Namespace}", nsObj.Metadata.Name);
                yield return nsObj;
            }
            else
            {
                _logger.LogTrace("Skipping namespace '{Namespace}' as it does not match filter", nsObj.Metadata.Name);
            }
    }

    /// <summary>
    /// Adds a namespace-level location to the discovery results.
    /// </summary>
    /// <param name="locations">List to add the location to.</param>
    /// <param name="clusterName">Name of the cluster.</param>
    /// <param name="namespaceName">Name of the namespace.</param>
    private void AddNamespaceLocation(List<string> locations, string clusterName, string namespaceName)
    {
        var nsLocation = $"{clusterName}/namespace/{namespaceName}";
        locations.Add(nsLocation);
        _logger.LogDebug("Added namespace-level location: {NamespaceLocation}", nsLocation);
    }

    /// <summary>
    /// Discovers secrets within a specific namespace.
    /// </summary>
    /// <param name="namespaceName">Namespace to search.</param>
    /// <param name="allowedKeys">Allowed secret data field names.</param>
    /// <param name="secType">Secret type filter.</param>
    /// <param name="locations">List to add discovered locations to.</param>
    /// <param name="clusterName">Name of the cluster.</param>
    private void DiscoverSecretsInNamespace(
        string namespaceName, string[] allowedKeys, string secType, List<string> locations, string clusterName)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogDebug("Discovering secrets in namespace: {Namespace}", namespaceName);

        var secrets = RetryPolicy(() =>
            Client.CoreV1.ListNamespacedSecret(namespaceName).Items);

        foreach (var secret in secrets)
            ProcessSecretIfSupported(secret, secType, allowedKeys, clusterName, namespaceName, locations);
    }

    private void ProcessSecretIfSupported(
        V1Secret secret, string secType, string[] allowedKeys, string clusterName, string namespaceName,
        List<string> locations)
    {
        if (!IsSupportedSecretType(secret.Type, secType))
        {
            _logger.LogDebug(
                "Skipping secret '{SecretName}' as its type ({SecretType}) does not match {SecType}.",
                secret.Metadata.Name, secret.Type, secType);
            return;
        }

        var secretData = RetryPolicy(() =>
            Client.CoreV1.ReadNamespacedSecret(secret.Metadata.Name, namespaceName));

        ProcessSecret(secret, secretData, allowedKeys, clusterName, namespaceName, locations);
    }

    private T RetryPolicy<T>(Func<T> action)
    {
        const int maxRetries = 5;
        const double baseDelaySeconds = 2.0; // Base delay for exponential backoff
        const double maxDelaySeconds = 30.0;

        for (var attempt = 1; attempt <= maxRetries; attempt++)
            try
            {
                return action();
            }
            catch (HttpRequestException ex)
            {
                if (attempt == maxRetries)
                {
                    _logger.LogError("Reached max retry attempts for operation: {Message}", ex.Message);
                    throw;
                }

                var delay = TimeSpan.FromSeconds(Math.Min(baseDelaySeconds * Math.Pow(2, attempt - 1),
                    maxDelaySeconds));
                _logger.LogWarning(
                    "Retry attempt {Attempt}/{MaxRetries} caused by {Message}. Retrying after {Delay} seconds.",
                    attempt, maxRetries, ex.Message, delay.TotalSeconds);
                Thread.Sleep(delay);
            }

        throw new InvalidOperationException("Unexpected error in retry logic."); // This will never be reached
    }

    private static bool IsSupportedSecretType(string secretType, string secType)
    {
        return secretType.ToLower() switch
        {
            "kubernetes.io/tls" => secType.Equals("tls", StringComparison.OrdinalIgnoreCase)
                                   || secType.Equals("kubernetes.io/tls", StringComparison.OrdinalIgnoreCase),
            "opaque" => secType.Equals("opaque", StringComparison.OrdinalIgnoreCase)
                        || new[] { "pkcs12", "p12", "pfx", "jks" }.Contains(secType.ToLowerInvariant()),
            _ => false
        };
    }

    private void ProcessSecret(V1Secret secret, V1Secret secretData, string[] allowedKeys,
        string clusterName, string namespaceName, List<string> locations)
    {
        var secretLocation = $"{clusterName}/{namespaceName}/secrets/{secret.Metadata.Name}";
        _logger.LogTrace("Processing secret: {SecretName}. Secret location: {SecretLocation}",
            secret.Metadata.Name, secretLocation);

        try
        {
            switch (secret.Type.ToLower())
            {
                case "kubernetes.io/tls":
                    var cert = ParseTlsSecret(secretData, secret.Metadata.Name);
                    if (cert != null)
                    {
                        _logger.LogDebug("Discovered TLS certificate at: {Location}", secretLocation);
                        locations.Add(secretLocation);
                    }

                    break;

                case "opaque":
                    ParseOpaqueSecret(secretData, allowedKeys);
                    _logger.LogDebug("Discovered opaque secret at: {Location}", secretLocation);
                    locations.Add(secretLocation);
                    break;

                default:
                    _logger.LogWarning("Unsupported secret type: {SecretType}", secret.Type);
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError("Failed to process secret: {SecretName}. Error: {Message}", secret.Metadata.Name,
                ex.Message);
        }
    }

#nullable enable
    private string? ParseTlsSecret(V1Secret secretData, string secretName)
    {
        try
        {
            var certData = Encoding.UTF8.GetString(secretData.Data["tls.crt"]);
            var keyData = Encoding.UTF8.GetString(secretData.Data["tls.key"]);
            _logger.LogTrace("Successfully parsed TLS secret: {SecretName}.", secretName);
            return certData; // Simply returning certificate data
        }
        catch (Exception ex)
        {
            _logger.LogError("Error parsing TLS secret: {SecretName}. Message: {Message}", secretName, ex.Message);
            return null;
        }
    }
#nullable restore

    private void ParseOpaqueSecret(V1Secret secretData, string[] allowedKeys)
    {
        if (secretData.Data == null)
        {
            _logger.LogWarning("Secret data is null. Skipping this secret.");
            return;
        }

        foreach (var dataKey in secretData.Data.Keys)
        {
            var extension = Path.GetExtension(dataKey).TrimStart('.').ToLowerInvariant();
            if (!allowedKeys.Contains(extension) && !allowedKeys.Contains(dataKey))
            {
                _logger.LogDebug("Skipping key {Key} as it is not in the list of allowed keys.", dataKey);
                continue;
            }

            _logger.LogDebug("Allowed key {Key} found in secret. Parsing secret as needed.", dataKey);
            // Further processing logic here if required
        }
    }

    /// <summary>
    /// Retrieves a JKS (Java KeyStore) secret from Kubernetes.
    /// Filters secret data by allowed key extensions.
    /// </summary>
    /// <param name="secretName">Name of the Kubernetes secret.</param>
    /// <param name="namespaceName">Namespace containing the secret.</param>
    /// <param name="password">Password for the JKS store.</param>
    /// <param name="passwordPath">Path to password secret if stored separately.</param>
    /// <param name="allowedKeys">List of allowed file extensions/keys (defaults to jks).</param>
    /// <returns>JksSecret object containing the secret data.</returns>
    /// <exception cref="InvalidK8SSecretException">Thrown when the secret exists but has no data.</exception>
    /// <exception cref="StoreNotFoundException">Thrown when the secret does not exist.</exception>
    public JksSecret GetJksSecret(string secretName, string namespaceName, string password = null,
        string passwordPath = null, List<string> allowedKeys = null)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("SecretName: {SecretName}, Namespace: {Namespace}", secretName, namespaceName);
        _logger.LogTrace("Password: {Password}", LoggingUtilities.RedactPassword(password));
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

                allowedKeys ??= new List<string> { "jks", "JKS", "Jks" };

                var secretData = new Dictionary<string, byte[]>();

                foreach (var secretFieldName in secret?.Data.Keys)
                {
                    _logger.LogTrace("secretFieldName: {Name}", secretFieldName);
                    var sField = secretFieldName;
                    if (secretFieldName.Contains('.')) sField = secretFieldName.Split(".")[^1];
                    var isJksField = allowedKeys.Any(allowedKey => sField.Contains(allowedKey));

                    if (!isJksField) continue;

                    _logger.LogTrace("Key " + secretFieldName + " is in list of allowed keys" + allowedKeys);
                    var data = secret.Data[secretFieldName];
                    _logger.LogTrace("data: " + data);
                    secretData.Add(secretFieldName, data);
                }

                var output = new JksSecret
                {
                    Secret = secret,
                    SecretPath = $"{namespaceName}/secrets/{secretName}",
                    SecretFieldName = secret.Data.Keys.FirstOrDefault(),
                    Password = password,
                    PasswordPath = passwordPath,
                    AllowedKeys = allowedKeys,
                    Inventory = secretData
                };
                _logger.MethodExit(LogLevel.Debug);
                return output;
            }

            _logger.LogError("K8S secret {SecretName} in namespace {Namespace} has no data", secretName, namespaceName);
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
            _logger.LogError("K8S secret {SecretName} not found in namespace {NamespaceName}", secretName,
                namespaceName);
            throw new StoreNotFoundException($"K8S secret not found {namespaceName}/secrets/{secretName}");
        }
    }

    /// <summary>
    /// Retrieves a PKCS12/PFX secret from Kubernetes.
    /// Filters secret data by allowed key extensions.
    /// </summary>
    /// <param name="secretName">Name of the Kubernetes secret.</param>
    /// <param name="namespaceName">Namespace containing the secret.</param>
    /// <param name="password">Password for the PKCS12 store.</param>
    /// <param name="passwordPath">Path to password secret if stored separately.</param>
    /// <param name="allowedKeys">List of allowed file extensions/keys (defaults to p12, pfx, pkcs12).</param>
    /// <returns>Pkcs12Secret object containing the secret data.</returns>
    /// <exception cref="StoreNotFoundException">Thrown when the secret does not exist.</exception>
    public Pkcs12Secret GetPkcs12Secret(string secretName, string namespaceName, string password = null,
        string passwordPath = null, List<string> allowedKeys = null)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("SecretName: {SecretName}, Namespace: {Namespace}", secretName, namespaceName);
        _logger.LogTrace("Password: {Password}", LoggingUtilities.RedactPassword(password));
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

            allowedKeys ??= new List<string> { "pkcs12", "p12", "P12", "PKCS12", "pfx", "PFX" };


            var secretData = new Dictionary<string, byte[]>();

            foreach (var secretFieldName in secret?.Data.Keys)
            {
                _logger.LogTrace("secretFieldName: " + secretFieldName);
                var sField = secretFieldName;
                if (secretFieldName.Contains('.')) sField = secretFieldName.Split(".")[^1];
                var isPkcs12Field = allowedKeys.Any(allowedKey => sField.Contains(allowedKey));

                if (!isPkcs12Field) continue;

                _logger.LogTrace("Key " + secretFieldName + " is in list of allowed keys" + allowedKeys);
                var data = secret.Data[secretFieldName];
                _logger.LogTrace("data: " + data);
                secretData.Add(secretFieldName, data);
            }

            var output = new Pkcs12Secret
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
    }

    /// <summary>
    /// Creates a Kubernetes Certificate Signing Request (CSR).
    /// </summary>
    /// <param name="name">Name of the CSR resource.</param>
    /// <param name="namespaceName">Namespace for the CSR metadata.</param>
    /// <param name="csr">PEM-encoded certificate signing request.</param>
    /// <returns>The created V1CertificateSigningRequest object.</returns>
    public V1CertificateSigningRequest CreateCertificateSigningRequest(string name, string namespaceName, string csr)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("CSR Name: {Name}, Namespace: {Namespace}", name, namespaceName);
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
        var result = Client.CertificatesV1.CreateCertificateSigningRequest(request);
        _logger.MethodExit(LogLevel.Debug);
        return result;
    }

    /// <summary>
    /// Generates a new certificate signing request (CSR) with private key.
    /// Creates an RSA key pair and builds a CSR with the specified SANs and IPs.
    /// </summary>
    /// <param name="name">Common Name for the certificate.</param>
    /// <param name="sans">Subject Alternative Names (DNS names).</param>
    /// <param name="ips">IP addresses to include in SAN.</param>
    /// <param name="keyType">Key algorithm type (default: RSA).</param>
    /// <param name="keyBits">Key size in bits (default: 4096).</param>
    /// <returns>CsrObject containing CSR, private key, and public key in PEM format.</returns>
    public CsrObject GenerateCertificateRequest(string name, string[] sans, IPAddress[] ips,
        string keyType = "RSA", int keyBits = 4096)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("Name: {Name}, KeyType: {KeyType}, KeyBits: {KeyBits}", name, keyType, keyBits);
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
            new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
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
        var result = new CsrObject
        {
            Csr = csrPem,
            PrivateKey = keyPem,
            PublicKey = pubKeyPem
        };
        _logger.LogTrace("Generated CSR: {CSR}", LoggingUtilities.RedactCertificatePem(csrPem));
        _logger.MethodExit(LogLevel.Debug);
        return result;
    }


    /// <summary>
    /// Gets certificate inventory from Opaque secrets.
    /// Currently returns empty list - placeholder for future implementation.
    /// </summary>
    /// <returns>Empty list of inventory items.</returns>
    public IEnumerable<CurrentInventoryItem> GetOpaqueSecretCertificateInventory()
    {
        _logger.MethodEntry(LogLevel.Debug);
        var inventoryItems = new List<CurrentInventoryItem>();
        _logger.MethodExit(LogLevel.Debug);
        return inventoryItems;
    }

    /// <summary>
    /// Gets certificate inventory from TLS secrets.
    /// Currently returns empty list - placeholder for future implementation.
    /// </summary>
    /// <returns>Empty list of inventory items.</returns>
    public IEnumerable<CurrentInventoryItem> GetTlsSecretCertificateInventory()
    {
        _logger.MethodEntry(LogLevel.Debug);
        var inventoryItems = new List<CurrentInventoryItem>();
        _logger.MethodExit(LogLevel.Debug);
        return inventoryItems;
    }

    /// <summary>
    /// Gets certificate inventory from all certificate resources.
    /// Currently returns empty list - placeholder for future implementation.
    /// </summary>
    /// <returns>Empty list of inventory items.</returns>
    public IEnumerable<CurrentInventoryItem> GetCertificateInventory()
    {
        _logger.MethodEntry(LogLevel.Debug);
        var inventoryItems = new List<CurrentInventoryItem>();
        _logger.MethodExit(LogLevel.Debug);
        return inventoryItems;
    }

    /// <summary>
    /// Creates or updates a JKS secret in Kubernetes.
    /// Preserves existing data fields while updating the inventory items.
    /// </summary>
    /// <param name="k8SData">JksSecret containing the data to store.</param>
    /// <param name="kubeSecretName">Name of the Kubernetes secret.</param>
    /// <param name="kubeNamespace">Namespace for the secret.</param>
    /// <returns>The created or updated V1Secret.</returns>
    public V1Secret CreateOrUpdateJksSecret(JksSecret k8SData, string kubeSecretName, string kubeNamespace)
    {
        _logger.MethodEntry(LogLevel.Debug);
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
                return Client.CoreV1.CreateNamespacedSecret(s1, kubeNamespace);
            _logger.LogError("Error checking if secret {Name} exists in namespace {Namespace}: {Message}",
                kubeSecretName, kubeNamespace, e.Message);
        }

        // Replace existing secret
        _logger.LogDebug("Replacing secret {Name} in namespace {Namespace}", kubeSecretName, kubeNamespace);
        var result = Client.CoreV1.ReplaceNamespacedSecret(s1, kubeSecretName, kubeNamespace);
        _logger.MethodExit(LogLevel.Debug);
        return result;
    }

    /// <summary>
    /// Creates or updates a PKCS12 secret in Kubernetes.
    /// Preserves existing data fields while updating the inventory items.
    /// </summary>
    /// <param name="k8SData">Pkcs12Secret containing the data to store.</param>
    /// <param name="kubeSecretName">Name of the Kubernetes secret.</param>
    /// <param name="kubeNamespace">Namespace for the secret.</param>
    /// <returns>The created or updated V1Secret.</returns>
    public V1Secret CreateOrUpdatePkcs12Secret(Pkcs12Secret k8SData, string kubeSecretName, string kubeNamespace)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("SecretName: {Name}, Namespace: {Namespace}", kubeSecretName, kubeNamespace);
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
        foreach (var inventoryItem in k8SData.Inventory) s1.Data[inventoryItem.Key] = inventoryItem.Value;

        // Create secret if it doesn't exist
        try
        {
            Client.CoreV1.ReadNamespacedSecret(kubeSecretName, kubeNamespace);
        }
        catch (HttpOperationException e)
        {
            if (e.Response.StatusCode == HttpStatusCode.NotFound)
                return Client.CoreV1.CreateNamespacedSecret(s1, kubeNamespace);
        }

        // Replace existing secret
        _logger.LogDebug("Replacing secret {Name} in namespace {Namespace}", kubeSecretName, kubeNamespace);
        var result = Client.CoreV1.ReplaceNamespacedSecret(s1, kubeSecretName, kubeNamespace);
        _logger.MethodExit(LogLevel.Debug);
        return result;
    }

    /// <summary>
    /// Represents a JKS (Java KeyStore) secret in Kubernetes.
    /// </summary>
    public struct JksSecret
    {
        /// <summary>Path to the secret in format namespace/secrets/name.</summary>
        public string SecretPath;
        /// <summary>Field name within the secret containing the JKS data.</summary>
        public string SecretFieldName;
        /// <summary>The underlying Kubernetes V1Secret object.</summary>
        public V1Secret Secret;
        /// <summary>Password for the JKS store.</summary>
        public string Password;
        /// <summary>Path to a separate secret containing the password.</summary>
        public string PasswordPath;
        /// <summary>List of allowed file extensions/keys.</summary>
        public List<string> AllowedKeys;
        /// <summary>Dictionary of field names to JKS data bytes.</summary>
        public Dictionary<string, byte[]> Inventory;
    }

    /// <summary>
    /// Represents a PKCS12/PFX secret in Kubernetes.
    /// </summary>
    public struct Pkcs12Secret
    {
        /// <summary>Path to the secret in format namespace/secrets/name.</summary>
        public string SecretPath;
        /// <summary>Field name within the secret containing the PKCS12 data.</summary>
        public string SecretFieldName;
        /// <summary>The underlying Kubernetes V1Secret object.</summary>
        public V1Secret Secret;
        /// <summary>Password for the PKCS12 store.</summary>
        public string Password;
        /// <summary>Path to a separate secret containing the password.</summary>
        public string PasswordPath;
        /// <summary>List of allowed file extensions/keys.</summary>
        public List<string> AllowedKeys;
        /// <summary>Dictionary of field names to PKCS12 data bytes.</summary>
        public Dictionary<string, byte[]> Inventory;
    }

    /// <summary>
    /// Represents a Certificate Signing Request with associated key pair.
    /// </summary>
    public struct CsrObject
    {
        /// <summary>PEM-encoded certificate signing request.</summary>
        public string Csr;
        /// <summary>PEM-encoded private key.</summary>
        public string PrivateKey;
        /// <summary>PEM-encoded public key.</summary>
        public string PublicKey;
    }
}