// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.IO;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Common.Logging;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

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

public abstract class JobBase
{
    // static JobBase()
    // {
    //     SupportedKubeStoreTypes = new[] { "secret", "certificate" };
    //     RequiredProperties = new[] { "KubeNamespace", "KubeSecretName", "KubeSecretType", "KubeSvcCreds" };
    //     CertChainSeparator = ",";
    // }

    static protected readonly string[] SupportedKubeStoreTypes = { "secret", "certificate" };

    // private static readonly string[] RequiredProperties = { "kube_namespace", "kube_secret_name", "kube_secret_type", "kube_svc_creds" };
    static protected readonly string[] RequiredProperties = { "KubeNamespace", "KubeSecretName", "KubeSecretType", "KubeSvcCreds" };

    static protected string CertChainSeparator = ",";
    internal protected KubeCertificateManagerClient KubeClient;

    internal protected ILogger Logger;

    internal protected string Capability { get; set; }

    internal protected IPAMSecretResolver Resolver { get; set; }

    public string StorePath { get; set; }

    internal protected string KubeNamespace { get; set; }

    internal protected string KubeSecretName { get; set; }

    internal protected string KubeSecretType { get; set; }

    internal protected string KubeSvcCreds { get; set; }

    internal protected string KubeHost { get; set; }

    internal protected string ServerUsername { get; set; }

    internal protected string ServerPassword { get; set; }

    internal protected string StorePassword { get; set; }

    internal protected bool Overwrite { get; set; }

    internal protected virtual AsymmetricKeyEntry KeyEntry { get; set; }

    internal protected ManagementJobConfiguration ManagementConfig { get; set; }

    internal protected DiscoveryJobConfiguration DiscoveryConfig { get; set; }

    internal protected InventoryJobConfiguration InventoryConfig { get; set; }

    public string ExtensionName => "K8S";

    protected void InitializeStore(InventoryJobConfiguration config)
    {
        InventoryConfig = config;
        Capability = config.Capability;
        Logger = LogHandler.GetClassLogger(GetType());
        var props = JsonConvert.DeserializeObject(config.CertificateStoreDetails.Properties);
        //var props = Jsonconfig.CertificateStoreDetails.Properties;
        ServerUsername = config?.ServerUsername;
        ServerPassword = config?.ServerPassword;
        StorePath = config.CertificateStoreDetails?.StorePath;
        // StorePath = GetStorePath();
        InitializeProperties(props);
        
    }

    protected void InitializeStore(DiscoveryJobConfiguration config)
    {
        DiscoveryConfig = config;
        Logger = LogHandler.GetClassLogger(GetType());
        var props = config.JobProperties;
        Capability = config?.Capability;
        ServerUsername = config?.ServerUsername;
        ServerPassword = config?.ServerPassword;
        InitializeProperties(props);
    }

    protected void InitializeStore(ManagementJobConfiguration config)
    {
        ManagementConfig = config;
        Logger = LogHandler.GetClassLogger(GetType());
        var props = JsonConvert.DeserializeObject(config.CertificateStoreDetails.Properties);
        Capability = config?.Capability;
        ServerUsername = config?.ServerUsername;
        ServerPassword = config?.ServerPassword;
        StorePath = config.CertificateStoreDetails?.StorePath;
        
        InitializeProperties(props);
        // StorePath = config.CertificateStoreDetails?.StorePath;
        // StorePath = GetStorePath();
        Overwrite = config.Overwrite;
    }

    private void InitializeProperties(dynamic storeProperties)
    {
        if (storeProperties == null)
            throw new ConfigurationException(
                $"Invalid configuration. Please provide {RequiredProperties}. Or review the documentation at https://github.com/Keyfactor/kubernetes-orchestrator#custom-fields-tab.");

        // check if key is present and set values if not

        try
        {
            KubeNamespace = storeProperties["KubeNamespace"];
            KubeSecretName = storeProperties["KubeSecretName"];
            KubeSecretType = storeProperties["KubeSecretType"];
            KubeSvcCreds = storeProperties["KubeSvcCreds"];
        }
        catch (Exception)
        {
            KubeSecretType = "";
            KubeSvcCreds = "";
        }

        if (string.IsNullOrEmpty(KubeSecretName) && !string.IsNullOrEmpty(StorePath))
        {
            KubeSecretName = StorePath.Split("/").Last();
        }
        
        if (string.IsNullOrEmpty(KubeNamespace) && !string.IsNullOrEmpty(StorePath))
        {
            KubeNamespace = StorePath.Split("/").First();
        }

        Logger.LogDebug($"KubeNamespace: {KubeNamespace}");
        Logger.LogDebug($"KubeSecretName: {KubeSecretName}");
        Logger.LogDebug($"KubeSecretType: {KubeSecretType}");

        if (string.IsNullOrEmpty(KubeSecretName))
        {
            // KubeSecretName = StorePath.Split("/").Last();
            KubeSecretName = StorePath;
        }
        
        //check if storeProperties contains ServerUsername key

        if (string.IsNullOrEmpty(ServerUsername))
        {
            // check if storeProperties contains ServerUsername ke
            ServerUsername = storeProperties.ContainsKey("ServerUsername") ? (string)ResolvePamField("ServerUsername", storeProperties["ServerUsername"]) : "kubeconfig";

        }
        if (string.IsNullOrEmpty(ServerPassword))
        {
            ServerPassword = storeProperties.ContainsKey("ServerPassword") ? (string)ResolvePamField("ServerPassword", storeProperties["ServerPassword"]) : "";
        }
        // var storePassword = ResolvePamField("Store Password", storeProperties.CertificateStoreDetails.StorePassword);

        // if (storePassword != null)
        // {
        //     Logger.LogWarning($"Store password provided but is not supported by store type {storeProperties.Capability}).");
        // }

        if (ServerUsername == "kubeconfig")
        {
            Logger.LogInformation("Using kubeconfig provided by 'Server Password' field");
            storeProperties["KubeSvcCreds"] = ServerPassword;
            KubeSvcCreds = ServerPassword;
            // logger.LogTrace($"KubeSvcCreds: {localCertStore.KubeSvcCreds}"); //Do not log passwords
        }

        if (string.IsNullOrEmpty(KubeSvcCreds))
        {
            const string credsErr =
                "No credentials provided to connect to Kubernetes. Please provide a kubeconfig file. See https://github.com/Keyfactor/kubernetes-orchestrator/blob/main/scripts/kubernetes/get_service_account_creds.sh";
            Logger.LogError(credsErr);
            throw new AuthenticationException(credsErr);
        }

        KubeClient = new KubeCertificateManagerClient(KubeSvcCreds);

        KubeHost = KubeClient.GetHost();
    }

    public string GetStorePath()
    {
        var secretType = KubeSecretType.ToLower() is "tls_secret" or "secret" ? "secret" : "certificate";
        StorePath = $"{KubeHost}/{KubeNamespace}/{secretType}/{KubeSecretName}";
        return StorePath;
    }

    protected string ResolvePamField(string name, string value)
    {
        var logger = LogHandler.GetClassLogger(GetType());
        logger.LogTrace($"Attempting to resolved PAM eligible field {name}");
        return Resolver.Resolve(name);
    }

    protected byte[] GetKeyBytes(X509Certificate2 certObj, string certPassword = null)
    {
        byte[] keyBytes;

        switch (certObj.GetKeyAlgorithm())
        {
            case "RSA":
                keyBytes = certObj.GetRSAPrivateKey()?.ExportRSAPrivateKey();
                break;
            case "ECDSA":
                keyBytes = certObj.GetECDsaPrivateKey()?.ExportECPrivateKey();
                break;
            case "DSA":
                keyBytes = certObj.GetDSAPrivateKey()?.ExportPkcs8PrivateKey();
                break;
            default:
                keyBytes = certObj.Export(X509ContentType.Pkcs12, certPassword);
                break;
        }
        return keyBytes;
    }

    static protected JobResult FailJob(string message, long jobHistoryId)
    {
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Failure,
            JobHistoryId = jobHistoryId,
            FailureMessage = message
        };
    }

    static protected JobResult SuccessJob(long jobHistoryId)
    {
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Success,
            JobHistoryId = jobHistoryId
        };
    }

    protected string ParseJobPrivateKey(ManagementJobConfiguration config)
    {
        if (string.IsNullOrWhiteSpace(config.JobCertificate.Alias)) Logger.LogTrace("No Alias Found");

        // Load PFX
        var pfxBytes = Convert.FromBase64String(config.JobCertificate.Contents);
        Pkcs12Store p;
        using (var pfxBytesMemoryStream = new MemoryStream(pfxBytes))
        {
            p = new Pkcs12Store(pfxBytesMemoryStream,
                config.JobCertificate.PrivateKeyPassword.ToCharArray());
        }

        Logger.LogTrace(
            $"Created Pkcs12Store containing Alias {config.JobCertificate.Alias} Contains Alias is {p.ContainsAlias(config.JobCertificate.Alias)}");

        // Extract private key
        string alias;
        string privateKeyString;
        using (var memoryStream = new MemoryStream())
        {
            using (TextWriter streamWriter = new StreamWriter(memoryStream))
            {
                Logger.LogTrace("Extracting Private Key...");
                var pemWriter = new PemWriter(streamWriter);
                Logger.LogTrace("Created pemWriter...");
                alias = p.Aliases.Cast<string>().SingleOrDefault(a => p.IsKeyEntry(a));
                Logger.LogTrace($"Alias = {alias}");
                var publicKey = p.GetCertificate(alias).Certificate.GetPublicKey();
                Logger.LogTrace($"publicKey = {publicKey}");
                KeyEntry = p.GetKey(alias);
                Logger.LogTrace($"KeyEntry = {KeyEntry}");
                if (KeyEntry == null) throw new Exception("Unable to retrieve private key");

                var privateKey = KeyEntry.Key;
                // Logger.LogTrace($"privateKey = {privateKey}");
                var keyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);

                pemWriter.WriteObject(keyPair.Private);
                streamWriter.Flush();
                privateKeyString = Encoding.ASCII.GetString(memoryStream.GetBuffer()).Trim()
                    .Replace("\r", "").Replace("\0", "");
                // Logger.LogTrace($"Got Private Key String {privateKeyString}");
                memoryStream.Close();
                streamWriter.Close();
                Logger.LogTrace("Finished Extracting Private Key...");
                return privateKeyString;
            }
        }
    }
}
