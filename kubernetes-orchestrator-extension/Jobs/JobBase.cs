// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Common.Logging;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.PKI.PrivateKeys;
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

public class K8SJobCertificate
{
    public string Alias { get; set; } = "";

    public string Certb64 { get; set; } = "";

    public string CertPEM { get; set; } = "";

    public string CertThumbprint { get; set; } = "";

    public byte[] CertBytes { get; set; }

    public string PrivateKeyB64 { get; set; } = "";

    public string PrivateKeyPEM { get; set; } = "";

    public byte[] PrivateKeyBytes { get; set; }

    public string Password { get; set; } = "";

    public bool hasPrivateKey { get; set; } = false;

    public bool hasPassword { get; set; } = false;
}

public abstract class JobBase
{

    static protected readonly string[] SupportedKubeStoreTypes;

    static protected readonly string[] RequiredProperties;

    static protected readonly string[] TLSAllowedKeys;
    static protected readonly string[] OpaqueAllowedKeys;
    static protected readonly string[] CertAllowedKeys;

    static protected string CertChainSeparator = ",";
    internal protected KubeCertificateManagerClient KubeClient;

    internal protected ILogger Logger;
    static JobBase()
    {
        CertAllowedKeys = new[] { "cert", "csr" };
        TLSAllowedKeys = new[] { "tls.crt", "tls.key", "ca.crt" };
        OpaqueAllowedKeys = new[] { "tls.crt", "tls.crts", "cert", "certs", "certificate", "certificates", "crt", "crts", "ca.crt" };
        SupportedKubeStoreTypes = new[] { "secret", "certificate" };
        RequiredProperties = new[] { "KubeNamespace", "KubeSecretName", "KubeSecretType" };
    }

    public K8SJobCertificate K8SCertificate { get; set; }

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

    public string KubeCluster { get; set; }

    protected void InitializeStore(InventoryJobConfiguration config)
    {
        InventoryConfig = config;
        Capability = config.Capability;
        Logger = LogHandler.GetClassLogger(GetType());
        Logger.LogTrace("Entered InitializeStore() for INVENTORY.");
        var props = JsonConvert.DeserializeObject(config.CertificateStoreDetails.Properties);
        //var props = Jsonconfig.CertificateStoreDetails.Properties;
        ServerUsername = config?.ServerUsername;
        ServerPassword = config?.ServerPassword;
        StorePath = config.CertificateStoreDetails?.StorePath;
        // StorePath = GetStorePath();
        Logger.LogTrace($"ServerUsername: {ServerUsername}");
        // Logger.LogTrace($"ServerPassword: {ServerPassword}");
        Logger.LogTrace($"StorePath: {StorePath}");
        Logger.LogTrace("Calling InitializeProperties()");
        InitializeProperties(props);

    }

    protected void InitializeStore(DiscoveryJobConfiguration config)
    {
        DiscoveryConfig = config;
        Logger = LogHandler.GetClassLogger(GetType());
        Logger.LogTrace("Entered InitializeStore() for DISCOVERY.");
        var props = config.JobProperties;
        Capability = config?.Capability;
        ServerUsername = config?.ServerUsername;
        ServerPassword = config?.ServerPassword;

        Logger.LogTrace($"ServerUsername: {ServerUsername}");

        Logger.LogTrace("Calling InitializeProperties()");
        InitializeProperties(props);
    }

    protected void InitializeStore(ManagementJobConfiguration config)
    {
        ManagementConfig = config;
        Logger = LogHandler.GetClassLogger(GetType());
        Logger.LogTrace("Entered InitializeStore() for MANAGEMENT.");
        var props = JsonConvert.DeserializeObject(config.CertificateStoreDetails.Properties);
        Capability = config?.Capability;
        ServerUsername = config?.ServerUsername;
        ServerPassword = config?.ServerPassword;
        StorePath = config.CertificateStoreDetails?.StorePath;

        Logger.LogTrace($"ServerUsername: {ServerUsername}");
        Logger.LogTrace($"StorePath: {StorePath}");

        Logger.LogTrace("Calling InitializeProperties()");
        InitializeProperties(props);
        // StorePath = config.CertificateStoreDetails?.StorePath;
        // StorePath = GetStorePath();
        Overwrite = config.Overwrite;
        Logger.LogTrace($"Overwrite: {Overwrite.ToString()}");
    }


    public K8SJobCertificate InitJobCertificate(dynamic config)
    {
        Logger.LogTrace("Entered InitJobCertificate()");
        Logger.LogTrace("Creating new K8SJobCertificate object");

        var jobCertObject = new K8SJobCertificate();

        var pKeyPassword = config.JobCertificate.PrivateKeyPassword;
        Logger.LogTrace($"pKeyPassword: {pKeyPassword}");
        jobCertObject.Password = pKeyPassword;

        if (string.IsNullOrEmpty(pKeyPassword))
        {
            Logger.LogDebug($"Certificate {jobCertObject.CertThumbprint} does not have a password");
            Logger.LogTrace("Attempting to create certificate without password");
            var x509 = new X509Certificate2(config.JobCertificate.Contents);
            Logger.LogTrace("Created certificate without password");

            Logger.LogDebug($"Attempting to export certificate obj {jobCertObject.CertThumbprint} to raw data");
            var rawData = x509.Export(X509ContentType.Cert);
            Logger.LogTrace($"Exported certificate obj to raw data {rawData}");
            
            Logger.LogDebug("Attempting to create PEM formatted string from raw data");
            var pemCert = "-----BEGIN CERTIFICATE-----\n" +
                          Convert.ToBase64String(rawData, Base64FormattingOptions.InsertLineBreaks) +
                          "\n-----END CERTIFICATE-----";
            Logger.LogTrace($"Created PEM formatted string from raw data\n{pemCert}");

            // CA certificate, put contents directly in PEM armor
            jobCertObject.CertPEM = pemCert;
            jobCertObject.Certb64 = config.JobCertificate.Contents;
            jobCertObject.PrivateKeyB64 = "";
            jobCertObject.PrivateKeyPEM = "";
            jobCertObject.PrivateKeyBytes = null;
            jobCertObject.CertThumbprint = x509.Thumbprint;
        }
        else
        {
            // App or Controller certificate, process with X509Certificate2 and Private Key Converter
            Logger.LogDebug($"Certificate {jobCertObject.CertThumbprint} does have a password");
            Logger.LogTrace("Attempting to create certificate with password");
            byte[] certBytes = Convert.FromBase64String(config.JobCertificate.Contents);
            Logger.LogTrace("Created certificate with password");

            Logger.LogDebug($"Attempting to export certificate obj {jobCertObject.CertThumbprint} to raw data");
            var x509 = new X509Certificate2(certBytes, pKeyPassword);
            
            Logger.LogDebug($"Attempting to export certificate obj {jobCertObject.CertThumbprint} to raw data");
            var rawData = x509.Export(X509ContentType.Cert);
            Logger.LogTrace($"Exported certificate obj to raw data {rawData}");
            
            Logger.LogDebug("Attempting to create PEM formatted string from raw data for " + jobCertObject.CertThumbprint);
            var pemCert = "-----BEGIN CERTIFICATE-----\n" +
                          Convert.ToBase64String(rawData, Base64FormattingOptions.InsertLineBreaks) +
                          "\n-----END CERTIFICATE-----";
            Logger.LogTrace($"Created PEM formatted string from raw data\n{pemCert}");
            
            Logger.LogDebug("Attempting to create PrivateKeyConverter object from PKCS12 for " + jobCertObject.CertThumbprint);
            PrivateKeyConverter pkey = PrivateKeyConverterFactory.FromPKCS12(certBytes, pKeyPassword);
            Logger.LogDebug($"Attempting to create PEM formatted string from PrivateKeyConverter object for {jobCertObject.CertThumbprint}");
            var certB64 = Convert.ToBase64String(x509.RawData);
            
            jobCertObject.CertPEM = pemCert;
            jobCertObject.Certb64 = certB64;
            jobCertObject.CertBytes = x509.RawData;
            jobCertObject.CertThumbprint = x509.Thumbprint;

            // check type of key
            string keyType;
            Logger.LogTrace("Checking type of private key");
            using (AsymmetricAlgorithm keyAlg = x509.GetRSAPublicKey())
            {
                keyType = keyAlg != null ? "RSA" : "EC";
            }
            Logger.LogTrace("Private key type is " + keyType);
            Logger.LogDebug($"Attempting to export private key for {jobCertObject.CertThumbprint} to PKCS8 blob");
            var pKeyB64 = Convert.ToBase64String(pkey.ToPkcs8BlobUnencrypted(), Base64FormattingOptions.InsertLineBreaks);
            jobCertObject.PrivateKeyPEM = $"-----BEGIN {keyType} PRIVATE KEY-----\n{pKeyB64}\n-----END {keyType} PRIVATE KEY-----";
            jobCertObject.PrivateKeyB64 = pKeyB64;
            Logger.LogTrace("Private key exported to PKCS8 blob");

        }

        // Get type of config
        Logger.LogTrace("Exiting InitJobCertificate()");
        return jobCertObject;
    }

    public string resolveStorePath(string spath)
    {
        Logger.LogTrace("Entered resolveStorePath()");
        Logger.LogTrace("Passed Store Path: " + spath);

        Logger.LogTrace("Attempting to split storepath by '/'");
        var sPathParts = spath.Split("/");
        Logger.LogTrace("Split count: " + sPathParts.Length);

        switch (sPathParts.Length)
        {
            case 1:
                Logger.LogTrace("Store path is 1 part assuming that it is the secret name");
                if (string.IsNullOrEmpty(KubeSecretName))
                {
                    Logger.LogTrace("No KubeSecretName set. Setting KubeSecretName to store path.");
                    KubeSecretName = sPathParts[0];
                }
                break;
            case 2:
                Logger.LogTrace("Store path is 2 parts assuming that it is the namespace/secret name");
                var kNs = sPathParts[0];
                var kSn = sPathParts[1];
                if (string.IsNullOrEmpty(KubeNamespace))
                {
                    Logger.LogTrace("No KubeNamespace set. Setting KubeNamespace to store path.");
                    KubeNamespace = kNs;
                }
                if (string.IsNullOrEmpty(KubeSecretName))
                {
                    Logger.LogTrace("No KubeSecretName set. Setting KubeSecretName to store path.");
                    KubeSecretName = kSn;
                }
                break;
            case 3:
                Logger.LogTrace("Store path is 3 parts assuming that it is the cluster/namespace/secret name");
                var kH = sPathParts[0];
                var kN = sPathParts[1];
                var kS = sPathParts[2];
                if (kN == "secret" || kN == "tls" || kN == "certificate")
                {
                    Logger.LogTrace("Store path is 3 parts and the second part is a secret type. Assuming that it is the namespace/secret name");
                    kN = sPathParts[0];
                    kS = sPathParts[1];
                }
                if (string.IsNullOrEmpty(KubeNamespace))
                {
                    Logger.LogTrace("No KubeNamespace set. Setting KubeNamespace to store path.");
                    KubeNamespace = kN;
                }
                if (string.IsNullOrEmpty(KubeSecretName))
                {
                    Logger.LogTrace("No KubeSecretName set. Setting KubeSecretName to store path.");
                    KubeSecretName = kS;
                }
                break;
            case 4:
                Logger.LogTrace("Store path is 4 parts assuming that it is the cluster/namespace/secret type/secret name");
                var kHN = sPathParts[0];
                var kNN = sPathParts[1];
                var kST = sPathParts[2];
                var kSN = sPathParts[3];
                if (string.IsNullOrEmpty(KubeNamespace))
                {
                    Logger.LogTrace("No KubeNamespace set. Setting KubeNamespace to store path.");
                    KubeNamespace = kNN;
                }
                if (string.IsNullOrEmpty(KubeSecretName))
                {
                    Logger.LogTrace("No KubeSecretName set. Setting KubeSecretName to store path.");
                    KubeSecretName = kSN;
                }
                break;
            default:
                Logger.LogWarning("Unable to resolve store path. Please check the store path and try again.");
                break;
        }
        return GetStorePath();
    }

    private void InitializeProperties(dynamic storeProperties)
    {
        Logger.LogTrace("Entered InitializeProperties()");
        if (storeProperties == null)
            throw new ConfigurationException(
                $"Invalid configuration. Please provide {RequiredProperties}. Or review the documentation at https://github.com/Keyfactor/kubernetes-orchestrator#custom-fields-tab.");

        // check if key is present and set values if not

        try
        {
            Logger.LogDebug("Setting K8S values from store properties.");
            KubeNamespace = storeProperties["KubeNamespace"];
            KubeSecretName = storeProperties["KubeSecretName"];
            KubeSecretType = storeProperties["KubeSecretType"];
            KubeSvcCreds = storeProperties["KubeSvcCreds"];
        }
        catch (Exception)
        {
            Logger.LogError("Unknown error while parsing store properties.");
            Logger.LogWarning("Setting KubeSecretType and KubeSvcCreds to empty strings.");
            KubeSecretType = "";
            KubeSvcCreds = "";
        }

        //check if storeProperties contains ServerUsername key

        if (string.IsNullOrEmpty(ServerUsername))
        {
            // check if storeProperties contains ServerUsername ke
            Logger.LogDebug("ServerUsername is empty.");
            try
            {
                Logger.LogDebug("Attempting to resolve ServerUsername from store properties or PAM provider. Defaults to 'kubeconfig'.");
                ServerUsername = storeProperties.ContainsKey("ServerUsername") && string.IsNullOrEmpty(storeProperties["ServerUsername"])
                    ? (string)ResolvePamField("ServerUsername", storeProperties["ServerUsername"])
                    : "kubeconfig";
            }
            catch (Exception)
            {
                ServerUsername = "kubeconfig";
            }
            Logger.LogTrace("ServerUsername: " + ServerUsername);
        }
        if (string.IsNullOrEmpty(ServerPassword))
        {
            Logger.LogDebug("ServerPassword is empty.");
            try
            {
                Logger.LogDebug("Attempting to resolve ServerPassword from store properties or PAM provider.");
                ServerPassword = storeProperties.ContainsKey("ServerPassword") ? (string)ResolvePamField("ServerPassword", storeProperties["ServerPassword"]) : "";
                if (string.IsNullOrEmpty(ServerPassword))
                {
                    ServerPassword = (string)ResolvePamField("ServerPassword", storeProperties["ServerPassword"]);
                }
                // Logger.LogTrace("ServerPassword: " + ServerPassword);
            }
            catch (Exception e)
            {
                Logger.LogError("Unable to resolve ServerPassword from store properties or PAM provider, defaulting to empty string.");
                ServerPassword = "";
                Logger.LogError(e.Message);
                Logger.LogTrace(e.ToString());
                Logger.LogTrace(e.StackTrace);
                throw new ConfigurationException("Invalid configuration. ServerPassword not provided or is invalid.");
            }

        }
        // var storePassword = ResolvePamField("Store Password", storeProperties.CertificateStoreDetails.StorePassword);

        // if (storePassword != null)
        // {
        //     Logger.LogWarning($"Store password provided but is not supported by store type {storeProperties.Capability}).");
        // }

        if (ServerUsername == "kubeconfig" || string.IsNullOrEmpty(ServerUsername))
        {
            Logger.LogInformation("Using kubeconfig provided by 'Server Password' field");
            storeProperties["KubeSvcCreds"] = ServerPassword;
            KubeSvcCreds = ServerPassword;
            // logger.LogTrace($"KubeSvcCreds: {localCertStore.KubeSvcCreds}"); //Do not log passwords
        }

        // if (string.IsNullOrEmpty(KubeSvcCreds))
        // {
        //     const string credsErr =
        //         "No credentials provided to connect to Kubernetes. Please provide a kubeconfig file. See https://github.com/Keyfactor/kubernetes-orchestrator/blob/main/scripts/kubernetes/get_service_account_creds.sh";
        //     Logger.LogError(credsErr);
        //     throw new AuthenticationException(credsErr);
        // }

        KubeClient = new KubeCertificateManagerClient(KubeSvcCreds);

        KubeHost = KubeClient.GetHost();
        KubeCluster = KubeClient.GetClusterName();

        if (string.IsNullOrEmpty(KubeSecretName) && !string.IsNullOrEmpty(StorePath))
        {
            Logger.LogDebug("KubeSecretName is empty. Attempting to set KubeSecretName from StorePath.");
            resolveStorePath(StorePath);
        }

        if (string.IsNullOrEmpty(KubeNamespace) && !string.IsNullOrEmpty(StorePath))
        {
            Logger.LogDebug("KubeNamespace is empty. Attempting to set KubeNamespace from StorePath.");
            resolveStorePath(StorePath);
        }

        if (string.IsNullOrEmpty(KubeNamespace))
        {
            Logger.LogDebug("KubeNamespace is empty. Setting KubeNamespace to 'default'.");
            KubeNamespace = "default";
        }

        Logger.LogDebug($"KubeNamespace: {KubeNamespace}");
        Logger.LogDebug($"KubeSecretName: {KubeSecretName}");
        Logger.LogDebug($"KubeSecretType: {KubeSecretType}");

        if (string.IsNullOrEmpty(KubeSecretName))
        {
            // KubeSecretName = StorePath.Split("/").Last();
            Logger.LogWarning("KubeSecretName is empty. Setting KubeSecretName to StorePath.");
            KubeSecretName = StorePath;
            Logger.LogTrace("KubeSecretName: " + KubeSecretName);
        }

    }

    public string GetStorePath()
    {
        Logger.LogTrace("Entered GetStorePath()");
        try
        {
            var secretType = KubeSecretType.ToLower();
            Logger.LogTrace("secretType: " + secretType);
            Logger.LogTrace("Entered switch statement based on secretType.");
            switch (secretType)
            {
                case "secret":
                case "opaque":
                case "tls":
                case "tls_secret":
                    Logger.LogDebug("Kubernetes secret resource type. Setting secretType to 'secret'.");
                    secretType = "secret";
                    break;
                case "cert":
                case "certs":
                case "certificate":
                case "certificates":
                    Logger.LogDebug("Kubernetes certificate resource type. Setting secretType to 'certificate'.");
                    secretType = "certificate";
                    break;
                default:
                    Logger.LogWarning("Unknown secret type. Will use value provided.");
                    Logger.LogTrace($"secretType: {secretType}");
                    break;
            }

            Logger.LogTrace("Building StorePath.");
            var storePath = $"{KubeClient.GetClusterName()}/{KubeNamespace}/{secretType}/{KubeSecretName}";
            Logger.LogDebug("Returning StorePath: " + storePath);
            return storePath;
        }
        catch (Exception e)
        {
            Logger.LogError("Unknown error constructing canonical store path.");
            return StorePath;
        }

    }

    protected string ResolvePamField(string name, string value)
    {
        Logger.LogTrace($"Attempting to resolved PAM eligible field {name}");
        return Resolver.Resolve(name);
    }

    protected byte[] GetKeyBytes(X509Certificate2 certObj, string certPassword = null)
    {
        Logger.LogTrace("Entered GetKeyBytes()");
        Logger.LogTrace("Key algo: " + certObj.GetKeyAlgorithm());
        Logger.LogTrace("Has private key: " + certObj.HasPrivateKey);
        Logger.LogTrace("Pub key: " + certObj.GetPublicKey());

        byte[] keyBytes;

        try
        {
            switch (certObj.GetKeyAlgorithm())
            {
                case "RSA":
                    Logger.LogDebug("Attempting to export private key as RSA");
                    Logger.LogTrace("GetRSAPrivateKey().ExportRSAPrivateKey(): ");
                    keyBytes = certObj.GetRSAPrivateKey()?.ExportRSAPrivateKey();
                    Logger.LogTrace("ExportPkcs8PrivateKey(): completed");
                    break;
                case "ECDSA":
                    Logger.LogDebug("Attempting to export private key as ECDSA");
                    Logger.LogTrace("GetECDsaPrivateKey().ExportECPrivateKey(): ");
                    keyBytes = certObj.GetECDsaPrivateKey()?.ExportECPrivateKey();
                    Logger.LogTrace("GetECDsaPrivateKey().ExportPkcs8PrivateKey(): completed");
                    break;
                case "DSA":
                    Logger.LogDebug("Attempting to export private key as DSA");
                    Logger.LogTrace("GetDSAPrivateKey().ExportPkcs8PrivateKey(): ");
                    keyBytes = certObj.GetDSAPrivateKey()?.ExportPkcs8PrivateKey();
                    Logger.LogTrace("GetDSAPrivateKey().ExportPkcs8PrivateKey(): completed");
                    break;
                default:
                    Logger.LogWarning("Unknown key algorithm. Attempting to export as PKCS12.");
                    Logger.LogTrace("Export(X509ContentType.Pkcs12, certPassword)");
                    keyBytes = certObj.Export(X509ContentType.Pkcs12, certPassword);
                    Logger.LogTrace("Export(X509ContentType.Pkcs12, certPassword) complete");
                    break;
            }
            if (keyBytes != null) return keyBytes;

            Logger.LogError("Key bytes are null. This is unexpected.");
            throw new Exception("Key bytes are null. This is unexpected.");

            return keyBytes;
        }
        catch (Exception e)
        {
            Logger.LogError("Unknown error getting key bytes, but we're going to try a different method.");
            Logger.LogError(e.Message);
            Logger.LogTrace(e.ToString());
            Logger.LogTrace(e.StackTrace);
            try
            {
                if (certObj.HasPrivateKey)
                {
                    try
                    {
                        Logger.LogDebug("Attempting to export private key as PKCS8.");
                        Logger.LogTrace("ExportPkcs8PrivateKey()");
                        keyBytes = certObj.PrivateKey.ExportPkcs8PrivateKey();
                        Logger.LogTrace("ExportPkcs8PrivateKey() complete");
                        // Logger.LogTrace("keyBytes: " + keyBytes);
                        // Logger.LogTrace("Converted to string: " + Encoding.UTF8.GetString(keyBytes));
                        return keyBytes;
                    }
                    catch (Exception e2)
                    {
                        Logger.LogError("Unknown error exporting private key as PKCS8, but we're going to try a a final method .");
                        Logger.LogError(e2.Message);
                        Logger.LogTrace(e2.ToString());
                        Logger.LogTrace(e2.StackTrace);
                        //attempt to export encrypted pkcs8
                        Logger.LogDebug("Attempting to export encrypted PKCS8 private key.");
                        Logger.LogTrace("ExportEncryptedPkcs8PrivateKey()");
                        keyBytes = certObj.PrivateKey.ExportEncryptedPkcs8PrivateKey(certPassword,
                            new PbeParameters(
                                PbeEncryptionAlgorithm.Aes128Cbc,
                                HashAlgorithmName.SHA256,
                                1));
                        Logger.LogTrace("ExportEncryptedPkcs8PrivateKey() complete");
                        return keyBytes;
                    }

                }
            }
            catch (Exception ie)
            {
                Logger.LogError("Unknown error exporting private key as PKCS8, returning null.");
                Logger.LogError(ie.Message);
                Logger.LogTrace(ie.ToString());
                Logger.LogTrace(ie.StackTrace);
            }
            return new byte[] { };
        }
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
        Logger.LogTrace("Entered ParseJobPrivateKey()");
        if (string.IsNullOrWhiteSpace(config.JobCertificate.Alias)) Logger.LogTrace("No Alias Found");

        // Load PFX
        Logger.LogTrace("Loading PFX...");
        var pfxBytes = Convert.FromBase64String(config.JobCertificate.Contents);
        Logger.LogTrace("Loaded PFX...");
        Pkcs12Store p;

        Logger.LogTrace("Creating Pkcs12Store...");
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

        Logger.LogTrace("Creating MemoryStream...");
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

                Logger.LogTrace("Creating AsymmetricCipherKeyPair...");
                var keyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);

                Logger.LogTrace("Writing Private Key to PEM...");
                pemWriter.WriteObject(keyPair.Private);

                Logger.LogTrace("Flush and Close PEM...");
                streamWriter.Flush();

                Logger.LogTrace("Get Private Key String...");
                privateKeyString = Encoding.ASCII.GetString(memoryStream.GetBuffer()).Trim()
                    .Replace("\r", "").Replace("\0", "");
                // Logger.LogTrace($"Got Private Key String {privateKeyString}");

                Logger.LogTrace("Close MemoryStream...");
                memoryStream.Close();

                Logger.LogTrace("Close StreamWriter...");
                streamWriter.Close();
                Logger.LogTrace("Finished Extracting Private Key...");
                // Logger.LogTrace("privateKeyString: " + privateKeyString);
                return privateKeyString;
            }
        }
    }
}
