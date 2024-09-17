// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Common.Logging;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.PKI.Extensions;
using Keyfactor.PKI.PrivateKeys;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using PemWriter = Org.BouncyCastle.OpenSsl.PemWriter;

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

    public string CertB64 { get; set; } = "";

    public string CertPem { get; set; } = "";

    public string CertThumbprint { get; set; } = "";

    public byte[] CertBytes { get; set; }

    public string PrivateKeyPem { get; set; } = "";

    public byte[] PrivateKeyBytes { get; set; }

    public string Password { get; set; } = "";

    public bool PasswordIsK8SSecret { get; set; } = false;

    public string StorePassword { get; set; } = "";

    public string StorePasswordPath { get; set; } = "";

    public bool HasPrivateKey { get; set; } = false;

    public bool HasPassword { get; set; } = false;

    public X509CertificateEntry CertificateEntry { get; set; }

    public X509CertificateEntry[] CertificateEntryChain { get; set; }

    public byte[] Pkcs12 { get; set; }

    public List<string> ChainPem { get; set; }
}

public abstract class JobBase
{
    protected static readonly string[] SupportedKubeStoreTypes;

    private static readonly string[] RequiredProperties;
    private const string DefaultPFXSecretFieldName = "pfx";
    private const string DefaultJKSSecretFieldName = "jks";
    private const string DefaultPFXPasswordSecretFieldName = "password";

    protected static readonly string[] TLSAllowedKeys;
    protected static readonly string[] OpaqueAllowedKeys;
    protected static readonly string[] CertAllowedKeys;
    protected static readonly string[] Pkcs12AllowedKeys;
    protected static readonly string[] JksAllowedKeys;


    protected internal bool SeparateChain { get; set; } =
        false; //Don't arbitrarily change this to true without specifying BREAKING CHANGE in the release notes.

    protected internal bool IncludeCertChain { get; set; } =
        true; //Don't arbitrarily change this to false without specifying BREAKING CHANGE in the release notes.

    protected internal string OperationType { get; set; }
    protected internal bool SkipTlsValidation { get; set; } = false;

    protected const string CertChainSeparator = ",";

    protected KubeCertificateManagerClient KubeClient;

    protected ILogger Logger;

    static JobBase()
    {
        CertAllowedKeys = new[] { "cert", "csr" };
        TLSAllowedKeys = new[] { "tls.crt", "tls.key", "ca.crt" };
        OpaqueAllowedKeys = new[]
            { "tls.crt", "tls.crts", "cert", "certs", "certificate", "certificates", "crt", "crts", "ca.crt" };
        SupportedKubeStoreTypes = new[] { "secret", "certificate" };
        RequiredProperties = new[] { "KubeNamespace", "KubeSecretName", "KubeSecretType" };
        Pkcs12AllowedKeys = new[] { "p12", "pkcs12", "pfx" };
        JksAllowedKeys = new[] { "jks" };
    }

    public K8SJobCertificate K8SCertificate { get; set; }

    protected internal string Capability { get; set; }

    protected IPAMSecretResolver _resolver;

    public string StorePath { get; set; }

    protected internal string KubeNamespace { get; set; }

    protected internal string KubeSecretName { get; set; }

    protected internal string KubeSecretType { get; set; }

    protected internal string KubeSvcCreds { get; set; }

    protected internal string KubeHost { get; set; }

    protected internal string CertificateDataFieldName { get; set; }

    protected internal string PasswordFieldName { get; set; }

    protected internal bool PasswordIsSeparateSecret { get; set; }

    protected string StorePasswordPath { get; set; }

    private string ServerUsername { get; set; }

    protected string ServerPassword { get; set; }

    protected string StorePassword { get; set; }

    protected bool Overwrite { get; set; }

    protected internal virtual AsymmetricKeyEntry KeyEntry { get; set; }

    protected internal ManagementJobConfiguration ManagementConfig { get; set; }

    protected internal DiscoveryJobConfiguration DiscoveryConfig { get; set; }

    protected internal InventoryJobConfiguration InventoryConfig { get; set; }

    public string ExtensionName => "K8S";

    public string KubeCluster { get; set; }

    protected void InitializeStore(InventoryJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.LogDebug("Entered InitializeStore() for INVENTORY");
        InventoryConfig = config;
        Capability = config.Capability;
        Logger.LogTrace("Capability: {Capability}", Capability);

        Logger.LogDebug("Calling JsonConvert.DeserializeObject()");
        var props = JsonConvert.DeserializeObject(config.CertificateStoreDetails.Properties);
        // Logger.LogTrace("Properties: {Properties}", props); // Commented out to avoid logging sensitive information

        ServerUsername = config.ServerUsername;
        ServerPassword = config.ServerPassword;
        StorePassword = config.CertificateStoreDetails?.StorePassword;
        StorePath = config.CertificateStoreDetails?.StorePath;
        // StorePath = GetStorePath();
        Logger.LogTrace("ServerUsername: {ServerUsername}", ServerUsername);
        // Logger.LogTrace($"ServerPassword: {ServerPassword}"); // Commented out to avoid logging sensitive information
        Logger.LogTrace("StorePath: {StorePath}", StorePath);
        Logger.LogDebug("Calling InitializeProperties()");
        InitializeProperties(props);
        Logger.LogDebug("Returned from InitializeStore()");
        Logger.LogInformation(
            "Initialized Inventory Job Configuration for `{Capability}` with store path `{StorePath}`", Capability,
            StorePath);
    }

    protected void InitializeStore(DiscoveryJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.LogDebug("Entered InitializeStore() for DISCOVERY");
        DiscoveryConfig = config;
        var props = config.JobProperties;
        Capability = config.Capability;
        ServerUsername = config.ServerUsername;
        ServerPassword = config.ServerPassword;
        // check that config has UseSSL bool set
        if (config.UseSSL)
        {
            Logger.LogInformation("UseSSL is set to true, setting k8s client `SkipTlsValidation` to `false`");
            SkipTlsValidation = false;
        }
        else
        {
            Logger.LogInformation("UseSSL is set to false, setting k8s client `SkipTlsValidation` to `true`");
            SkipTlsValidation = true;
        }

        Logger.LogTrace("ServerUsername: {ServerUsername}", ServerUsername);
        Logger.LogDebug("Calling InitializeProperties()");
        InitializeProperties(props);
        Logger.LogDebug("Returned from InitializeStore()");
        Logger.LogInformation(
            "Initialized Discovery Job Configuration for `{Capability}` with store path `{StorePath}`", Capability,
            StorePath);
    }

    protected void InitializeStore(ManagementJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.LogDebug("Entered InitializeStore() for MANAGEMENT");
        ManagementConfig = config;

        Logger.LogDebug("Calling JsonConvert.DeserializeObject()");
        var props = JsonConvert.DeserializeObject(config.CertificateStoreDetails.Properties);
        Logger.LogDebug("Returned from JsonConvert.DeserializeObject()");
        Capability = config.Capability;
        ServerUsername = config.ServerUsername;
        ServerPassword = config.ServerPassword;
        StorePath = config.CertificateStoreDetails?.StorePath;

        Logger.LogTrace("ServerUsername: {ServerUsername}", ServerUsername);
        Logger.LogTrace("StorePath: {StorePath}", StorePath);

        Logger.LogDebug("Calling InitializeProperties()");
        InitializeProperties(props);
        Logger.LogDebug("Returned from InitializeProperties()");
        // StorePath = config.CertificateStoreDetails?.StorePath;
        // StorePath = GetStorePath();
        Overwrite = config.Overwrite;
        Logger.LogTrace("Overwrite: {Overwrite}", Overwrite);
        Logger.LogInformation(
            "Initialized Management Job Configuration for `{Capability}` with store path `{StorePath}`", Capability,
            StorePath);
    }

    private static string InsertLineBreaks(string input, int lineLength)
    {
        var sb = new StringBuilder();
        var i = 0;
        while (i < input.Length)
        {
            sb.Append(input.AsSpan(i, Math.Min(lineLength, input.Length - i)));
            sb.AppendLine();
            i += lineLength;
        }

        return sb.ToString();
    }


    protected K8SJobCertificate InitJobCertificate(dynamic config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.LogTrace("Entered InitJobCertificate()");

        var jobCertObject = new K8SJobCertificate();
        var pKeyPassword = config.JobCertificate.PrivateKeyPassword;
        // Logger.LogTrace($"pKeyPassword: {pKeyPassword}"); // Commented out to avoid logging sensitive information
        jobCertObject.Password = pKeyPassword;

        if (!string.IsNullOrEmpty(pKeyPassword))
        {
            Logger.LogDebug("Certificate {CertThumbprint} does not have a password", jobCertObject.CertThumbprint);
            Logger.LogTrace("Attempting to create certificate without password");
            try
            {
                Logger.LogDebug("Calling LoadPkcs12Store()");
                Pkcs12Store pkcs12Store = LoadPkcs12Store(Convert.FromBase64String(config.JobCertificate.Contents),
                    pKeyPassword);
                Logger.LogDebug("Returned from LoadPkcs12Store()");

                Logger.LogDebug("Attempting to get alias from pkcs12Store");
                var alias = pkcs12Store.Aliases.FirstOrDefault(pkcs12Store.IsKeyEntry);
                Logger.LogTrace("Alias: {Alias}", alias);

                Logger.LogTrace("Calling pkcs12Store.GetKey() with `{Alias}`", alias);
                var key = pkcs12Store.GetKey(alias);
                Logger.LogTrace("Returned from pkcs12Store.GetKey() with `{Alias}`", alias);

                //if not null then extract the private key unencrypted in PEM format
                if (key != null)
                {
                    Logger.LogDebug("Attempting to extract private key as PEM");
                    Logger.LogTrace("Calling ExtractPrivateKeyAsPem()");
                    var pKeyPem = KubeClient.ExtractPrivateKeyAsPem(pkcs12Store, pKeyPassword);
                    Logger.LogTrace("Returned from ExtractPrivateKeyAsPem()");
                    jobCertObject.PrivateKeyPem = pKeyPem;
                    // Logger.LogTrace("Private key: {PrivateKey}", jobCertObject.PrivateKeyPem); // Commented out to avoid logging sensitive information
                }

                Logger.LogDebug("Attempting to get certificate from pkcs12Store");
                Logger.LogTrace("Calling pkcs12Store.GetCertificate()");
                var x509Obj = pkcs12Store.GetCertificate(alias);
                Logger.LogTrace("Returned from pkcs12Store.GetCertificate()");

                Logger.LogDebug("Attempting to get certificate chain from pkcs12Store");
                Logger.LogTrace("Calling pkcs12Store.GetCertificateChain()");
                var chain = pkcs12Store.GetCertificateChain(alias);
                Logger.LogTrace("Returned from pkcs12Store.GetCertificateChain()");

                var chainList = chain.Select(c => KubeClient.ConvertToPem(c.Certificate)).ToList();

                jobCertObject.CertificateEntry = x509Obj;
                jobCertObject.CertificateEntryChain = chain;
                jobCertObject.CertThumbprint = x509Obj.Certificate.Thumbprint();
                jobCertObject.ChainPem = chainList;
                jobCertObject.CertPem = KubeClient.ConvertToPem(x509Obj.Certificate);
            }
            catch (Exception e)
            {
                Logger.LogError("Error parsing certificate data from pkcs12 format without password: {Error}",
                    e.Message);
                Logger.LogTrace("{Message}", e.StackTrace);
                jobCertObject.CertThumbprint = config.JobCertificate.Thumbprint;
                //todo: should this throw an exception?
            }
        }
        else
        {
            pKeyPassword = "";
            Logger.LogDebug("Certificate {CertThumbprint} does have a password", jobCertObject.CertThumbprint);
            Logger.LogTrace("Calling Convert.FromBase64String()");
            byte[] certBytes = Convert.FromBase64String(config.JobCertificate.Contents);
            Logger.LogTrace("Returned from Convert.FromBase64String()");

            if (certBytes.Length == 0)
            {
                Logger.LogError("Certificate `{CertThumbprint}` is empty, this should not happen",
                    jobCertObject.CertThumbprint);
                return jobCertObject;
            }

            Logger.LogTrace("Calling new X509Certificate2()");
            var x509 = new X509Certificate2(certBytes, pKeyPassword);
            Logger.LogTrace("Returned from new X509Certificate2()");

            Logger.LogTrace("Calling x509.Export()");
            var rawData = x509.Export(X509ContentType.Cert);
            Logger.LogTrace("Returned from x509.Export()");

            Logger.LogDebug("Attempting to export certificate `{CertThumbprint}` to PEM format",
                jobCertObject.CertThumbprint);
            //check if certBytes are null or empty
            var pemCert =
                "-----BEGIN CERTIFICATE-----\n" +
                Convert.ToBase64String(rawData, Base64FormattingOptions.InsertLineBreaks) +
                "\n-----END CERTIFICATE-----";

            jobCertObject.CertPem = pemCert;
            jobCertObject.CertBytes = x509.RawData;
            jobCertObject.CertThumbprint = x509.Thumbprint;
            jobCertObject.Pkcs12 = certBytes;

            try
            {
                Logger.LogDebug("Attempting to export private key for `{CertThumbprint}` to PKCS8",
                    jobCertObject.CertThumbprint);
                Logger.LogTrace("Calling PrivateKeyConverterFactory.FromPKCS12()");
                PrivateKeyConverter pkey = PrivateKeyConverterFactory.FromPKCS12(certBytes, pKeyPassword);
                Logger.LogTrace("Returned from PrivateKeyConverterFactory.FromPKCS12()");

                string keyType;
                Logger.LogTrace("Calling x509.GetRSAPublicKey()");
                using (AsymmetricAlgorithm keyAlg = x509.GetRSAPublicKey())
                {
                    keyType = keyAlg != null ? "RSA" : "EC";
                }

                Logger.LogTrace("Returned from x509.GetRSAPublicKey()");

                Logger.LogTrace("Private key type is {Type}", keyType);
                Logger.LogTrace("Calling pkey.ToPkcs8BlobUnencrypted()");
                var pKeyB64 = Convert.ToBase64String(pkey.ToPkcs8BlobUnencrypted(),
                    Base64FormattingOptions.InsertLineBreaks);
                Logger.LogTrace("Returned from pkey.ToPkcs8BlobUnencrypted()");

                Logger.LogDebug("Creating private key PEM for `{CertThumbprint}`", jobCertObject.CertThumbprint);
                jobCertObject.PrivateKeyPem =
                    $"-----BEGIN {keyType} PRIVATE KEY-----\n{pKeyB64}\n-----END {keyType} PRIVATE KEY-----";
                // Logger.LogTrace("Private key: {PrivateKey}", jobCertObject.PrivateKeyPem); // Commented out to avoid logging sensitive information
                Logger.LogDebug("Private key extracted for `{CertThumbprint}`", jobCertObject.CertThumbprint);
            }
            catch (ArgumentException)
            {
                Logger.LogDebug("Private key extraction failed for `{CertThumbprint}`", jobCertObject.CertThumbprint);
                var refStr = string.IsNullOrEmpty(jobCertObject.Alias)
                    ? jobCertObject.CertThumbprint
                    : jobCertObject.Alias;

                var pkeyErr = $"Unable to unpack private key from `{refStr}`, invalid password";
                Logger.LogError("{Error}", pkeyErr);
                // todo: should this throw an exception?
            }
        }

        jobCertObject.StorePassword = config.CertificateStoreDetails.StorePassword;
        Logger.LogDebug("Returning from InitJobCertificate()");
        return jobCertObject;
    }

    private static bool IsNamespaceStore(string capability)
    {
        return capability != null && string.IsNullOrEmpty(capability) &&
               capability.Contains("K8SNS", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsClusterStore(string capability)
    {
        return capability != null && string.IsNullOrEmpty(capability) &&
               capability.Contains("K8SCLUSTER", StringComparison.OrdinalIgnoreCase);
    }

    protected string ResolveStorePath(string spath)
    {
        Logger.LogDebug("Entered resolveStorePath()");
        Logger.LogTrace("Store path: {StorePath}", spath);

        Logger.LogTrace("Attempting to split store path by '/'");
        var sPathParts = spath.Split("/");
        Logger.LogTrace("Split count: {Count}", sPathParts.Length);

        switch (sPathParts.Length)
        {
            case 1 when IsNamespaceStore(Capability):
                Logger.LogInformation(
                    "Store is of type `K8SNS` and `StorePath` is length 1; setting `KubeSecretName` to empty and `KubeNamespace` to `StorePath`");

                KubeSecretName = "";
                KubeNamespace = sPathParts[0];
                break;
            case 1 when IsClusterStore(Capability):
                Logger.LogInformation(
                    "Store is of type `K8SCluster` path is 1 part and capability is cluster, assuming that store path is the cluster name and setting 'KubeSecretName' and 'KubeNamespace' equal empty");
                if (!string.IsNullOrEmpty(KubeSecretName))
                {
                    Logger.LogWarning(
                        "`KubeSecretName` is not a valid parameter for store type `K8SCluster` and will be set to empty");
                    KubeSecretName = "";
                }

                if (!string.IsNullOrEmpty(KubeNamespace))
                {
                    Logger.LogWarning(
                        "`KubeNamespace` is not a valid parameter for store type `K8SCluster` and will be set to empty");
                    KubeNamespace = "";
                }

                break;
            case 1:
                if (string.IsNullOrEmpty(KubeSecretName))
                {
                    Logger.LogInformation(
                        "`StorePath`: `{StorePath}` is 1 part, assuming that it is the k8s secret name and setting 'KubeSecretName' to `{StorePath}`",
                        sPathParts[0]);
                    KubeSecretName = sPathParts[0];
                }
                else
                {
                    Logger.LogInformation(
                        "`StorePath`: `{StorePath}` is 1 part and `KubeSecretName` is not empty, `StorePath` will be ignored",
                        spath);
                }

                break;
            case 2 when IsClusterStore(Capability):
                Logger.LogWarning("`StorePath`: `{StorePath}` is 2 parts this is not a valid combination for `K8SCluster` and will be ignored", spath);
                break;
            case 2 when IsNamespaceStore(Capability):
                var nsPrefix = sPathParts[0];
                Logger.LogTrace("nsPrefix: {NsPrefix}", nsPrefix);
                var nsName = sPathParts[1];
                Logger.LogTrace("nsName: {NsName}", nsName);
                
                Logger.LogInformation(
                    "`StorePath`: `{StorePath}` is 2 parts and store type is `K8SNS`, assuming that store path pattern is either `<cluster_name>/<namespace_name>` or `namespace/<namespace_name>`", spath);
                if (string.IsNullOrEmpty(KubeNamespace))
                {
                    Logger.LogInformation("`KubeNamespace` is empty, setting `KubeNamespace` to `{Namespace}`", nsName);
                    KubeNamespace = nsName;
                }
                else
                {
                    Logger.LogInformation("`KubeNamespace` parameter is not empty, ignoring `StorePath` value `{StorePath}`", spath);
                }
                break;
            case 2:
                Logger.LogInformation("`StorePath`: `{StorePath}` is 2 parts, assuming that store path pattern is the `<cluster>/<secret_name>` ", spath);
                var kNs = sPathParts[0];
                Logger.LogTrace("kNs: {KubeNamespace}", kNs);
                var kSn = sPathParts[1];
                Logger.LogTrace("kSn: {KubeSecretName}", kSn);
                
                if (string.IsNullOrEmpty(KubeNamespace))
                {
                    Logger.LogInformation("`KubeNamespace` is not set, setting `KubeNamespace` to `{Namespace}`", kNs);
                    KubeNamespace = kNs;
                }
                else
                {
                    Logger.LogInformation("`KubeNamespace` is set, ignoring `StorePath` value `{StorePath}`", kNs);
                }

                if (string.IsNullOrEmpty(KubeSecretName))
                {
                    Logger.LogInformation("`KubeSecretName` is not set, setting `KubeSecretName` to `{Secret}`", kSn);
                    KubeSecretName = kSn;
                }
                else
                {
                    Logger.LogInformation("`KubeSecretName` is set, ignoring `StorePath` value `{StorePath}`", kSn);
                }

                break;
            case 3 when IsClusterStore(Capability):
                Logger.LogError("`StorePath`: `{StorePath}` is 3 parts and store type is `K8SCluster`, this is not a valid combination and `StorePath` will be ignored", spath);
                break;
            case 3 when IsNamespaceStore(Capability):
                Logger.LogInformation("`StorePath`: `{StorePath}` is 3 parts and store type is `K8SNS`, assuming that store path pattern is `<cluster>/namespace/<namespace_name>`", spath);
                var nsCluster = sPathParts[0];
                Logger.LogTrace("nsCluster: {NsCluster}", nsCluster);
                var nsClarifier = sPathParts[1];
                Logger.LogTrace("nsClarifier: {NsClarifier}", nsClarifier);
                var nsName3 = sPathParts[2];
                Logger.LogTrace("nsName3: {NsName3}", nsName3);

                if (string.IsNullOrEmpty(KubeNamespace))
                {
                    Logger.LogInformation("`KubeNamespace` is not set, setting `KubeNamespace` to `{Namespace}`", nsName3);
                    KubeNamespace = nsName3;
                }
                else
                {
                    Logger.LogInformation("`KubeNamespace` is set, ignoring `StorePath` value `{StorePath}`", spath);    
                }

                if (!string.IsNullOrEmpty(KubeSecretName))
                {
                    Logger.LogWarning("`KubeSecretName` parameter is not empty, but is not supported for `K8SNS` store type and will be ignored");
                    KubeSecretName = "";
                }

                break;
            case 3:
                Logger.LogInformation("Store path is 3 parts assuming that it is the '<cluster_name>/<namespace_name>/<secret_name>`");
                var kH = sPathParts[0];
                Logger.LogTrace("kH: {KubeHost}", kH);
                var kN = sPathParts[1];
                Logger.LogTrace("kN: {KubeNamespace}", kN);
                var kS = sPathParts[2];
                Logger.LogTrace("kS: {KubeSecretName}", kS);
                
                if (kN is "secret" or "tls" or "certificate" or "namespace")
                {
                    Logger.LogInformation("Store path is 3 parts and the second part is a reserved keyword, assuming that it is the '<cluster_name>/<namespace_name>/<secret_name>'");
                    kN = sPathParts[0];
                    kS = sPathParts[1];
                }

                if (string.IsNullOrEmpty(KubeNamespace))
                {
                    Logger.LogTrace("No 'KubeNamespace' set, setting 'KubeNamespace' to store path");
                    KubeNamespace = kN;
                }

                if (string.IsNullOrEmpty(KubeSecretName))
                {
                    Logger.LogTrace("No 'KubeSecretName' set, setting 'KubeSecretName' to store path");
                    KubeSecretName = kS;
                }

                break;
            case 4 when Capability.Contains("Cluster") || Capability.Contains("NS"):
                Logger.LogError("Store path is 4 parts and capability is {Capability}. This is not a valid combination",
                    Capability);
                break;
            case 4:
                Logger.LogTrace(
                    "Store path is 4 parts assuming that it is the cluster/namespace/secret type/secret name");
                var kHN = sPathParts[0];
                var kNN = sPathParts[1];
                var kST = sPathParts[2];
                var kSN = sPathParts[3];
                if (string.IsNullOrEmpty(KubeNamespace))
                {
                    Logger.LogTrace("No 'KubeNamespace' set, setting 'KubeNamespace' to store path");
                    KubeNamespace = kNN;
                }

                if (string.IsNullOrEmpty(KubeSecretName))
                {
                    Logger.LogTrace("No 'KubeSecretName' set, setting 'KubeSecretName' to store path");
                    KubeSecretName = kSN;
                }

                break;
            default:
                Logger.LogWarning("Unable to resolve store path, please check the store path and try again");
                //todo: does anything need to be handled because of this error?                
                break;
        }

        return GetStorePath();
    }

    private void InitializeProperties(dynamic storeProperties)
    {
        Logger.LogTrace("Entered InitializeProperties()");
        if (storeProperties == null)
            throw new ConfigurationException(
                $"Invalid configuration. Please provide {RequiredProperties}. Or review the documentation at https://github.com/Keyfactor/kubernetes-orchestrator#custom-fields-tab");

        // check if key is present and set values if not
        try
        {
            Logger.LogDebug("Setting K8S values from store properties");
            KubeNamespace = storeProperties["KubeNamespace"];
            KubeSecretName = storeProperties["KubeSecretName"];
            KubeSecretType = storeProperties["KubeSecretType"];
            KubeSvcCreds = storeProperties["KubeSvcCreds"];

            // check if storeProperties contains PasswordIsSeparateSecret key and if it does, set PasswordIsSeparateSecret to the value of the key
            if (storeProperties.ContainsKey("PasswordIsSeparateSecret"))
            {
                PasswordIsSeparateSecret = storeProperties["PasswordIsSeparateSecret"];
            }
            else
            {
                Logger.LogDebug("PasswordIsSeparateSecret not found in store properties");
                PasswordIsSeparateSecret = false;
            }

            // check if storeProperties contains PasswordFieldName key and if it does, set PasswordFieldName to the value of the key
            if (storeProperties.ContainsKey("PasswordFieldName"))
            {
                PasswordFieldName = storeProperties["PasswordFieldName"];
            }
            else
            {
                Logger.LogDebug("PasswordFieldName not found in store properties");
                PasswordFieldName = "";
            }

            // check if storeProperties contains StorePasswordPath key and if it does, set StorePasswordPath to the value of the key
            if (storeProperties.ContainsKey("StorePasswordPath"))
            {
                StorePasswordPath = storeProperties["StorePasswordPath"];
            }
            else
            {
                Logger.LogDebug("StorePasswordPath not found in store properties");
                StorePasswordPath = "";
            }

            // check if storeProperties contains KubeSecretKey key and if it does, set KubeSecretKey to the value of the key
            if (storeProperties.ContainsKey("KubeSecretKey"))
            {
                CertificateDataFieldName = storeProperties["KubeSecretKey"];
            }
            else
            {
                Logger.LogDebug("KubeSecretKey not found in store properties");
                CertificateDataFieldName = "";
            }
        }
        catch (Exception)
        {
            Logger.LogError("Unknown error while parsing store properties");
            Logger.LogWarning("Setting KubeSecretType and KubeSvcCreds to empty strings");
            KubeSecretType = "";
            KubeSvcCreds = "";
        }

        //check if storeProperties contains ServerUsername key
        Logger.LogInformation("Attempting to resolve 'ServerUsername' from store properties or PAM provider");
        var pamServerUsername =
            (string)PAMUtilities.ResolvePAMField(_resolver, Logger, "ServerUsername", ServerUsername);
        if (!string.IsNullOrEmpty(pamServerUsername))
        {
            Logger.LogInformation(
                "ServerUsername resolved from PAM provider, setting 'ServerUsername' to resolved value");
            Logger.LogTrace("PAMServerUsername: {Username}", pamServerUsername);
            ServerUsername = pamServerUsername;
        }
        else
        {
            Logger.LogInformation(
                "ServerUsername not resolved from PAM provider, attempting to resolve 'Server Username' from store properties");
            pamServerUsername =
                (string)PAMUtilities.ResolvePAMField(_resolver, Logger, "Server Username", ServerUsername);
            if (!string.IsNullOrEmpty(pamServerUsername))
            {
                Logger.LogInformation(
                    "ServerUsername resolved from store properties. Setting ServerUsername to resolved value");
                Logger.LogTrace("PAMServerUsername: {Username}", pamServerUsername);
                ServerUsername = pamServerUsername;
            }
        }

        if (string.IsNullOrEmpty(ServerUsername))
        {
            Logger.LogInformation("ServerUsername is empty, setting 'ServerUsername' to default value: 'kubeconfig'");
            ServerUsername = "kubeconfig";
        }

        // Check if ServerPassword is empty and resolve from store properties or PAM provider
        try
        {
            Logger.LogInformation("Attempting to resolve 'ServerPassword' from store properties or PAM provider");
            var pamServerPassword =
                (string)PAMUtilities.ResolvePAMField(_resolver, Logger, "ServerPassword", ServerPassword);
            if (!string.IsNullOrEmpty(pamServerPassword))
            {
                Logger.LogInformation(
                    "ServerPassword resolved from PAM provider, setting 'ServerPassword' to resolved value");
                // Logger.LogTrace("PAMServerPassword: " + pamServerPassword);
                ServerPassword = pamServerPassword;
            }
            else
            {
                Logger.LogInformation(
                    "ServerPassword not resolved from PAM provider, attempting to resolve 'Server Password' from store properties");
                pamServerPassword =
                    (string)PAMUtilities.ResolvePAMField(_resolver, Logger, "Server Password", ServerPassword);
                if (!string.IsNullOrEmpty(pamServerPassword))
                {
                    Logger.LogInformation(
                        "ServerPassword resolved from store properties, setting 'ServerPassword' to resolved value");
                    // Logger.LogTrace("PAMServerPassword: " + pamServerPassword);
                    ServerPassword = pamServerPassword;
                }
            }
        }
        catch (Exception e)
        {
            Logger.LogError(
                "Unable to resolve 'ServerPassword' from store properties or PAM provider, defaulting to empty string");
            ServerPassword = "";
            Logger.LogError("{Message}", e.Message);
            Logger.LogTrace("{Message}", e.ToString());
            Logger.LogTrace("{Trace}", e.StackTrace);
            // throw new ConfigurationException("Invalid configuration. ServerPassword not provided or is invalid");
        }

        try
        {
            Logger.LogInformation("Attempting to resolve 'StorePassword' from store properties or PAM provider");
            var pamStorePassword =
                (string)PAMUtilities.ResolvePAMField(_resolver, Logger, "StorePassword", StorePassword);
            if (!string.IsNullOrEmpty(pamStorePassword))
            {
                Logger.LogInformation(
                    "StorePassword resolved from PAM provider, setting 'StorePassword' to resolved value");
                StorePassword = pamStorePassword;
            }
            else
            {
                Logger.LogInformation(
                    "StorePassword not resolved from PAM provider, attempting to resolve 'Store Password' from store properties");
                pamStorePassword =
                    (string)PAMUtilities.ResolvePAMField(_resolver, Logger, "Store Password", StorePassword);
                if (!string.IsNullOrEmpty(pamStorePassword))
                {
                    Logger.LogInformation(
                        "StorePassword resolved from store properties, setting 'StorePassword' to resolved value");
                    StorePassword = pamStorePassword;
                }
            }
        }
        catch (Exception e)
        {
            Logger.LogError(
                "Unable to resolve 'StorePassword' from store properties or PAM provider, defaulting to empty string");
            StorePassword = "";
            Logger.LogError("{Message}", e.Message);
            Logger.LogTrace("{Message}", e.ToString());
            Logger.LogTrace("{Trace}", e.StackTrace);
            // throw new ConfigurationException("Invalid configuration. StorePassword not provided or is invalid");
        }

        if (ServerUsername == "kubeconfig" || string.IsNullOrEmpty(ServerUsername))
        {
            Logger.LogInformation("Using kubeconfig provided by 'Server Password' field");
            storeProperties["KubeSvcCreds"] = ServerPassword;
            KubeSvcCreds = ServerPassword;
        }

        if (string.IsNullOrEmpty(KubeSvcCreds))
        {
            const string credsErr =
                "No credentials provided to connect to Kubernetes. Please provide a kubeconfig file. See https://github.com/Keyfactor/kubernetes-orchestrator/blob/main/scripts/kubernetes/get_service_account_creds.sh";
            Logger.LogError(credsErr);
            throw new ConfigurationException(credsErr);
        }

        switch (KubeSecretType)
        {
            case "pfx":
            case "p12":
            case "pkcs12":
                Logger.LogInformation(
                    "Kubernetes certificate store type is 'pfx'. Setting default values for 'PasswordFieldName' and 'CertificateDataFieldName'");
                PasswordFieldName = storeProperties.ContainsKey("PasswordFieldName")
                    ? storeProperties["PasswordFieldName"]
                    : DefaultPFXPasswordSecretFieldName;
                PasswordIsSeparateSecret = storeProperties.ContainsKey("PasswordIsSeparateSecret")
                    ? storeProperties["PasswordIsSeparateSecret"]
                    : false;
                StorePasswordPath = storeProperties.ContainsKey("StorePasswordPath")
                    ? storeProperties["StorePasswordPath"]
                    : "";
                PasswordIsK8SSecret = storeProperties.ContainsKey("PasswordIsK8SSecret")
                    ? storeProperties["PasswordIsK8SSecret"]
                    : false;
                KubeSecretPassword = storeProperties.ContainsKey("KubeSecretPassword")
                    ? storeProperties["KubeSecretPassword"]
                    : "";
                CertificateDataFieldName = storeProperties.ContainsKey("CertificateDataFieldName")
                    ? storeProperties["CertificateDataFieldName"]
                    : DefaultPFXSecretFieldName;
                break;
            case "jks":
                Logger.LogInformation(
                    "Kubernetes certificate store type is 'jks'. Setting default values for 'PasswordFieldName' and 'CertificateDataFieldName'");
                PasswordFieldName = storeProperties.ContainsKey("PasswordFieldName")
                    ? storeProperties["PasswordFieldName"]
                    : DefaultPFXPasswordSecretFieldName;
                PasswordIsSeparateSecret = storeProperties.ContainsKey("PasswordIsSeparateSecret")
                    ? bool.Parse(storeProperties["PasswordIsSeparateSecret"])
                    : false;
                StorePasswordPath = storeProperties.ContainsKey("StorePasswordPath")
                    ? storeProperties["StorePasswordPath"]
                    : "";
                PasswordIsK8SSecret = storeProperties.ContainsKey("PasswordIsK8SSecret")
                    ? storeProperties["PasswordIsK8SSecret"]
                    : false;
                KubeSecretPassword = storeProperties.ContainsKey("KubeSecretPassword")
                    ? storeProperties["KubeSecretPassword"]
                    : "";
                CertificateDataFieldName = storeProperties.ContainsKey("CertificateDataFieldName")
                    ? storeProperties["CertificateDataFieldName"]
                    : DefaultJKSSecretFieldName;
                break;
        }

        Logger.LogTrace("Creating new KubeCertificateManagerClient object");
        KubeClient = new KubeCertificateManagerClient(KubeSvcCreds);
        
        Logger.LogTrace("Getting KubeHost and KubeCluster from KubeClient");
        KubeHost = KubeClient.GetHost();
        Logger.LogTrace("KubeHost: {KubeHost}", KubeHost);
        
        Logger.LogTrace("Getting cluster name from KubeClient");
        KubeCluster = KubeClient.GetClusterName();
        Logger.LogTrace("KubeCluster: {KubeCluster}", KubeCluster);

        if (string.IsNullOrEmpty(KubeSecretName) && !string.IsNullOrEmpty(StorePath) && !Capability.Contains("NS") &&
            !Capability.Contains("Cluster"))
        {
            Logger.LogDebug("KubeSecretName is empty, attempting to set 'KubeSecretName' from StorePath");
            ResolveStorePath(StorePath);
        }

        if (string.IsNullOrEmpty(KubeNamespace) && !string.IsNullOrEmpty(StorePath))
        {
            Logger.LogDebug("KubeNamespace is empty, attempting to set 'KubeNamespace' from StorePath");
            ResolveStorePath(StorePath);
        }

        if (string.IsNullOrEmpty(KubeNamespace))
        {
            Logger.LogDebug("KubeNamespace is empty, setting 'KubeNamespace' to 'default'");
            KubeNamespace = "default";
        }

        Logger.LogDebug("KubeNamespace: {KubeNamespace}", KubeNamespace);
        Logger.LogDebug("KubeSecretName: {KubeSecretName}", KubeSecretName);
        Logger.LogDebug("KubeSecretType: {KubeSecretType}", KubeSecretName);

        if (!string.IsNullOrEmpty(KubeSecretName)) return;
        // KubeSecretName = StorePath.Split("/").Last();
        Logger.LogWarning("KubeSecretName is empty, setting 'KubeSecretName' to StorePath");
        KubeSecretName = StorePath;
        Logger.LogTrace("KubeSecretName: {KubeSecretName}", KubeSecretName);
    }

    public bool PasswordIsK8SSecret { get; set; } = false;

    public object KubeSecretPassword { get; set; }

    public string GetStorePath()
    {
        Logger.LogTrace("Entered GetStorePath()");
        try
        {
            var secretType = "";
            var storePath = StorePath;


            if (Capability.Contains("K8SNS"))
            {
                secretType = "namespace";
            }
            else if (Capability.Contains("K8SCluster"))
            {
                secretType = "cluster";
            }
            else
            {
                secretType = KubeSecretType.ToLower();
            }

            Logger.LogTrace("secretType: {SecretType}", secretType);
            Logger.LogTrace("Entered switch statement based on secretType");
            switch (secretType)
            {
                case "secret":
                case "opaque":
                case "tls":
                case "tls_secret":
                    Logger.LogDebug("Kubernetes secret resource type, setting secretType to 'secret'");
                    secretType = "secret";
                    break;
                case "cert":
                case "certs":
                case "certificate":
                case "certificates":
                    Logger.LogDebug("Kubernetes certificate resource type, setting secretType to 'certificate'");
                    secretType = "certificate";
                    break;
                case "namespace":
                    Logger.LogDebug("Kubernetes namespace resource type, setting secretType to 'namespace'");
                    KubeSecretType = "namespace";

                    Logger.LogDebug(
                        "Setting store path to 'cluster/namespace/namespacename' for 'namespace' secret type");
                    storePath = $"{KubeClient.GetClusterName()}/namespace/{KubeNamespace}";
                    Logger.LogDebug("Returning storePath: {StorePath}", storePath);
                    return storePath;
                case "cluster":
                    Logger.LogDebug("Kubernetes cluster resource type, setting secretType to 'cluster'");
                    KubeSecretType = "cluster";
                    Logger.LogDebug("Returning storePath: {StorePath}", storePath);
                    return storePath;
                default:
                    Logger.LogWarning("Unknown secret type '{SecretType}' will use value provided", secretType);
                    Logger.LogTrace("secretType: {SecretType}", secretType);
                    break;
            }

            Logger.LogDebug("Building StorePath");
            storePath = $"{KubeClient.GetClusterName()}/{KubeNamespace}/{secretType}/{KubeSecretName}";
            Logger.LogDebug("Returning storePath: {StorePath}", storePath);
            return storePath;
        }
        catch (Exception e)
        {
            Logger.LogError("Unknown error constructing canonical store path {Error}", e.Message);
            return StorePath;
        }

    }

    protected string ResolvePamField(string name, string value)
    {
        try
        {
            Logger.LogTrace($"Attempting to resolved PAM eligible field {name}");
            return Resolver.Resolve(value);
        }
        catch (Exception e)
        {
            Logger.LogError($"Unable to resolve PAM field {name}. Returning original value.");
            Logger.LogError(e.Message);
            Logger.LogTrace(e.ToString());
            Logger.LogTrace(e.StackTrace);
            return value;
        }

    }

    protected byte[] GetKeyBytes(X509Certificate2 certObj, string certPassword = null)
    {
        Logger.LogDebug("Entered GetKeyBytes()");
        Logger.LogTrace("Key algo: {KeyAlgo}", certObj.GetKeyAlgorithm());
        Logger.LogTrace("Has private key: {HasPrivateKey}", certObj.HasPrivateKey);
        Logger.LogTrace("Pub key: {PublicKey}", certObj.GetPublicKey());

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
                    Logger.LogWarning("Unknown key algorithm, attempting to export as PKCS12");
                    Logger.LogTrace("Export(X509ContentType.Pkcs12, certPassword)");
                    keyBytes = certObj.Export(X509ContentType.Pkcs12, certPassword);
                    Logger.LogTrace("Export(X509ContentType.Pkcs12, certPassword) complete");
                    break;
            }

            if (keyBytes != null) return keyBytes;

            Logger.LogError("Unable to parse private key");

            throw new InvalidKeyException($"Unable to parse private key from certificate '{certObj.Thumbprint}'");
        }
        catch (Exception e)
        {
            Logger.LogError("Unknown error getting key bytes, but we're going to try a different method");
            Logger.LogError("{Message}", e.Message);
            Logger.LogTrace("{Message}", e.ToString());
            Logger.LogTrace("{Trace}", e.StackTrace);
            try
            {
                if (certObj.HasPrivateKey)
                {
                    try
                    {
                        Logger.LogDebug("Attempting to export private key as PKCS8");
                        Logger.LogTrace("ExportPkcs8PrivateKey()");
                        keyBytes = certObj.PrivateKey.ExportPkcs8PrivateKey();
                        Logger.LogTrace("ExportPkcs8PrivateKey() complete");
                        // Logger.LogTrace("keyBytes: " + keyBytes);
                        // Logger.LogTrace("Converted to string: " + Encoding.UTF8.GetString(keyBytes));
                        return keyBytes;
                    }
                    catch (Exception e2)
                    {
                        Logger.LogError(
                            "Unknown error exporting private key as PKCS8, but we're going to try a a final method ");
                        Logger.LogError(e2.Message);
                        Logger.LogTrace(e2.ToString());
                        Logger.LogTrace(e2.StackTrace);
                        //attempt to export encrypted pkcs8
                        Logger.LogDebug("Attempting to export encrypted PKCS8 private key");
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
                Logger.LogError("Unknown error exporting private key as PKCS8, returning null");
                Logger.LogError("{Message}", ie.Message);
                Logger.LogTrace("{Message}", ie.ToString());
                Logger.LogTrace("{Trace}", ie.StackTrace);
            }

            return Array.Empty<byte>();
        }
    }

    protected static JobResult FailJob(string message, long jobHistoryId)
    {
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Failure,
            JobHistoryId = jobHistoryId,
            FailureMessage = message
        };
    }

    protected static JobResult SuccessJob(long jobHistoryId, string jobMessage = null)
    {
        var result = new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Success,
            JobHistoryId = jobHistoryId,
        };

        if (!string.IsNullOrEmpty(jobMessage))
        {
            result.FailureMessage = jobMessage;
        }

        return result;
    }

    protected string ParseJobPrivateKey(ManagementJobConfiguration config)
    {
        Logger.LogTrace("Entered ParseJobPrivateKey()");
        if (string.IsNullOrWhiteSpace(config.JobCertificate.Alias)) Logger.LogTrace("No Alias Found");

        // Load PFX
        Logger.LogTrace("Loading PFX from job contents");
        var pfxBytes = Convert.FromBase64String(config.JobCertificate.Contents);
        Logger.LogTrace("PFX loaded successfully");

        var alias = config.JobCertificate.Alias;
        Logger.LogTrace("Alias: {Alias}", alias);

        Logger.LogTrace("Creating Pkcs12Store object");
        // Load the PKCS12 bytes into a Pkcs12Store object
        using var pkcs12Stream = new MemoryStream(pfxBytes);
        var store = new Pkcs12StoreBuilder().Build();

        Logger.LogDebug("Attempting to load PFX into store using password");
        store.Load(pkcs12Stream, config.JobCertificate.PrivateKeyPassword.ToCharArray());

        // Find the private key entry with the given alias
        Logger.LogDebug("Attempting to get private key entry with alias");
        foreach (var aliasName in store.Aliases)
        {
            Logger.LogTrace("Alias: {Alias}", aliasName);
            if (!aliasName.Equals(alias) || !store.IsKeyEntry(aliasName)) continue;
            Logger.LogDebug("Alias found, attempting to get private key");
            var keyEntry = store.GetKey(aliasName);

            // Convert the private key to unencrypted PEM format
            using var stringWriter = new StringWriter();
            var pemWriter = new PemWriter(stringWriter);
            pemWriter.WriteObject(keyEntry.Key);
            pemWriter.Writer.Flush();

            Logger.LogDebug("Private key found for alias {Alias}, returning private key", alias);
            return stringWriter.ToString();
        }

        Logger.LogDebug("Alias '{Alias}' not found, returning null private key", alias);
        return null; // Private key with the given alias not found
    }

    protected string getK8SStorePassword(V1Secret certData)
    {
        Logger.LogDebug("Entered getK8SStorePassword()");
        Logger.LogDebug("Attempting to get store password from K8S secret");
        var storePasswordBytes = Array.Empty<byte>();

        // if secret is a buddy pass
        if (!string.IsNullOrEmpty(StorePassword))
        {
            Logger.LogDebug("Using provided 'StorePassword'");
            // var passwordHash = GetSHA256Hash(StorePassword);
            // Logger.LogTrace("Password hash: " + passwordHash);
            storePasswordBytes = Encoding.UTF8.GetBytes(StorePassword);
        }
        else if (!string.IsNullOrEmpty(StorePasswordPath))
        {
            // Split password path into namespace and secret name
            Logger.LogDebug(
                "Store password is null or empty and StorePasswordPath is set, attempting to read password from K8S buddy secret");
            Logger.LogTrace("Password path: {Path}", StorePasswordPath);
            Logger.LogTrace("Splitting password path by /");
            var passwordPath = StorePasswordPath.Split("/");
            Logger.LogDebug("Password path length: {Len}", passwordPath.Length.ToString());
            var passwordNamespace = "";
            var passwordSecretName = "";
            if (passwordPath.Length == 1)
            {
                Logger.LogDebug("Password path length is 1, using KubeNamespace");
                passwordNamespace = KubeNamespace;
                Logger.LogTrace("Password namespace: {Namespace}", passwordNamespace);
                passwordSecretName = passwordPath[0];
                Logger.LogTrace("Password secret name: {SecretName}", passwordSecretName);
            }
            else
            {
                Logger.LogDebug("Password path length is not 1, using passwordPath[0] and passwordPath[^1]");
                passwordNamespace = passwordPath[0];
                Logger.LogTrace("Password namespace: {Namespace}", passwordNamespace);
                passwordSecretName = passwordPath[^1];
                Logger.LogTrace("Password secret name: {SecretName}", passwordSecretName);
            }

            Logger.LogTrace("Password secret name: {Name}", passwordSecretName);
            Logger.LogTrace("Password namespace: {Ns}", passwordNamespace);

            Logger.LogDebug("Attempting to read K8S buddy secret");
            var k8sPasswordObj = KubeClient.ReadBuddyPass(passwordSecretName, passwordNamespace);
            storePasswordBytes = k8sPasswordObj.Data[PasswordFieldName];
            // var passwordHash = GetSHA256Hash(Encoding.UTF8.GetString(storePasswordBytes));
            // Logger.LogTrace("Password hash: {Pwd}", passwordHash);
            if (storePasswordBytes == null)
            {
                Logger.LogError("Password not found in K8S buddy secret");
                throw new InvalidK8SSecretException(
                    "Password not found in K8S buddy secret"); // todo: should this be thrown?
            }

            Logger.LogDebug("K8S buddy secret read successfully");
        }
        else if (certData != null && certData.Data.TryGetValue(PasswordFieldName, out var value1))
        {
            Logger.LogDebug("Attempting to read password from PasswordFieldName");
            storePasswordBytes = value1;
            // var passwordHash = GetSHA256Hash(Encoding.UTF8.GetString(storePasswordBytes));
            // Logger.LogTrace("Password hash: {Pwd}", passwordHash);
            if (storePasswordBytes == null)
            {
                Logger.LogError("Password not found in K8S secret");
                throw new InvalidK8SSecretException("Password not found in K8S secret"); // todo: should this be thrown?
            }

            Logger.LogDebug("Password read successfully");
        }
        else
        {
            Logger.LogDebug("No password found");
            var passwdEx = "";
            if (!string.IsNullOrEmpty(StorePasswordPath))
            {
                passwdEx = "Store secret '" + StorePasswordPath + "'did not contain key '" + CertificateDataFieldName +
                           "' or '" + PasswordFieldName + "'" +
                           "  Please provide a valid store password and try again";
            }
            else
            {
                passwdEx = "Invalid store password.  Please provide a valid store password and try again";
            }

            Logger.LogError("{Msg}", passwdEx);
            throw new Exception(passwdEx);
        }

        //convert password to string
        var storePassword = Encoding.UTF8.GetString(storePasswordBytes);
        // Logger.LogTrace("Store password: {Pwd}", storePassword);
        // var passwordHash2 = GetSHA256Hash(storePassword);
        // Logger.LogTrace("Password hash: {Pwd}", passwordHash2);
        Logger.LogDebug("Returning store password");
        return storePassword;
    }

    protected Pkcs12Store LoadPkcs12Store(byte[] pkcs12Data, string password)
    {
        Logger.LogDebug("Entered LoadPkcs12Store()");
        var storeBuilder = new Pkcs12StoreBuilder();
        var store = storeBuilder.Build();

        Logger.LogDebug("Attempting to load PKCS12 store");
        using var pkcs12Stream = new MemoryStream(pkcs12Data);
        if (password != null) store.Load(pkcs12Stream, password.ToCharArray());

        Logger.LogDebug("PKCS12 store loaded successfully");
        return store;
    }

    protected string GetCertificatePem(Pkcs12Store store, string password, string alias = "")
    {
        Logger.LogDebug("Entered GetCertificatePem()");
        if (string.IsNullOrEmpty(alias))
        {
            alias = store.Aliases.Cast<string>().FirstOrDefault(store.IsKeyEntry);
        }

        Logger.LogDebug("Attempting to get certificate with alias {Alias}", alias);
        var cert = store.GetCertificate(alias).Certificate;

        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);

        Logger.LogDebug("Attempting to write certificate to PEM format");
        pemWriter.WriteObject(cert);
        pemWriter.Writer.Flush();

        Logger.LogTrace("certificate:\n{Cert}", stringWriter.ToString());

        Logger.LogDebug("Returning certificate in PEM format");
        return stringWriter.ToString();
    }

    protected string getPrivateKeyPem(Pkcs12Store store, string password, string alias = "")
    {
        Logger.LogDebug("Entered getPrivateKeyPem()");
        if (string.IsNullOrEmpty(alias))
        {
            Logger.LogDebug("Alias is empty, attempting to get key entry alias");
            alias = store.Aliases.FirstOrDefault(store.IsKeyEntry);
        }

        Logger.LogDebug("Attempting to get private key with alias {Alias}", alias);
        var privateKey = store.GetKey(alias).Key;

        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);

        Logger.LogDebug("Attempting to write private key to PEM format");
        pemWriter.WriteObject(privateKey);
        pemWriter.Writer.Flush();

        // Logger.LogTrace("private key:\n{Key}", stringWriter.ToString());
        Logger.LogDebug("Returning private key in PEM format for alias '{Alias}'", alias);
        return stringWriter.ToString();
    }

    protected List<string> getCertChain(Pkcs12Store store, string password, string alias = "")
    {
        Logger.LogDebug("Entered getCertChain()");
        if (string.IsNullOrEmpty(alias))
        {
            Logger.LogDebug("Alias is empty, attempting to get key entry alias");
            alias = store.Aliases.Cast<string>().FirstOrDefault(store.IsKeyEntry);
        }

        var chain = new List<string>();
        Logger.LogDebug("Attempting to get certificate chain with alias {Alias}", alias);
        var chainCerts = store.GetCertificateChain(alias);
        foreach (var chainCert in chainCerts)
        {
            Logger.LogTrace("Adding certificate to chain");
            using var stringWriter = new StringWriter();
            var pemWriter = new PemWriter(stringWriter);
            pemWriter.WriteObject(chainCert.Certificate);
            pemWriter.Writer.Flush();
            chain.Add(stringWriter.ToString());
        }

        Logger.LogTrace("Certificate chain:\n{Chain}", string.Join("\n", chain));
        Logger.LogDebug("Returning certificate chain");
        return chain;
    }

    public static bool IsDerFormat(byte[] data)
    {
        try
        {
            var cert = new X509CertificateParser().ReadCertificate(data);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string ConvertDerToPem(byte[] data)
    {
        var pemObject = new PemObject("CERTIFICATE", data);
        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);
        pemWriter.WriteObject(pemObject);
        pemWriter.Writer.Flush();
        return stringWriter.ToString();
    }

    protected static string GetSHA256Hash(string input)
    {
        var passwordHashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(input));
        var passwordHash = BitConverter.ToString(passwordHashBytes).Replace("-", "").ToLower();
        return passwordHash;
    }
}

public class StoreNotFoundException : Exception
{
    public StoreNotFoundException()
    {
    }

    public StoreNotFoundException(string message)
        : base(message)
    {
    }

    public StoreNotFoundException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public class InvalidK8SSecretException : Exception
{
    public InvalidK8SSecretException()
    {
    }

    public InvalidK8SSecretException(string message)
        : base(message)
    {
    }

    public InvalidK8SSecretException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public class JkSisPkcs12Exception : Exception
{
    public JkSisPkcs12Exception()
    {
    }

    public JkSisPkcs12Exception(string message)
        : base(message)
    {
    }

    public JkSisPkcs12Exception(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}