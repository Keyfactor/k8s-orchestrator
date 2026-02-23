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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Common.Logging;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Exceptions;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.PKI.Extensions;
using Keyfactor.PKI.PrivateKeys;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;
using Newtonsoft.Json;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using PemWriter = Org.BouncyCastle.OpenSsl.PemWriter;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

/// <summary>
/// Abstract base class for all Kubernetes orchestrator jobs (Inventory, Management, Discovery, Reenrollment).
/// Provides common functionality for Kubernetes client initialization, credential parsing, store type detection,
/// certificate handling, and PAM integration.
/// </summary>
public abstract class JobBase
{
    /// <summary>Default field name for PKCS12/PFX data in secrets.</summary>
    private const string DefaultPFXSecretFieldName = "pfx";
    /// <summary>Default field name for JKS data in secrets.</summary>
    private const string DefaultJKSSecretFieldName = "jks";
    /// <summary>Default field name for password data in secrets.</summary>
    private const string DefaultPFXPasswordSecretFieldName = "password";

    /// <summary>Separator used when joining certificate chains.</summary>
    protected const string CertChainSeparator = ",";
    /// <summary>Array of supported Kubernetes store types.</summary>
    protected static readonly string[] SupportedKubeStoreTypes;

    /// <summary>Array of required job properties.</summary>
    private static readonly string[] RequiredProperties;

    /// <summary>Allowed keys for TLS secrets (tls.crt, tls.key, ca.crt).</summary>
    protected static readonly string[] TLSAllowedKeys;
    /// <summary>Allowed keys for Opaque secrets containing certificates.</summary>
    protected static readonly string[] OpaqueAllowedKeys;
    /// <summary>Allowed keys for certificate resources.</summary>
    protected static readonly string[] CertAllowedKeys;
    /// <summary>Allowed keys for PKCS12/PFX files.</summary>
    protected static readonly string[] Pkcs12AllowedKeys;
    /// <summary>Allowed keys for JKS files.</summary>
    protected static readonly string[] JksAllowedKeys;

    /// <summary>PAM secret resolver for retrieving secrets from Privileged Access Management systems.</summary>
    protected IPAMSecretResolver _resolver;

    /// <summary>Kubernetes client for API operations.</summary>
    protected KubeCertificateManagerClient KubeClient;

    /// <summary>Logger instance for this job.</summary>
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


    protected internal bool SeparateChain { get; set; } =
        false; //Don't arbitrarily change this to true without specifying BREAKING CHANGE in the release notes.

    protected internal bool IncludeCertChain { get; set; } =
        true; //Don't arbitrarily change this to false without specifying BREAKING CHANGE in the release notes.

    protected internal string OperationType { get; set; }
    protected internal bool SkipTlsValidation { get; set; }

    public K8SJobCertificate K8SCertificate { get; set; }

    protected internal string Capability { get; set; }

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

    public bool PasswordIsK8SSecret { get; set; }

    public object KubeSecretPassword { get; set; }

    /// <summary>
    /// Initializes the store configuration for an Inventory job.
    /// Parses job configuration, extracts credentials, and sets up the Kubernetes client.
    /// </summary>
    /// <param name="config">The inventory job configuration from Keyfactor.</param>
    protected void InitializeStore(InventoryJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(MsLogLevel.Debug);

        try
        {
            InventoryConfig = config;
            Capability = config.Capability;
            Logger.LogTrace("Capability: {Capability}", Capability);

            Logger.LogDebug("Calling JsonConvert.DeserializeObject()");
            var props = JsonConvert.DeserializeObject(config.CertificateStoreDetails.Properties);
            Logger.LogTrace("Props type: {Type}", props?.GetType()?.Name ?? "null");
            // Logger.LogTrace("Properties: {Properties}", props); // Commented out to avoid logging sensitive information

            ServerUsername = config.ServerUsername;
            Logger.LogTrace("ServerUsername: {ServerUsername}", ServerUsername);

            ServerPassword = config.ServerPassword;
            Logger.LogTrace("ServerPassword: {Password}", LoggingUtilities.RedactPassword(ServerPassword));
            Logger.LogTrace("ServerPassword correlation: {CorrelationId}", LoggingUtilities.GetPasswordCorrelationId(ServerPassword));

            StorePassword = config.CertificateStoreDetails?.StorePassword;
            Logger.LogTrace("StorePassword: {Password}", LoggingUtilities.RedactPassword(StorePassword));
            Logger.LogTrace("StorePassword correlation: {CorrelationId}", LoggingUtilities.GetPasswordCorrelationId(StorePassword));

            StorePath = config.CertificateStoreDetails?.StorePath;
            Logger.LogTrace("StorePath: {StorePath}", StorePath);

            Logger.LogDebug("Calling InitializeProperties()");
            InitializeProperties(props);
            Logger.LogDebug("Returned from InitializeProperties()");
            Logger.LogInformation(
                "Initialized Inventory Job Configuration for `{Capability}` with store path `{StorePath}`", Capability,
                StorePath);
            Logger.MethodExit(MsLogLevel.Debug);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "CRITICAL ERROR in InitializeStore(Inventory): {Message}", ex.Message);
            Logger.LogError("Exception Type: {Type}", ex.GetType().FullName);
            Logger.LogError("Stack Trace: {StackTrace}", ex.StackTrace);
            throw;
        }
    }

    /// <summary>
    /// Initializes the store configuration for a Discovery job.
    /// Parses job configuration and sets up SSL/TLS validation settings.
    /// </summary>
    /// <param name="config">The discovery job configuration from Keyfactor.</param>
    protected void InitializeStore(DiscoveryJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(MsLogLevel.Debug);
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
        Logger.LogInformation(
            "Initialized Discovery Job Configuration for `{Capability}` with store path `{StorePath}`", Capability,
            StorePath);
        Logger.MethodExit(MsLogLevel.Debug);
    }

    /// <summary>
    /// Initializes the store configuration for a Management job (Add/Remove certificates).
    /// Parses job configuration, extracts credentials, and initializes the job certificate.
    /// </summary>
    /// <param name="config">The management job configuration from Keyfactor.</param>
    protected void InitializeStore(ManagementJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(MsLogLevel.Debug);

        try
        {
            ManagementConfig = config;

            Logger.LogDebug("Calling JsonConvert.DeserializeObject()");
            var props = JsonConvert.DeserializeObject(config.CertificateStoreDetails.Properties);
            Logger.LogTrace("Props type: {Type}", props?.GetType()?.Name ?? "null");
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
        catch (Exception ex)
        {
            Logger.LogError(ex, "CRITICAL ERROR in InitializeStore(Management): {Message}", ex.Message);
            Logger.LogError("Exception Type: {Type}", ex.GetType().FullName);
            Logger.LogError("Stack Trace: {StackTrace}", ex.StackTrace);
            throw;
        }
    }

    /// <summary>
    /// Inserts line breaks into a string at regular intervals (e.g., for PEM formatting).
    /// </summary>
    /// <param name="input">The input string to format.</param>
    /// <param name="lineLength">Maximum characters per line.</param>
    /// <returns>The formatted string with line breaks.</returns>
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


    /// <summary>
    /// Initializes a K8SJobCertificate from the job configuration's certificate data.
    /// Parses PKCS12 data, extracts certificates and private keys, and builds certificate chains.
    /// </summary>
    /// <param name="config">Dynamic configuration object containing JobCertificate with certificate data.</param>
    /// <returns>A populated K8SJobCertificate with certificate, private key, and chain information.</returns>
    protected K8SJobCertificate InitJobCertificate(dynamic config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(MsLogLevel.Debug);

        var jobCertObject = new K8SJobCertificate();
        var pKeyPassword = config.JobCertificate.PrivateKeyPassword;
        // Logger.LogTrace($"pKeyPassword: {pKeyPassword}"); // Commented out to avoid logging sensitive information
        jobCertObject.Password = pKeyPassword;

        if (!string.IsNullOrEmpty(pKeyPassword))
        {
            Logger.LogDebug("Certificate {CertThumbprint} does not have a password", jobCertObject.CertThumbprint);
            Logger.LogTrace("Attempting to create certificate without password");
            Logger.LogTrace("Password: {Password}", LoggingUtilities.RedactPassword((string)pKeyPassword));
            try
            {
                byte[] certBytes = Convert.FromBase64String(config.JobCertificate.Contents);
                Logger.LogDebug("PKCS12 data: {Data}", LoggingUtilities.RedactPkcs12Bytes(certBytes));
                Logger.LogDebug("Calling LoadPkcs12Store()");
                Pkcs12Store pkcs12Store = LoadPkcs12Store(certBytes, pKeyPassword);
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
                jobCertObject.CertThumbprint = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.GetThumbprint(x509Obj.Certificate);
                jobCertObject.ChainPem = chainList;
                jobCertObject.CertPem = KubeClient.ConvertToPem(x509Obj.Certificate);

                Logger.LogDebug("Certificate loaded: {Summary}", LoggingUtilities.GetCertificateSummary(x509Obj.Certificate));
                Logger.LogDebug("Certificate chain: {Count} certificates", chain?.Length ?? 0);
            }
            catch (Exception e)
            {
                Logger.LogError(e, "Error parsing certificate data from pkcs12 format: {Error}", e.Message);
                Logger.LogError("Certificate thumbprint: {Thumbprint}", (string)(config.JobCertificate?.Thumbprint) ?? "UNKNOWN");
                Logger.LogTrace("Stack trace: {StackTrace}", e.StackTrace);
                jobCertObject.CertThumbprint = config.JobCertificate.Thumbprint;
                //todo: should this throw an exception?
            }
        }
        else
        {
            pKeyPassword = "";
            Logger.LogDebug("Certificate {CertThumbprint} does have a password", jobCertObject.CertThumbprint);

            if (config.JobCertificate == null ||
                string.IsNullOrEmpty(config.JobCertificate.Contents))
            {
                Logger.LogError("Job certificate contents are null or empty, cannot initialize job certificate");
                return jobCertObject;
            }

            Logger.LogTrace("Calling Convert.FromBase64String()");
            byte[] certBytes = Convert.FromBase64String(config.JobCertificate.Contents);
            Logger.LogTrace("Returned from Convert.FromBase64String()");
            Logger.LogDebug("PKCS12 data: {Data}", LoggingUtilities.RedactPkcs12Bytes(certBytes));

            if (certBytes.Length == 0)
            {
                Logger.LogError("Certificate `{CertThumbprint}` is empty, this should not happen",
                    jobCertObject.CertThumbprint);
                return jobCertObject;
            }

            Logger.LogDebug("Loading PKCS12 store without password");
            Logger.LogTrace("Calling LoadPkcs12Store()");
            Pkcs12Store pkcs12Store = LoadPkcs12Store(certBytes, pKeyPassword);
            Logger.LogTrace("Returned from LoadPkcs12Store()");

            Logger.LogDebug("Attempting to get alias from pkcs12Store");
            var alias = pkcs12Store.Aliases.FirstOrDefault(pkcs12Store.IsKeyEntry);
            Logger.LogTrace("Alias: {Alias}", alias);

            if (alias == null)
            {
                Logger.LogError("No key entry found in PKCS12 store");
                return jobCertObject;
            }

            Logger.LogTrace("Calling pkcs12Store.GetCertificate()");
            var x509Obj = pkcs12Store.GetCertificate(alias);
            Logger.LogTrace("Returned from pkcs12Store.GetCertificate()");

            if (x509Obj?.Certificate == null)
            {
                Logger.LogError("Unable to retrieve certificate from PKCS12 store");
                return jobCertObject;
            }

            var bcCertificate = x509Obj.Certificate;

            Logger.LogDebug("Certificate loaded: {Summary}", LoggingUtilities.GetCertificateSummary(bcCertificate));

            Logger.LogDebug("Attempting to export certificate to PEM format");
            var pemCert = KubeClient.ConvertToPem(bcCertificate);
            Logger.LogTrace("Certificate exported to PEM format");

            jobCertObject.CertPem = pemCert;
            jobCertObject.CertBytes = bcCertificate.GetEncoded();
            jobCertObject.CertThumbprint = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.GetThumbprint(bcCertificate);
            jobCertObject.Pkcs12 = certBytes;
            jobCertObject.CertificateEntry = x509Obj;

            // Get certificate chain
            Logger.LogDebug("Attempting to get certificate chain from pkcs12Store");
            Logger.LogTrace("Calling pkcs12Store.GetCertificateChain()");
            var chain = pkcs12Store.GetCertificateChain(alias);
            Logger.LogTrace("Returned from pkcs12Store.GetCertificateChain()");

            if (chain != null && chain.Length > 0)
            {
                Logger.LogDebug("Certificate chain: {Count} certificates", chain.Length);
                var chainList = chain.Select(c => KubeClient.ConvertToPem(c.Certificate)).ToList();
                jobCertObject.CertificateEntryChain = chain;
                jobCertObject.ChainPem = chainList;
            }
            else
            {
                Logger.LogDebug("No certificate chain found");
            }

            try
            {
                Logger.LogDebug("Attempting to extract private key for `{CertThumbprint}`",
                    jobCertObject.CertThumbprint);

                // Get private key
                Logger.LogTrace("Calling pkcs12Store.GetKey()");
                var keyEntry = pkcs12Store.GetKey(alias);
                Logger.LogTrace("Returned from pkcs12Store.GetKey()");

                if (keyEntry?.Key != null)
                {
                    var privateKey = keyEntry.Key;

                    // Determine key type using BouncyCastle
                    var keyType = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.GetPrivateKeyType(privateKey);
                    Logger.LogTrace("Private key type is {Type}", keyType);

                    // Extract private key as PEM
                    Logger.LogTrace("Calling ExtractPrivateKeyAsPem()");
                    var pKeyPem = KubeClient.ExtractPrivateKeyAsPem(pkcs12Store, pKeyPassword);
                    Logger.LogTrace("Returned from ExtractPrivateKeyAsPem()");

                    jobCertObject.PrivateKeyPem = pKeyPem;
                    jobCertObject.PrivateKeyBytes = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.ExportPrivateKeyPkcs8(privateKey);
                    jobCertObject.HasPrivateKey = true;

                    Logger.LogDebug("Private key extracted for certificate: {Thumbprint}", jobCertObject.CertThumbprint);
                    Logger.LogTrace("Private key: {Key}", LoggingUtilities.RedactPrivateKey(privateKey));
                }
                else
                {
                    Logger.LogDebug("No private key found for alias `{Alias}`", alias);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Private key extraction failed for certificate: {Thumbprint}", jobCertObject.CertThumbprint);
                var refStr = string.IsNullOrEmpty(jobCertObject.Alias)
                    ? jobCertObject.CertThumbprint
                    : jobCertObject.Alias;

                Logger.LogError("Unable to unpack private key from `{Ref}`: invalid password or error", refStr);
                Logger.LogTrace("Error details: {Message}", ex.Message);
                // todo: should this throw an exception?
            }
        }

        jobCertObject.StorePassword = config.CertificateStoreDetails.StorePassword;
        Logger.LogDebug("Successfully initialized job certificate with thumbprint: {Thumbprint}", jobCertObject.CertThumbprint);
        Logger.MethodExit(MsLogLevel.Debug);
        return jobCertObject;
    }

    /// <summary>
    /// Determines if the current capability indicates a namespace-level store (K8SNS).
    /// </summary>
    /// <param name="capability">The store capability string.</param>
    /// <returns>True if this is a namespace-level store; otherwise, false.</returns>
    private static bool IsNamespaceStore(string capability)
    {
        return !string.IsNullOrEmpty(capability) &&
               capability.Contains("K8SNS", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines if the current capability indicates a cluster-level store (K8SCluster).
    /// </summary>
    /// <param name="capability">The store capability string.</param>
    /// <returns>True if this is a cluster-level store; otherwise, false.</returns>
    private static bool IsClusterStore(string capability)
    {
        return !string.IsNullOrEmpty(capability) &&
               capability.Contains("K8SCLUSTER", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Resolves and parses the store path to extract namespace, secret name, and secret type.
    /// Handles various path formats: secret_name, namespace/secret, cluster/namespace/secret, etc.
    /// </summary>
    /// <param name="spath">The store path to resolve.</param>
    /// <returns>The canonical store path in format: cluster/namespace/type/name.</returns>
    protected string ResolveStorePath(string spath)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Resolving store path: {StorePath}", spath);
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
                        sPathParts[0], sPathParts[0]);
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
                Logger.LogWarning(
                    "`StorePath`: `{StorePath}` is 2 parts this is not a valid combination for `K8SCluster` and will be ignored",
                    spath);
                break;
            case 2 when IsNamespaceStore(Capability):
                var nsPrefix = sPathParts[0];
                Logger.LogTrace("nsPrefix: {NsPrefix}", nsPrefix);
                var nsName = sPathParts[1];
                Logger.LogTrace("nsName: {NsName}", nsName);

                Logger.LogInformation(
                    "`StorePath`: `{StorePath}` is 2 parts and store type is `K8SNS`, assuming that store path pattern is either `<cluster_name>/<namespace_name>` or `namespace/<namespace_name>`",
                    spath);
                if (string.IsNullOrEmpty(KubeNamespace))
                {
                    Logger.LogInformation("`KubeNamespace` is empty, setting `KubeNamespace` to `{Namespace}`", nsName);
                    KubeNamespace = nsName;
                }
                else
                {
                    Logger.LogInformation(
                        "`KubeNamespace` parameter is not empty, ignoring `StorePath` value `{StorePath}`", spath);
                }

                break;
            case 2:
                Logger.LogInformation(
                    "`StorePath`: `{StorePath}` is 2 parts, assuming that store path pattern is the `<cluster>/<secret_name>` ",
                    spath);
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
                Logger.LogError(
                    "`StorePath`: `{StorePath}` is 3 parts and store type is `K8SCluster`, this is not a valid combination and `StorePath` will be ignored",
                    spath);
                break;
            case 3 when IsNamespaceStore(Capability):
                Logger.LogInformation(
                    "`StorePath`: `{StorePath}` is 3 parts and store type is `K8SNS`, assuming that store path pattern is `<cluster>/namespace/<namespace_name>`",
                    spath);
                var nsCluster = sPathParts[0];
                Logger.LogTrace("nsCluster: {NsCluster}", nsCluster);
                var nsClarifier = sPathParts[1];
                Logger.LogTrace("nsClarifier: {NsClarifier}", nsClarifier);
                var nsName3 = sPathParts[2];
                Logger.LogTrace("nsName3: {NsName3}", nsName3);

                if (string.IsNullOrEmpty(KubeNamespace))
                {
                    Logger.LogInformation("`KubeNamespace` is not set, setting `KubeNamespace` to `{Namespace}`",
                        nsName3);
                    KubeNamespace = nsName3;
                }
                else
                {
                    Logger.LogInformation("`KubeNamespace` is set, ignoring `StorePath` value `{StorePath}`", spath);
                }

                if (!string.IsNullOrEmpty(KubeSecretName))
                {
                    Logger.LogWarning(
                        "`KubeSecretName` parameter is not empty, but is not supported for `K8SNS` store type and will be ignored");
                    KubeSecretName = "";
                }

                break;
            case 3:
                Logger.LogInformation(
                    "Store path is 3 parts assuming that it is the '<cluster_name>/<namespace_name>/<secret_name>`");
                var kH = sPathParts[0];
                Logger.LogTrace("kH: {KubeHost}", kH);
                var kN = sPathParts[1];
                Logger.LogTrace("kN: {KubeNamespace}", kN);
                var kS = sPathParts[2];
                Logger.LogTrace("kS: {KubeSecretName}", kS);

                if (kN is "secret" or "tls" or "certificate" or "namespace")
                {
                    Logger.LogInformation(
                        "Store path is 3 parts and the second part is a reserved keyword, assuming that it is the '<cluster_name>/<namespace_name>/<secret_name>'");
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

        var resolvedPath = GetStorePath();
        Logger.LogDebug("Resolved store path: {ResolvedPath}", resolvedPath);
        Logger.MethodExit(MsLogLevel.Debug);
        return resolvedPath;
    }

    /// <summary>
    /// Initializes job properties from the store properties dictionary.
    /// Extracts Kubernetes configuration (namespace, secret name, type, credentials),
    /// resolves PAM fields, and creates the Kubernetes client.
    /// </summary>
    /// <param name="storeProperties">Dynamic dictionary of store properties from job configuration.</param>
    /// <exception cref="ConfigurationException">Thrown when required properties are missing.</exception>
    private void InitializeProperties(dynamic storeProperties)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        string storePropsType = storeProperties != null ? (string)storeProperties.GetType().FullName : "null";
        Logger.LogTrace("InitializeProperties called with storeProperties type: {Type}", storePropsType);

        if (storeProperties == null)
        {
            Logger.MethodExit(MsLogLevel.Debug);
            throw new Exceptions.ConfigurationException(
                $"Invalid configuration. Please provide {RequiredProperties}. Or review the documentation at https://github.com/Keyfactor/kubernetes-orchestrator#custom-fields-tab");
        }


        // check if key is present and set values if not
        try
        {
            Logger.LogDebug("Setting K8S values from store properties");
            Logger.LogTrace("Attempting to get KubeNamespace from storeProperties");
            KubeNamespace = storeProperties["KubeNamespace"];
            Logger.LogTrace("KubeNamespace retrieved: {Value}", KubeNamespace ?? "null");

            Logger.LogTrace("Attempting to get KubeSecretName from storeProperties");
            KubeSecretName = storeProperties["KubeSecretName"];
            Logger.LogTrace("KubeSecretName retrieved: {Value}", KubeSecretName ?? "null");

            Logger.LogTrace("Attempting to get KubeSecretType from storeProperties");
            KubeSecretType = storeProperties["KubeSecretType"];
            Logger.LogTrace("KubeSecretType retrieved: {Value}", KubeSecretType ?? "null");

            Logger.LogTrace("Attempting to get KubeSvcCreds from storeProperties");
            KubeSvcCreds = storeProperties["KubeSvcCreds"];
            Logger.LogTrace("KubeSvcCreds retrieved: {Present}", !string.IsNullOrEmpty(KubeSvcCreds));

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

            if (storeProperties.ContainsKey("SeparateChain"))
            {
                SeparateChain = storeProperties["SeparateChain"];
            }

            if (storeProperties.ContainsKey("IncludeCertChain"))
            {
                IncludeCertChain = storeProperties["IncludeCertChain"];
            }
        }
        catch (Exception ex)
        {
            Logger.LogError($"CRITICAL ERROR while parsing store properties: {ex.Message}");
            Logger.LogError($"Exception Type: {ex.GetType().FullName}");
            Logger.LogError($"Stack Trace: {ex.StackTrace}");
            Logger.LogWarning("Setting KubeSecretType and KubeSvcCreds to empty strings");
            KubeSecretType = "";
            KubeSvcCreds = "";
        }

        //check if storeProperties contains ServerUsername key
        Logger.LogInformation("Attempting to resolve 'ServerUsername' from store properties or PAM provider");
        var pamServerUsername =
            PAMUtilities.ResolvePAMField(_resolver, Logger, "ServerUsername", ServerUsername);
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
                PAMUtilities.ResolvePAMField(_resolver, Logger, "Server Username", ServerUsername);
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
                PAMUtilities.ResolvePAMField(_resolver, Logger, "ServerPassword", ServerPassword);
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
                    PAMUtilities.ResolvePAMField(_resolver, Logger, "Server Password", ServerPassword);
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
                PAMUtilities.ResolvePAMField(_resolver, Logger, "StorePassword", StorePassword);
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
                    PAMUtilities.ResolvePAMField(_resolver, Logger, "Store Password", StorePassword);
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
            if (string.IsNullOrEmpty(StorePassword))
            {
                Logger.LogError(
                    "Unable to resolve 'StorePassword' from store properties or PAM provider, defaulting to empty string");
                StorePassword = "";
            }

            Logger.LogError("{Message}", e.Message);
            Logger.LogTrace("{Message}", e.ToString());
            Logger.LogTrace("{Trace}", e.StackTrace);
            // throw new ConfigurationException("Invalid configuration. StorePassword not provided or is invalid");
        }

        if (ServerUsername == "kubeconfig" || string.IsNullOrEmpty(ServerUsername))
        {
            Logger.LogInformation("Using kubeconfig provided by 'Server Password' field");
            try
            {
                Logger.LogTrace("Attempting to set KubeSvcCreds in storeProperties dictionary");
                storeProperties["KubeSvcCreds"] = ServerPassword;
                Logger.LogTrace("Successfully set KubeSvcCreds in storeProperties");
                KubeSvcCreds = ServerPassword;
            }
            catch (Exception ex)
            {
                Logger.LogError($"CRITICAL ERROR setting KubeSvcCreds: {ex.Message}");
                Logger.LogError($"storeProperties is null: {storeProperties == null}");
                var propsType = storeProperties != null ? storeProperties.GetType().FullName : "null";
                Logger.LogError($"storeProperties type: {propsType}");
                throw;
            }
        }

        if (string.IsNullOrEmpty(KubeSvcCreds))
        {
            const string credsErr =
                "No credentials provided to connect to Kubernetes. Please provide a kubeconfig file. See https://github.com/Keyfactor/kubernetes-orchestrator/blob/main/scripts/kubernetes/get_service_account_creds.sh";
            Logger.LogError(credsErr);
            throw new Exceptions.ConfigurationException(credsErr);
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
                Logger.LogDebug("Parsing 'PasswordFieldName' from store properties");
                PasswordFieldName = storeProperties.ContainsKey("PasswordFieldName")
                    ? storeProperties["PasswordFieldName"]
                    : DefaultPFXPasswordSecretFieldName;
                Logger.LogTrace("PasswordFieldName: {PasswordFieldName}", PasswordFieldName);

                Logger.LogDebug("Parsing 'PasswordIsSeparateSecret' from store properties");
                PasswordIsSeparateSecret = storeProperties.ContainsKey("PasswordIsSeparateSecret")
                    ? bool.Parse(storeProperties["PasswordIsSeparateSecret"])
                    : false;
                Logger.LogTrace("PasswordIsSeparateSecret: {PasswordIsSeparateSecret}", PasswordIsSeparateSecret);

                Logger.LogDebug("Parsing 'StorePasswordPath' from store properties");
                StorePasswordPath = storeProperties.ContainsKey("StorePasswordPath")
                    ? storeProperties["StorePasswordPath"]
                    : "";
                Logger.LogTrace("StorePasswordPath presence: {Presence}", LoggingUtilities.GetFieldPresence("StorePasswordPath", StorePasswordPath));

                Logger.LogDebug("Parsing 'PasswordIsK8SSecret' from store properties");
                PasswordIsK8SSecret = storeProperties.ContainsKey("PasswordIsK8SSecret") &&
                                      !string.IsNullOrEmpty(storeProperties["PasswordIsK8SSecret"]?.ToString())
                    ? bool.Parse(storeProperties["PasswordIsK8SSecret"].ToString())
                    : false;
                Logger.LogTrace("PasswordIsK8SSecret: {PasswordIsK8SSecret}", PasswordIsK8SSecret);

                Logger.LogDebug("Parsing 'KubeSecretPassword' from store properties");
                KubeSecretPassword = storeProperties.ContainsKey("KubeSecretPassword")
                    ? storeProperties["KubeSecretPassword"]
                    : "";
                Logger.LogTrace("KubeSecretPassword: {Password}", LoggingUtilities.RedactPassword(KubeSecretPassword?.ToString()));

                Logger.LogDebug("Parsing 'CertificateDataFieldName' from store properties");
                CertificateDataFieldName = storeProperties.ContainsKey("CertificateDataFieldName")
                    ? storeProperties["CertificateDataFieldName"]
                    : DefaultJKSSecretFieldName;
                Logger.LogTrace("CertificateDataFieldName: {CertificateDataFieldName}", CertificateDataFieldName);

                break;
        }

        Logger.LogTrace("Creating new KubeCertificateManagerClient object");
        Logger.LogTrace("KubeSvcCreds length: {Length}", KubeSvcCreds?.Length ?? 0);
        try
        {
            KubeClient = new KubeCertificateManagerClient(KubeSvcCreds);
            Logger.LogTrace("KubeCertificateManagerClient created successfully");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "CRITICAL ERROR creating KubeCertificateManagerClient: {Message}", ex.Message);
            Logger.LogError("Exception Type: {Type}", ex.GetType().FullName);
            throw;
        }

        Logger.LogTrace("Getting KubeHost and KubeCluster from KubeClient");
        try
        {
            KubeHost = KubeClient.GetHost();
            Logger.LogTrace("KubeHost: {KubeHost}", KubeHost);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "CRITICAL ERROR calling KubeClient.GetHost(): {Message}", ex.Message);
            throw;
        }

        Logger.LogTrace("Getting cluster name from KubeClient");
        try
        {
            KubeCluster = KubeClient.GetClusterName();
            Logger.LogTrace("KubeCluster: {KubeCluster}", KubeCluster);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "CRITICAL ERROR calling KubeClient.GetClusterName(): {Message}", ex.Message);
            throw;
        }

        if (string.IsNullOrEmpty(KubeSecretName) && !string.IsNullOrEmpty(StorePath) &&
            !string.IsNullOrEmpty(Capability) && !Capability.Contains("NS") && !Capability.Contains("Cluster"))
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
        Logger.MethodExit(MsLogLevel.Debug);
    }

    /// <summary>
    /// Constructs the canonical store path based on cluster, namespace, secret type, and secret name.
    /// Format varies based on store type (namespace, cluster, or individual secret).
    /// </summary>
    /// <returns>The canonical store path string.</returns>
    public string GetStorePath()
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        try
        {
            var secretType = "";
            var storePath = StorePath;


            if (Capability.Contains("K8SNS"))
                secretType = "namespace";
            else if (Capability.Contains("K8SCluster"))
                secretType = "cluster";
            else
                secretType = KubeSecretType.ToLower();

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
                    Logger.MethodExit(MsLogLevel.Debug);
                    return storePath;
                case "cluster":
                    Logger.LogDebug("Kubernetes cluster resource type, setting secretType to 'cluster'");
                    KubeSecretType = "cluster";
                    Logger.LogDebug("Returning storePath: {StorePath}", storePath);
                    Logger.MethodExit(MsLogLevel.Debug);
                    return storePath;
                default:
                    Logger.LogWarning("Unknown secret type '{SecretType}' will use value provided", secretType);
                    Logger.LogTrace("secretType: {SecretType}", secretType);
                    break;
            }

            Logger.LogDebug("Building StorePath");
            storePath = $"{KubeClient.GetClusterName()}/{KubeNamespace}/{secretType}/{KubeSecretName}";
            Logger.LogDebug("Returning storePath: {StorePath}", storePath);
            Logger.MethodExit(MsLogLevel.Debug);
            return storePath;
        }
        catch (Exception e)
        {
            Logger.LogError("Unknown error constructing canonical store path: {Error}", e.Message);
            Logger.LogTrace("Stack trace: {StackTrace}", e.StackTrace);
            Logger.MethodExit(MsLogLevel.Debug);
            return StorePath;
        }
    }

    /// <summary>
    /// Resolves a PAM (Privileged Access Management) field value using the configured PAM resolver.
    /// Falls back to the original value if resolution fails.
    /// </summary>
    /// <param name="name">Name of the PAM field (for logging purposes).</param>
    /// <param name="value">The value to resolve (may contain PAM reference).</param>
    /// <returns>The resolved value, or the original value if resolution fails.</returns>
    protected string ResolvePamField(string name, string value)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        try
        {
            Logger.LogTrace("Attempting to resolve PAM eligible field: {FieldName}", name);
            var resolved = _resolver.Resolve(value);
            Logger.LogDebug("Successfully resolved PAM field: {FieldName}", name);
            Logger.MethodExit(MsLogLevel.Debug);
            return resolved;
        }
        catch (Exception e)
        {
            Logger.LogError("Unable to resolve PAM field {FieldName}, returning original value", name);
            Logger.LogError("Error: {Message}", e.Message);
            Logger.LogTrace("Exception details: {Details}", e.ToString());
            Logger.LogTrace("Stack trace: {StackTrace}", e.StackTrace);
            Logger.MethodExit(MsLogLevel.Debug);
            return value;
        }
    }

    /// <summary>
    /// Extract private key bytes from a PKCS12 store in PKCS#8 format
    /// </summary>
    /// <param name="store">PKCS12 store containing the private key</param>
    /// <param name="alias">Alias of the key entry. If null, uses the first key entry.</param>
    /// <param name="password">Optional password (not typically used for key export from already-loaded store)</param>
    /// <returns>Private key bytes in PKCS#8 format</returns>
    protected byte[] GetKeyBytes(Pkcs12Store store, string alias = null, string password = null)
    {
        Logger.MethodEntry(MsLogLevel.Debug);

        if (store == null)
            throw new ArgumentNullException(nameof(store));

        if (string.IsNullOrEmpty(alias))
        {
            alias = store.Aliases.FirstOrDefault(store.IsKeyEntry);
            Logger.LogTrace("Using first key entry alias: {Alias}", alias);
        }

        if (string.IsNullOrEmpty(alias))
        {
            Logger.LogError("No key entry found in PKCS12 store");
            throw new InvalidKeyException("No key entry found in PKCS12 store");
        }

        if (!store.IsKeyEntry(alias))
        {
            Logger.LogError("Alias '{Alias}' does not have a private key", alias);
            throw new InvalidKeyException($"Alias '{alias}' does not have a private key");
        }

        try
        {
            Logger.LogDebug("Attempting to extract private key with alias '{Alias}'", alias);
            var keyEntry = store.GetKey(alias);
            if (keyEntry?.Key == null)
            {
                Logger.LogError("Unable to retrieve private key for alias '{Alias}'", alias);
                throw new InvalidKeyException($"Unable to retrieve private key for alias '{alias}'");
            }

            var privateKey = keyEntry.Key;
            var keyType = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.GetPrivateKeyType(privateKey);
            Logger.LogTrace("Private key type: {KeyType}", keyType);

            Logger.LogDebug("Exporting private key as PKCS#8");
            var keyBytes = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.ExportPrivateKeyPkcs8(privateKey);
            Logger.LogTrace("Successfully exported private key, {Length} bytes", keyBytes?.Length ?? 0);

            Logger.MethodExit(MsLogLevel.Debug);
            return keyBytes;
        }
        catch (Exception e)
        {
            Logger.LogError("Error extracting private key: {Message}", e.Message);
            Logger.LogTrace("Stack trace: {StackTrace}", e.StackTrace);
            // Note: MethodExit not called here as we're throwing
            throw new InvalidKeyException($"Unable to extract private key from alias '{alias}'", e);
        }
    }

    /// <summary>
    /// Creates a JobResult indicating job failure with the specified message.
    /// </summary>
    /// <param name="message">The failure message describing why the job failed.</param>
    /// <param name="jobHistoryId">The job history ID for tracking.</param>
    /// <returns>A JobResult with Failure status.</returns>
    protected static JobResult FailJob(string message, long jobHistoryId)
    {
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Failure,
            JobHistoryId = jobHistoryId,
            FailureMessage = message
        };
    }

    /// <summary>
    /// Creates a JobResult indicating job success.
    /// </summary>
    /// <param name="jobHistoryId">The job history ID for tracking.</param>
    /// <param name="jobMessage">Optional message to include with the result.</param>
    /// <returns>A JobResult with Success status.</returns>
    protected static JobResult SuccessJob(long jobHistoryId, string jobMessage = null)
    {
        var result = new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Success,
            JobHistoryId = jobHistoryId
        };

        if (!string.IsNullOrEmpty(jobMessage)) result.FailureMessage = jobMessage;

        return result;
    }

    /// <summary>
    /// Parses and extracts the private key from a management job's PKCS12 certificate data.
    /// Looks for a private key entry matching the specified alias.
    /// </summary>
    /// <param name="config">The management job configuration containing certificate data.</param>
    /// <returns>The private key in PEM format, or null if not found.</returns>
    protected string ParseJobPrivateKey(ManagementJobConfiguration config)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        if (string.IsNullOrWhiteSpace(config.JobCertificate.Alias)) Logger.LogTrace("No Alias Found");

        // Load PFX
        Logger.LogTrace("Loading PFX from job contents");
        var pfxBytes = Convert.FromBase64String(config.JobCertificate.Contents);
        Logger.LogTrace("PFX loaded successfully, {Length} bytes", pfxBytes.Length);

        var alias = config.JobCertificate.Alias;
        Logger.LogTrace("Alias: {Alias}", alias);

        Logger.LogTrace("Creating Pkcs12Store object");
        // Load the PKCS12 bytes into a Pkcs12Store object
        using var pkcs12Stream = new MemoryStream(pfxBytes);
        var store = new Pkcs12StoreBuilder().Build();

        Logger.LogDebug("Attempting to load PFX into store using password");
        store.Load(pkcs12Stream, config.JobCertificate.PrivateKeyPassword.ToCharArray());

        // Find the private key entry with the given alias
        Logger.LogDebug("Searching for private key entry with alias: {Alias}", alias);
        foreach (var aliasName in store.Aliases)
        {
            Logger.LogTrace("Checking alias: {Alias}", aliasName);
            if (!aliasName.Equals(alias) || !store.IsKeyEntry(aliasName)) continue;
            Logger.LogDebug("Alias found, extracting private key");
            var keyEntry = store.GetKey(aliasName);

            // Convert the private key to unencrypted PEM format
            using var stringWriter = new StringWriter();
            var pemWriter = new PemWriter(stringWriter);
            pemWriter.WriteObject(keyEntry.Key);
            pemWriter.Writer.Flush();

            Logger.LogDebug("Private key extracted for alias: {Alias}", alias);
            Logger.MethodExit(MsLogLevel.Debug);
            return stringWriter.ToString();
        }

        Logger.LogDebug("Alias '{Alias}' not found, returning null", alias);
        Logger.MethodExit(MsLogLevel.Debug);
        return null; // Private key with the given alias not found
    }

    /// <summary>
    /// Retrieves the store password from configuration or from a Kubernetes buddy secret.
    /// Handles password stored directly, in a separate K8S secret, or embedded in the certificate secret.
    /// </summary>
    /// <param name="certData">The certificate secret that may contain an embedded password.</param>
    /// <returns>The store password as a string.</returns>
    /// <exception cref="InvalidK8SSecretException">Thrown when password cannot be retrieved from K8S secret.</exception>
    /// <exception cref="Exception">Thrown when no valid password source is available.</exception>
    protected string getK8SStorePassword(V1Secret certData)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Retrieving store password from K8S secret or configuration");
        var storePasswordBytes = Array.Empty<byte>();

        // if secret is a buddy pass
        if (!string.IsNullOrEmpty(StorePassword))
        {
            Logger.LogDebug("Using provided 'StorePassword'");
            Logger.LogTrace("StorePassword: {Password}", LoggingUtilities.RedactPassword(StorePassword));
            Logger.LogTrace("Password correlation: {CorrelationId}", LoggingUtilities.GetPasswordCorrelationId(StorePassword));
            storePasswordBytes = Encoding.UTF8.GetBytes(StorePassword);
        }
        else if (!string.IsNullOrEmpty(StorePasswordPath))
        {
            // Split password path into namespace and secret name
            Logger.LogDebug(
                "StorePassword is null or empty and StorePasswordPath is set, attempting to read password from K8S buddy secret at {StorePasswordPath}",
                StorePasswordPath);
            Logger.LogTrace("Password path: {Path}", StorePasswordPath);
            Logger.LogTrace("Splitting password path by /");
            var passwordPath = StorePasswordPath.Split("/");
            Logger.LogDebug("Password path length: {Len}", passwordPath.Length.ToString());

            string passwordNamespace;
            string passwordSecretName;

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
            if (k8sPasswordObj?.Data == null)
            {
                Logger.LogError("Unable to read K8S buddy secret {SecretName} in namespace {Namespace}",
                    passwordSecretName, passwordNamespace);
                throw new InvalidK8SSecretException(
                    $"Unable to read K8S buddy secret {passwordSecretName} in namespace {passwordNamespace}");
            }

            Logger.LogTrace("Buddy secret: {Summary}", LoggingUtilities.GetSecretSummary(k8sPasswordObj));
            Logger.LogTrace("Secret response fields: {Keys}", LoggingUtilities.GetSecretDataKeysSummary(k8sPasswordObj.Data));

            if (!k8sPasswordObj.Data.TryGetValue(PasswordFieldName, out storePasswordBytes) ||
                storePasswordBytes == null)
            {
                Logger.LogError("Unable to find password field {FieldName}", PasswordFieldName);
                throw new InvalidK8SSecretException(
                    $"Unable to find password field '{PasswordFieldName}' in secret '{passwordSecretName}' in namespace '{passwordNamespace}'"
                );
            }

            Logger.LogDebug(
                "Successfully read password from K8S buddy secret '{SecretName}' in namespace '{Namespace}'",
                passwordSecretName, passwordNamespace);
        }
        else if (certData != null && certData.Data.TryGetValue(PasswordFieldName, out var value1))
        {
            Logger.LogDebug("Attempting to read password from PasswordFieldName");
            storePasswordBytes = value1;
            if (storePasswordBytes == null)
            {
                Logger.LogError("Password not found in K8S secret");
                throw new InvalidK8SSecretException("Password not found in K8S secret"); // todo: should this be thrown?
            }

            Logger.LogDebug("Password read successfully");
        }
        else
        {
            string passwdEx;
            if (!string.IsNullOrEmpty(StorePasswordPath))
                passwdEx = "Store secret '" + StorePasswordPath + "'did not contain key '" + CertificateDataFieldName +
                           "' or '" + PasswordFieldName + "'" +
                           "  Please provide a valid store password and try again";
            else
                passwdEx = "Invalid store password.  Please provide a valid store password and try again";

            Logger.LogError("{Msg}", passwdEx);
            throw new Exception(passwdEx);
        }

        //convert password to string
        var storePassword = Encoding.UTF8.GetString(storePasswordBytes);
        Logger.LogTrace("Password (before trimming): {Password}", LoggingUtilities.RedactPassword(storePassword));
        Logger.LogTrace("Password length (before trimming): {Length}", storePassword.Length);

        // remove any trailing new line characters from the string
        storePassword = storePassword.TrimEnd('\r', '\n');
        Logger.LogDebug("Store password loaded and trimmed");
        Logger.LogTrace("Password (after trimming): {Password}", LoggingUtilities.RedactPassword(storePassword));
        Logger.LogTrace("Password length (after trimming): {Length}", storePassword.Length);
        Logger.LogTrace("Password correlation: {CorrelationId}", LoggingUtilities.GetPasswordCorrelationId(storePassword));

        Logger.MethodExit(MsLogLevel.Debug);
        return storePassword;
    }

    /// <summary>
    /// Loads a PKCS12/PFX store from byte data using the provided password.
    /// </summary>
    /// <param name="pkcs12Data">The PKCS12 data bytes.</param>
    /// <param name="password">The password to decrypt the store.</param>
    /// <returns>A loaded Pkcs12Store instance.</returns>
    protected Pkcs12Store LoadPkcs12Store(byte[] pkcs12Data, string password)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogTrace("PKCS12 data size: {Length} bytes", pkcs12Data?.Length ?? 0);

        var storeBuilder = new Pkcs12StoreBuilder();
        var store = storeBuilder.Build();

        Logger.LogDebug("Attempting to load PKCS12 store");
        using var pkcs12Stream = new MemoryStream(pkcs12Data);
        if (password != null) store.Load(pkcs12Stream, password.ToCharArray());

        Logger.LogDebug("PKCS12 store loaded successfully");
        Logger.MethodExit(MsLogLevel.Debug);
        return store;
    }

    /// <summary>
    /// Extracts a certificate from a PKCS12 store and converts it to PEM format.
    /// </summary>
    /// <param name="store">The PKCS12 store containing the certificate.</param>
    /// <param name="password">The store password (may be needed for certain operations).</param>
    /// <param name="alias">Optional alias of the certificate. If empty, uses the first key entry.</param>
    /// <returns>The certificate in PEM format.</returns>
    protected string GetCertificatePem(Pkcs12Store store, string password, string alias = "")
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        if (string.IsNullOrEmpty(alias)) alias = store.Aliases.FirstOrDefault(store.IsKeyEntry);

        Logger.LogDebug("Extracting certificate with alias: {Alias}", alias);
        var cert = store.GetCertificate(alias).Certificate;

        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);

        Logger.LogDebug("Converting certificate to PEM format");
        pemWriter.WriteObject(cert);
        pemWriter.Writer.Flush();

        Logger.LogTrace("Certificate: {Cert}", LoggingUtilities.RedactCertificatePem(stringWriter.ToString()));

        Logger.LogDebug("Returning certificate in PEM format");
        Logger.MethodExit(MsLogLevel.Debug);
        return stringWriter.ToString();
    }

    /// <summary>
    /// Extracts a private key from a PKCS12 store and converts it to PEM format.
    /// </summary>
    /// <param name="store">The PKCS12 store containing the private key.</param>
    /// <param name="password">The store password (may be needed for certain operations).</param>
    /// <param name="alias">Optional alias of the key entry. If empty, uses the first key entry.</param>
    /// <returns>The private key in PEM format (unencrypted).</returns>
    protected string getPrivateKeyPem(Pkcs12Store store, string password, string alias = "")
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        if (string.IsNullOrEmpty(alias))
        {
            Logger.LogDebug("Alias is empty, using first key entry alias");
            alias = store.Aliases.FirstOrDefault(store.IsKeyEntry);
        }

        Logger.LogDebug("Extracting private key with alias: {Alias}", alias);
        var privateKey = store.GetKey(alias).Key;

        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);

        Logger.LogDebug("Converting private key to PEM format");
        pemWriter.WriteObject(privateKey);
        pemWriter.Writer.Flush();

        Logger.LogDebug("Returning private key in PEM format for alias: {Alias}", alias);
        Logger.MethodExit(MsLogLevel.Debug);
        return stringWriter.ToString();
    }

    /// <summary>
    /// Extracts the certificate chain from a PKCS12 store as a list of PEM-formatted certificates.
    /// </summary>
    /// <param name="store">The PKCS12 store containing the certificate chain.</param>
    /// <param name="password">The store password (may be needed for certain operations).</param>
    /// <param name="alias">Optional alias of the key entry. If empty, uses the first key entry.</param>
    /// <returns>A list of PEM-formatted certificates representing the chain.</returns>
    protected List<string> getCertChain(Pkcs12Store store, string password, string alias = "")
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        if (string.IsNullOrEmpty(alias))
        {
            Logger.LogDebug("Alias is empty, using first key entry alias");
            alias = store.Aliases.FirstOrDefault(store.IsKeyEntry);
        }

        var chain = new List<string>();
        Logger.LogDebug("Extracting certificate chain with alias: {Alias}", alias);
        var chainCerts = store.GetCertificateChain(alias);
        foreach (var chainCert in chainCerts)
        {
            Logger.LogTrace("Adding certificate to chain list");
            using var stringWriter = new StringWriter();
            var pemWriter = new PemWriter(stringWriter);
            pemWriter.WriteObject(chainCert.Certificate);
            pemWriter.Writer.Flush();
            chain.Add(stringWriter.ToString());
        }

        Logger.LogDebug("Certificate chain extracted with {Count} certificates", chain.Count);
        Logger.MethodExit(MsLogLevel.Debug);
        return chain;
    }

    /// <summary>
    /// Determines if the provided byte data is in DER (binary) certificate format.
    /// </summary>
    /// <param name="data">The byte data to check.</param>
    /// <returns>True if the data is valid DER-encoded certificate; otherwise, false.</returns>
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

    /// <summary>
    /// Converts DER-encoded certificate data to PEM format.
    /// </summary>
    /// <param name="data">The DER-encoded certificate bytes.</param>
    /// <returns>The certificate in PEM format.</returns>
    public static string ConvertDerToPem(byte[] data)
    {
        var pemObject = new PemObject("CERTIFICATE", data);
        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);
        pemWriter.WriteObject(pemObject);
        pemWriter.Writer.Flush();
        return stringWriter.ToString();
    }

    /// <summary>
    /// Computes a SHA-256 hash of the input string.
    /// Useful for creating consistent identifiers without exposing sensitive data.
    /// </summary>
    /// <param name="input">The input string to hash.</param>
    /// <returns>The SHA-256 hash as a lowercase hexadecimal string.</returns>
    protected static string GetSHA256Hash(string input)
    {
        var passwordHashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(input));
        var passwordHash = BitConverter.ToString(passwordHashBytes).Replace("-", "").ToLower();
        return passwordHash;
    }
}