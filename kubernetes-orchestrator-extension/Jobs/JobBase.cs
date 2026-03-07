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
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Org.BouncyCastle.Crypto;
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
/// Data model representing a Kubernetes certificate store configuration.
/// Contains namespace, secret name, secret type, credentials, and certificate data.
/// </summary>
public class KubernetesCertStore
{
    /// <summary>Kubernetes namespace where the secret resides.</summary>
    public string KubeNamespace { get; set; } = "";

    /// <summary>Name of the Kubernetes secret.</summary>
    public string KubeSecretName { get; set; } = "";

    /// <summary>Type of Kubernetes secret (e.g., Opaque, kubernetes.io/tls).</summary>
    public string KubeSecretType { get; set; } = "";

    /// <summary>Service account credentials for Kubernetes API access (kubeconfig JSON).</summary>
    public string KubeSvcCreds { get; set; } = "";

    /// <summary>Array of certificates contained in this store.</summary>
    public Cert[] Certs { get; set; }
}

/// <summary>
/// Data model containing Kubernetes cluster credentials for API authentication.
/// </summary>
public class KubeCreds
{
    /// <summary>Kubernetes API server URL.</summary>
    public string KubeServer { get; set; } = "";

    /// <summary>Service account bearer token for authentication.</summary>
    public string KubeToken { get; set; } = "";

    /// <summary>Cluster CA certificate (base64 encoded).</summary>
    public string KubeCert { get; set; } = "";
}

/// <summary>
/// Data model representing a certificate with optional private key.
/// </summary>
public class Cert
{
    /// <summary>Alias/friendly name for the certificate.</summary>
    public string Alias { get; set; } = "";

    /// <summary>Certificate data (typically PEM or base64 encoded).</summary>
    public string CertData { get; set; } = "";

    /// <summary>Private key data (typically PEM format).</summary>
    public string PrivateKey { get; set; } = "";
}

/// <summary>
/// Comprehensive data model for a certificate processed during a Keyfactor orchestrator job.
/// Contains certificate data in multiple formats (PEM, bytes, base64), private key data,
/// certificate chain information, and password details.
/// </summary>
public class K8SJobCertificate
{
    /// <summary>Alias/friendly name for the certificate entry.</summary>
    public string Alias { get; set; } = "";

    /// <summary>Base64 encoded certificate data.</summary>
    public string CertB64 { get; set; } = "";

    /// <summary>Certificate in PEM format.</summary>
    public string CertPem { get; set; } = "";

    /// <summary>SHA-1 thumbprint of the certificate for identification.</summary>
    public string CertThumbprint { get; set; } = "";

    /// <summary>Raw certificate bytes (DER encoded).</summary>
    public byte[] CertBytes { get; set; }

    /// <summary>Private key in PEM format (unencrypted).</summary>
    public string PrivateKeyPem { get; set; } = "";

    /// <summary>Raw private key bytes (PKCS#8 format).</summary>
    public byte[] PrivateKeyBytes { get; set; }

    /// <summary>BouncyCastle AsymmetricKeyParameter for the private key. Used for format-preserving re-export.</summary>
    public AsymmetricKeyParameter PrivateKeyParameter { get; set; }

    /// <summary>Password protecting the private key (if encrypted).</summary>
    public string Password { get; set; } = "";

    /// <summary>Indicates if the password is stored in a separate Kubernetes secret.</summary>
    public bool PasswordIsK8SSecret { get; set; } = false;

    /// <summary>Password for the certificate store (JKS/PKCS12).</summary>
    public string StorePassword { get; set; } = "";

    /// <summary>Path to a separate Kubernetes secret containing the store password.</summary>
    public string StorePasswordPath { get; set; } = "";

    /// <summary>Indicates whether this certificate has an associated private key.</summary>
    public bool HasPrivateKey { get; set; } = false;

    /// <summary>Indicates whether the certificate/key is password protected.</summary>
    public bool HasPassword { get; set; } = false;

    /// <summary>
    /// BouncyCastle X509CertificateEntry containing the certificate
    /// </summary>
    public X509CertificateEntry CertificateEntry { get; set; }

    /// <summary>
    /// BouncyCastle X509CertificateEntry array containing the certificate chain
    /// </summary>
    public X509CertificateEntry[] CertificateEntryChain { get; set; }

    public byte[] Pkcs12 { get; set; }

    public List<string> ChainPem { get; set; }

    /// <summary>
    /// Optional: K8SCertificateContext providing BouncyCastle-based certificate operations.
    /// This property can be used for modern certificate handling without X509Certificate2 dependencies.
    /// </summary>
    public Keyfactor.Extensions.Orchestrator.K8S.Models.K8SCertificateContext CertificateContext { get; set; }

    /// <summary>
    /// Factory method to create K8SCertificateContext from this job certificate's data
    /// </summary>
    /// <returns>K8SCertificateContext instance or null if certificate data is unavailable</returns>
    public Keyfactor.Extensions.Orchestrator.K8S.Models.K8SCertificateContext GetCertificateContext()
    {
        if (CertificateEntry?.Certificate == null)
            return null;

        var context = new Keyfactor.Extensions.Orchestrator.K8S.Models.K8SCertificateContext
        {
            Certificate = CertificateEntry.Certificate,
            CertPem = CertPem,
            PrivateKeyPem = PrivateKeyPem
        };

        // Add chain if available
        if (CertificateEntryChain != null && CertificateEntryChain.Length > 0)
        {
            context.Chain = CertificateEntryChain
                .Skip(1) // Skip the first one (leaf cert)
                .Select(entry => entry.Certificate)
                .ToList();

            if (ChainPem != null && ChainPem.Count > 0)
            {
                context.ChainPem = ChainPem.Skip(1).ToList();
            }
        }

        return context;
    }
}

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

    /// <summary>Parser for extracting store configuration from properties.</summary>
    private StoreConfigurationParser _configParser;

    /// <summary>Resolver for parsing store paths into namespace/secret components.</summary>
    private StorePathResolver _storePathResolver;

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
    /// Initializes a K8SJobCertificate from the job configuration's certificate data.
    /// Parses PKCS12 data, extracts certificates and private keys, and builds certificate chains.
    /// </summary>
    /// <param name="config">Dynamic configuration object containing JobCertificate with certificate data.</param>
    /// <returns>A populated K8SJobCertificate with certificate, private key, and chain information.</returns>
    protected K8SJobCertificate InitJobCertificate(dynamic config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("=== InitJobCertificate - DER/PEM detection enabled ===");

        var jobCertObject = new K8SJobCertificate();

        // Diagnostic logging - cast dynamic results to concrete types first to avoid CS1973
        bool jobCertIsNull = config.JobCertificate == null;
        Logger.LogTrace("JobCertificate is null: {IsNull}", jobCertIsNull);
        if (!jobCertIsNull)
        {
            string contents = (string)config.JobCertificate.Contents;
            string password = (string)config.JobCertificate.PrivateKeyPassword;
            bool contentsEmpty = string.IsNullOrEmpty(contents);
            bool passwordEmpty = string.IsNullOrEmpty(password);
            Logger.LogTrace("JobCertificate.Contents is null/empty: {IsEmpty}", contentsEmpty);
            Logger.LogDebug("JobCertificate.PrivateKeyPassword is null/empty: {IsEmpty}", passwordEmpty);

            // Log all available properties on JobCertificate to discover chain field
            try
            {
                var certType = ((object)config.JobCertificate).GetType();
                var props = certType.GetProperties();
                Logger.LogTrace("JobCertificate has {Count} properties: {Names}",
                    props.Length,
                    string.Join(", ", props.Select(p => p.Name)));

                // Log ContentsFormat
                string contentsFormat = (string)config.JobCertificate.ContentsFormat;
                Logger.LogTrace("JobCertificate.ContentsFormat: {Format}", contentsFormat ?? "(null)");

                // Log first bytes of decoded content to see the format
                if (!string.IsNullOrEmpty(contents))
                {
                    try
                    {
                        byte[] decoded = Convert.FromBase64String(contents);
                        string decodedStr = System.Text.Encoding.UTF8.GetString(decoded);
                        // Check if it starts with PEM header or is binary (DER)
                        if (decodedStr.StartsWith("-----BEGIN"))
                        {
                            Logger.LogTrace("Contents is PEM format");
                            int certCount = System.Text.RegularExpressions.Regex.Matches(decodedStr, "-----BEGIN CERTIFICATE-----").Count;
                            Logger.LogTrace("PEM contains {Count} certificate(s)", certCount);
                        }
                        else
                        {
                            Logger.LogTrace("Contents is binary (DER) format, first bytes: {Bytes}",
                                BitConverter.ToString(decoded.Take(20).ToArray()));
                        }
                    }
                    catch (Exception decodeEx)
                    {
                        Logger.LogDebug("Could not decode contents for format detection: {Error}", decodeEx.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogDebug("Could not enumerate JobCertificate properties: {Error}", ex.Message);
            }
        }

        var pKeyPassword = config.JobCertificate.PrivateKeyPassword;
        // Logger.LogTrace($"pKeyPassword: {pKeyPassword}"); // Commented out to avoid logging sensitive information
        jobCertObject.Password = pKeyPassword;

        if (!string.IsNullOrEmpty(pKeyPassword))
        {
            Logger.LogDebug("Certificate {CertThumbprint} has a password", jobCertObject.CertThumbprint);
            Logger.LogTrace("Attempting to create certificate with password");
            Logger.LogTrace("Password: {Password}", LoggingUtilities.RedactPassword((string)pKeyPassword));
            try
            {
                byte[] certBytes = Convert.FromBase64String(config.JobCertificate.Contents);
                Logger.LogDebug("Certificate data length: {Length} bytes", certBytes.Length);

                // Try PKCS12 parsing FIRST (with password) - this is the expected format for certs with keys
                Logger.LogTrace("Attempting to parse as PKCS12 format with password...");
                Pkcs12Store pkcs12Store = null;
                string alias = null;
                bool isPkcs12 = false;
                try
                {
                    Logger.LogTrace("PKCS12 data: {Data}", LoggingUtilities.RedactPkcs12Bytes(certBytes));
                    Logger.LogTrace("Calling LoadPkcs12Store()");
                    pkcs12Store = LoadPkcs12Store(certBytes, pKeyPassword);
                    Logger.LogTrace("Returned from LoadPkcs12Store()");

                    Logger.LogTrace("Attempting to get alias from pkcs12Store");
                    alias = pkcs12Store.Aliases.FirstOrDefault(pkcs12Store.IsKeyEntry);
                    if (alias != null)
                    {
                        isPkcs12 = true;
                        Logger.LogDebug("Successfully parsed as PKCS12 format with key entry, alias: {Alias}", alias);
                    }
                    else
                    {
                        Logger.LogDebug("PKCS12 parsed but no key entry found, will try other formats");
                    }
                }
                catch (Exception pkcs12Ex)
                {
                    Logger.LogDebug("Not PKCS12 format or wrong password: {Error}", pkcs12Ex.Message);
                }

                // If not valid PKCS12 with key, try DER/PEM formats (cert-only, no private key)
                if (!isPkcs12)
                {
                    // Check if it's DER format (certificate only, no private key)
                    if (Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.IsDerFormat(certBytes))
                    {
                        Logger.LogDebug("Certificate data is in DER format (certificate only, no private key)");
                        return ParseDerCertificate(certBytes, jobCertObject);
                    }

                    // Check if it's PEM format (certificate only, no private key)
                    var dataStr = System.Text.Encoding.UTF8.GetString(certBytes);
                    if (dataStr.Contains("-----BEGIN CERTIFICATE-----") && !dataStr.Contains("PRIVATE KEY"))
                    {
                        Logger.LogDebug("Certificate data is in PEM format (certificate only, no private key)");
                        return ParsePemCertificate(dataStr, jobCertObject);
                    }

                    // If we get here, we couldn't parse the data
                    Logger.LogError("Failed to parse certificate data as PKCS12, DER, or PEM format");
                    throw new InvalidOperationException(
                        "Failed to parse certificate data. The data does not appear to be a valid PKCS12, DER, or PEM certificate.");
                }

                Logger.LogTrace("Alias: {Alias}", alias);

                Logger.LogTrace("Calling pkcs12Store.GetKey() with `{Alias}`", alias);
                var key = pkcs12Store.GetKey(alias);
                Logger.LogTrace("Returned from pkcs12Store.GetKey() with `{Alias}`", alias);

                //if not null then extract the private key unencrypted in PEM format
                if (key != null)
                {
                    Logger.LogDebug("Attempting to extract private key as PEM");
                    Logger.LogTrace("Calling ExtractPrivateKeyAsPem()");
                    // Store the key parameter for format-preserving re-export later
                    jobCertObject.PrivateKeyParameter = key.Key;
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
                jobCertObject.Pkcs12 = certBytes;

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
            Logger.LogDebug("Certificate does NOT have a password, trying auto-detection of format");

            if (config.JobCertificate == null ||
                string.IsNullOrEmpty(config.JobCertificate.Contents))
            {
                Logger.LogError("Job certificate contents are null or empty, cannot initialize job certificate");
                return jobCertObject;
            }

            Logger.LogTrace("Calling Convert.FromBase64String()...");
            byte[] certBytes = Convert.FromBase64String(config.JobCertificate.Contents);
            Logger.LogDebug("Certificate data length: {Length} bytes", certBytes.Length);

            if (certBytes.Length == 0)
            {
                Logger.LogError("Certificate `{CertThumbprint}` is empty, this should not happen",
                    jobCertObject.CertThumbprint);
                return jobCertObject;
            }

            // Try PKCS12 parsing FIRST (this is the most common format for certs with keys)
            Logger.LogTrace("Attempting to parse as PKCS12 format first...");
            Pkcs12Store pkcs12Store = null;
            bool isPkcs12 = false;
            try
            {
                Logger.LogTrace("Calling LoadPkcs12Store()");
                pkcs12Store = LoadPkcs12Store(certBytes, pKeyPassword);
                Logger.LogTrace("Returned from LoadPkcs12Store()");
                // Check if we actually got a valid PKCS12 with a key entry
                var testAlias = pkcs12Store.Aliases.FirstOrDefault(pkcs12Store.IsKeyEntry);
                if (testAlias != null)
                {
                    isPkcs12 = true;
                    Logger.LogDebug("Successfully parsed as PKCS12 format with key entry");
                }
                else
                {
                    Logger.LogDebug("PKCS12 parsed but no key entry found, will try other formats");
                }
            }
            catch (Exception ex)
            {
                Logger.LogDebug("Not PKCS12 format: {Error}", ex.Message);
            }

            // If not valid PKCS12 with key, try DER/PEM formats
            if (!isPkcs12)
            {
                // Check if it's DER format (certificate only, no private key)
                if (Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.IsDerFormat(certBytes))
                {
                    Logger.LogDebug("Certificate data is in DER format (certificate only, no private key)");
                    return ParseDerCertificate(certBytes, jobCertObject);
                }

                // Check if it's PEM format
                var dataStr = System.Text.Encoding.UTF8.GetString(certBytes);
                if (dataStr.Contains("-----BEGIN CERTIFICATE-----"))
                {
                    Logger.LogDebug("Certificate data is in PEM format");
                    return ParsePemCertificate(dataStr, jobCertObject);
                }

                // If we get here, we couldn't parse the data
                Logger.LogError("Failed to parse certificate data as PKCS12, DER, or PEM format");
                throw new InvalidOperationException(
                    "Failed to parse certificate data. The data does not appear to be a valid PKCS12, DER, or PEM certificate.");
            }

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

                    // Store the key parameter for format-preserving re-export later
                    jobCertObject.PrivateKeyParameter = privateKey;
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
    /// Derives the KubeSecretType from the Capability string.
    /// This replaces the need for the KubeSecretType store property for most store types.
    /// </summary>
    /// <param name="capability">The capability string (e.g., "CertStores.K8SJKS.Inventory")</param>
    /// <returns>The derived secret type, or null if it cannot be determined from Capability alone.</returns>
    /// <remarks>
    /// Mapping:
    /// - K8SJKS -> "jks"
    /// - K8SPKCS12 -> "pkcs12"
    /// - K8SSecret -> "secret"
    /// - K8STLSSecr -> "tls_secret"
    /// - K8SCluster -> "cluster" (actual secret type determined at runtime from alias)
    /// - K8SNS -> "namespace" (actual secret type determined at runtime from alias)
    /// - K8SCert -> "certificate"
    /// </remarks>
    protected static string DeriveSecretTypeFromCapability(string capability)
    {
        if (string.IsNullOrEmpty(capability))
            return null;

        // Order matters - check more specific patterns first
        if (capability.Contains("K8STLSSecr", StringComparison.OrdinalIgnoreCase))
            return "tls_secret";
        if (capability.Contains("K8SSecret", StringComparison.OrdinalIgnoreCase))
            return "secret";
        if (capability.Contains("K8SJKS", StringComparison.OrdinalIgnoreCase))
            return "jks";
        if (capability.Contains("K8SPKCS12", StringComparison.OrdinalIgnoreCase))
            return "pkcs12";
        if (capability.Contains("K8SCluster", StringComparison.OrdinalIgnoreCase))
            return "cluster";
        if (capability.Contains("K8SNS", StringComparison.OrdinalIgnoreCase))
            return "namespace";
        if (capability.Contains("K8SCert", StringComparison.OrdinalIgnoreCase))
            return "certificate";

        return null;
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

        // Initialize the resolver if not already done
        _storePathResolver ??= new StorePathResolver(Logger);

        // Delegate to the service for path resolution
        var result = _storePathResolver.Resolve(spath, Capability, KubeNamespace, KubeSecretName);

        // Apply the resolved values
        KubeNamespace = result.Namespace;
        KubeSecretName = result.SecretName;

        // Log any warnings from the resolution
        if (!string.IsNullOrEmpty(result.Warning))
        {
            Logger.LogWarning("{Warning}", result.Warning);
        }

        if (!result.Success)
        {
            Logger.LogError("Failed to resolve store path: {StorePath}", spath);
        }

        var resolvedPath = GetStorePath();
        Logger.LogDebug("Resolved store path: {ResolvedPath}", resolvedPath);
        Logger.MethodExit(MsLogLevel.Debug);
        return resolvedPath;
    }

    /// <summary>
    /// Resolves a PAM field with fallback key support.
    /// Attempts to resolve from primary key, then fallback key if specified.
    /// </summary>
    /// <param name="primaryKey">Primary PAM field key (e.g., "ServerPassword").</param>
    /// <param name="fallbackKey">Fallback PAM field key (e.g., "Server Password").</param>
    /// <param name="currentValue">Current value to use if PAM resolution fails.</param>
    /// <param name="defaultValue">Default value if all resolution attempts fail.</param>
    /// <returns>The resolved value, or default if resolution fails.</returns>
    private string ResolvePamFieldWithFallback(string primaryKey, string fallbackKey, string currentValue, string defaultValue = "")
    {
        try
        {
            Logger.LogInformation("Attempting to resolve '{PrimaryKey}' from store properties or PAM provider", primaryKey);
            var resolved = PAMUtilities.ResolvePAMField(_resolver, Logger, primaryKey, currentValue);
            if (!string.IsNullOrEmpty(resolved))
            {
                Logger.LogInformation("{Key} resolved from PAM provider", primaryKey);
                return resolved;
            }

            if (!string.IsNullOrEmpty(fallbackKey))
            {
                Logger.LogInformation("{PrimaryKey} not resolved, trying fallback key '{FallbackKey}'", primaryKey, fallbackKey);
                resolved = PAMUtilities.ResolvePAMField(_resolver, Logger, fallbackKey, currentValue);
                if (!string.IsNullOrEmpty(resolved))
                {
                    Logger.LogInformation("{Key} resolved from PAM provider using fallback key", fallbackKey);
                    return resolved;
                }
            }

            Logger.LogDebug("{Key} not resolved from PAM, using current/default value", primaryKey);
            return string.IsNullOrEmpty(currentValue) ? defaultValue : currentValue;
        }
        catch (Exception e)
        {
            Logger.LogError("Error resolving PAM field '{Key}': {Message}", primaryKey, e.Message);
            Logger.LogTrace("{Exception}", e.ToString());
            return string.IsNullOrEmpty(currentValue) ? defaultValue : currentValue;
        }
    }

    /// <summary>
    /// Applies parsed store configuration to class properties.
    /// </summary>
    /// <param name="config">The parsed store configuration.</param>
    private void ApplyParsedConfiguration(StoreConfiguration config)
    {
        KubeNamespace = config.KubeNamespace;
        KubeSecretName = config.KubeSecretName;
        KubeSecretType = config.KubeSecretType;
        KubeSvcCreds = config.KubeSvcCreds;
        PasswordIsSeparateSecret = config.PasswordIsSeparateSecret;
        PasswordFieldName = config.PasswordFieldName;
        StorePasswordPath = config.StorePasswordPath;
        CertificateDataFieldName = config.CertificateDataFieldName;
        PasswordIsK8SSecret = config.PasswordIsK8SSecret;
        KubeSecretPassword = config.KubeSecretPassword;
        SeparateChain = config.SeparateChain;
        IncludeCertChain = config.IncludeCertChain;
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
        _configParser ??= new StoreConfigurationParser(Logger);
        string storePropsType = storeProperties != null ? (string)storeProperties.GetType().FullName : "null";
        Logger.LogTrace("InitializeProperties called with storeProperties type: {Type}", storePropsType);

        if (storeProperties == null)
        {
            Logger.MethodExit(MsLogLevel.Debug);
            throw new ConfigurationException(
                $"Invalid configuration. Please provide {RequiredProperties}. Or review the documentation at https://github.com/Keyfactor/kubernetes-orchestrator#custom-fields-tab");
        }


        // Parse all store properties using centralized parser
        try
        {
            Logger.LogDebug("Parsing store properties using centralized parser");
            var config = _configParser.Parse(storeProperties, Capability);
            ApplyParsedConfiguration(config);
            Logger.LogDebug("KubeNamespace: '{Value}'", KubeNamespace ?? "(null)");
            Logger.LogDebug("KubeSecretName: '{Value}'", KubeSecretName ?? "(null)");
            Logger.LogDebug("KubeSecretType: '{Value}'", KubeSecretType ?? "(null)");
            Logger.LogTrace("KubeSvcCreds present: {Present}", !string.IsNullOrEmpty(KubeSvcCreds));
        }
        catch (Exception ex)
        {
            Logger.LogError("CRITICAL ERROR while parsing store properties: {Message}", ex.Message);
            Logger.LogError("Exception Type: {Type}", ex.GetType().FullName);
            Logger.LogTrace("{StackTrace}", ex.StackTrace);
            Logger.LogWarning("Setting KubeSecretType and KubeSvcCreds to empty strings");
            KubeSecretType = "";
            KubeSvcCreds = "";
        }

        // Resolve PAM fields using helper method with fallback support
        ServerUsername = ResolvePamFieldWithFallback("ServerUsername", "Server Username", ServerUsername, "kubeconfig");
        ServerPassword = ResolvePamFieldWithFallback("ServerPassword", "Server Password", ServerPassword, "");
        StorePassword = ResolvePamFieldWithFallback("StorePassword", "Store Password", StorePassword, "");

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
                var isNull = (bool)(storeProperties == null);
                var propsType = (string)(storeProperties != null ? storeProperties.GetType().FullName : "null");
                Logger.LogError("CRITICAL ERROR setting KubeSvcCreds: {Message}", ex.Message);
                Logger.LogError("storeProperties is null: {IsNull}", isNull);
                Logger.LogError("storeProperties type: {Type}", propsType);
                throw;
            }
        }

        if (string.IsNullOrEmpty(KubeSvcCreds))
        {
            const string credsErr =
                "No credentials provided to connect to Kubernetes. Please provide a kubeconfig file. See https://github.com/Keyfactor/kubernetes-orchestrator/blob/main/scripts/kubernetes/get_service_account_creds.sh";
            Logger.LogError(credsErr);
            throw new ConfigurationException(credsErr);
        }

        // Apply keystore-specific defaults using centralized configuration parser
        ApplyKeystoreDefaultsFromParser(storeProperties);

        // Initialize the Kubernetes client
        InitializeKubeClient();

        // Resolve store path and apply namespace defaults
        ResolveStorePathAndApplyDefaults();

        Logger.MethodExit(MsLogLevel.Debug);
    }

    /// <summary>
    /// Initializes the Kubernetes client and retrieves cluster information.
    /// </summary>
    /// <exception cref="ConfigurationException">Thrown when client creation fails.</exception>
    private void InitializeKubeClient()
    {
        Logger.LogTrace("Creating new KubeCertificateManagerClient object");
        Logger.LogTrace("KubeSvcCreds length: {Length}", KubeSvcCreds?.Length ?? 0);

        try
        {
            KubeClient = new KubeCertificateManagerClient(KubeSvcCreds);
            Logger.LogTrace("KubeCertificateManagerClient created successfully");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Failed to create KubeCertificateManagerClient: {Message}", ex.Message);
            throw;
        }

        try
        {
            KubeHost = KubeClient.GetHost();
            KubeCluster = KubeClient.GetClusterName();
            Logger.LogTrace("KubeHost: {KubeHost}, KubeCluster: {KubeCluster}", KubeHost, KubeCluster);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Failed to retrieve cluster information: {Message}", ex.Message);
            throw;
        }
    }

    /// <summary>
    /// Resolves the store path and applies default values for namespace and secret name.
    /// </summary>
    private void ResolveStorePathAndApplyDefaults()
    {
        // Determine if we need to resolve path components
        // K8SCert is also treated as aggregate-like because empty KubeSecretName means "all CSRs"
        var isAggregate = !string.IsNullOrEmpty(Capability) &&
            (Capability.Contains("NS") || Capability.Contains("Cluster") || Capability.Contains("Cert"));
        var needsResolution = !string.IsNullOrEmpty(StorePath) &&
            (string.IsNullOrEmpty(KubeSecretName) && !isAggregate || string.IsNullOrEmpty(KubeNamespace));

        if (needsResolution)
        {
            Logger.LogDebug("Resolving StorePath: {StorePath}", StorePath);
            ResolveStorePath(StorePath);
        }

        // Apply default namespace if still empty
        if (string.IsNullOrEmpty(KubeNamespace))
        {
            Logger.LogDebug("KubeNamespace is empty, setting to 'default'");
            KubeNamespace = "default";
        }

        // Apply StorePath as secret name if still empty and not aggregate store
        if (string.IsNullOrEmpty(KubeSecretName) && !isAggregate)
        {
            Logger.LogWarning("KubeSecretName is empty, setting to StorePath");
            KubeSecretName = StorePath;
        }

        Logger.LogDebug("Final values - Namespace: {Namespace}, SecretName: {SecretName}, SecretType: {SecretType}",
            KubeNamespace, KubeSecretName, KubeSecretType);
    }

    /// <summary>
    /// Applies keystore-specific defaults (PKCS12/JKS) using the centralized configuration parser.
    /// Reduces complexity by delegating property extraction to StoreConfigurationParser.
    /// </summary>
    /// <param name="storeProperties">Dynamic dictionary of store properties.</param>
    private void ApplyKeystoreDefaultsFromParser(dynamic storeProperties)
    {
        var secretType = KubeSecretType?.ToLower();
        if (secretType is not ("pfx" or "p12" or "pkcs12" or "jks"))
        {
            return; // Not a keystore type, nothing to apply
        }

        Logger.LogInformation("Kubernetes certificate store type is '{Type}'. Applying keystore defaults", secretType);

        // Create a StoreConfiguration from current values and apply defaults
        var config = new StoreConfiguration
        {
            KubeSecretType = secretType,
            PasswordFieldName = PasswordFieldName,
            CertificateDataFieldName = CertificateDataFieldName,
            PasswordIsSeparateSecret = PasswordIsSeparateSecret,
            StorePasswordPath = StorePasswordPath,
            PasswordIsK8SSecret = PasswordIsK8SSecret,
            KubeSecretPassword = KubeSecretPassword
        };

        // Apply keystore-specific defaults using centralized parser
        _configParser.ApplyKeystoreDefaults(config, storeProperties);

        // Copy back the resolved values
        PasswordFieldName = config.PasswordFieldName;
        CertificateDataFieldName = config.CertificateDataFieldName;
        PasswordIsSeparateSecret = config.PasswordIsSeparateSecret;
        StorePasswordPath = config.StorePasswordPath;
        PasswordIsK8SSecret = config.PasswordIsK8SSecret;
        KubeSecretPassword = config.KubeSecretPassword;

        Logger.LogTrace("PasswordFieldName: {PasswordFieldName}", PasswordFieldName);
        Logger.LogTrace("CertificateDataFieldName: {CertificateDataFieldName}", CertificateDataFieldName);
        Logger.LogTrace("PasswordIsSeparateSecret: {PasswordIsSeparateSecret}", PasswordIsSeparateSecret);
        Logger.LogTrace("StorePasswordPath presence: {Presence}", LoggingUtilities.GetFieldPresence("StorePasswordPath", StorePasswordPath));
        Logger.LogTrace("PasswordIsK8SSecret: {PasswordIsK8SSecret}", PasswordIsK8SSecret);
        Logger.LogTrace("KubeSecretPassword: {Password}", LoggingUtilities.RedactPassword(KubeSecretPassword?.ToString()));
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
            var storePath = StorePath;

            // Determine secret type from capability first, then fall back to KubeSecretType
            string secretType;
            if (Capability.Contains("K8SNS"))
                secretType = SecretTypes.Namespace;
            else if (Capability.Contains("K8SCluster"))
                secretType = SecretTypes.Cluster;
            else
                secretType = SecretTypes.Normalize(KubeSecretType);

            Logger.LogTrace("secretType: {SecretType}", secretType);

            // Handle aggregate store types (namespace/cluster) specially
            if (SecretTypes.IsNamespaceType(secretType))
            {
                Logger.LogDebug("Kubernetes namespace resource type");
                KubeSecretType = SecretTypes.Namespace;
                storePath = $"{KubeClient.GetClusterName()}/namespace/{KubeNamespace}";
                Logger.LogDebug("Returning storePath: {StorePath}", storePath);
                Logger.MethodExit(MsLogLevel.Debug);
                return storePath;
            }

            if (SecretTypes.IsClusterType(secretType))
            {
                Logger.LogDebug("Kubernetes cluster resource type");
                KubeSecretType = SecretTypes.Cluster;
                Logger.LogDebug("Returning storePath: {StorePath}", storePath);
                Logger.MethodExit(MsLogLevel.Debug);
                return storePath;
            }

            // For simple secrets (TLS/Opaque), normalize to 'secret' for path construction
            if (SecretTypes.IsSimpleSecretType(secretType))
            {
                Logger.LogDebug("Kubernetes secret resource type (TLS/Opaque), setting secretType to 'secret'");
                secretType = SecretTypes.Opaque;
            }
            else if (SecretTypes.IsCsrType(secretType))
            {
                Logger.LogDebug("Kubernetes certificate resource type");
                secretType = SecretTypes.Certificate;
            }
            else if (!SecretTypes.IsKeystoreType(secretType))
            {
                Logger.LogWarning("Unknown secret type '{SecretType}' will use value provided", secretType);
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
    /// Parses a DER-encoded certificate and populates the job certificate object.
    /// Used when Command sends a certificate without a private key in DER format.
    /// </summary>
    /// <param name="derBytes">The DER-encoded certificate bytes.</param>
    /// <param name="jobCertObject">The job certificate object to populate.</param>
    /// <returns>The populated K8SJobCertificate.</returns>
    protected K8SJobCertificate ParseDerCertificate(byte[] derBytes, K8SJobCertificate jobCertObject)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Parsing DER-encoded certificate ({ByteCount} bytes)", derBytes.Length);

        // Log warning if IncludeCertChain is true but certificate has no private key
        // When Command sends a certificate without a private key, it arrives in DER format
        // which only contains the leaf certificate - the chain cannot be included.
        if (IncludeCertChain)
        {
            Logger.LogWarning(
                "IncludeCertChain is enabled but the certificate was received in DER format (no private key). " +
                "DER format only contains the leaf certificate, so the certificate chain cannot be included. " +
                "To include the certificate chain, ensure the certificate in Keyfactor Command has 'Private Key' set.");
        }

        try
        {
            var parser = new Org.BouncyCastle.X509.X509CertificateParser();
            var bcCertificate = parser.ReadCertificate(derBytes);

            if (bcCertificate == null)
            {
                Logger.LogError("Failed to parse DER certificate - parser returned null");
                return jobCertObject;
            }

            Logger.LogDebug("DER certificate loaded: {Summary}", LoggingUtilities.GetCertificateSummary(bcCertificate));

            // Convert to PEM format
            var pemCert = ConvertCertificateToPem(bcCertificate);

            jobCertObject.CertPem = pemCert;
            jobCertObject.CertBytes = bcCertificate.GetEncoded();
            jobCertObject.CertThumbprint = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.GetThumbprint(bcCertificate);
            jobCertObject.CertificateEntry = new Org.BouncyCastle.Pkcs.X509CertificateEntry(bcCertificate);
            jobCertObject.HasPrivateKey = false;

            // For DER certificates, set up single-entry chain (leaf only, no issuer chain)
            jobCertObject.CertificateEntryChain = new[] { jobCertObject.CertificateEntry };
            jobCertObject.ChainPem = new List<string> { pemCert };

            Logger.LogDebug("DER certificate parsed successfully (no private key)");
            Logger.MethodExit(MsLogLevel.Debug);
            return jobCertObject;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error parsing DER certificate: {Error}", ex.Message);
            throw new InvalidOperationException($"Failed to parse DER-encoded certificate: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Parses a PEM-encoded certificate and populates the job certificate object.
    /// Used when Command sends a certificate without a private key in PEM format.
    /// </summary>
    /// <param name="pemData">The PEM-encoded certificate string.</param>
    /// <param name="jobCertObject">The job certificate object to populate.</param>
    /// <returns>The populated K8SJobCertificate.</returns>
    protected K8SJobCertificate ParsePemCertificate(string pemData, K8SJobCertificate jobCertObject)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Parsing PEM-encoded certificate(s)");

        try
        {
            // Parse all certificates from the PEM data (there may be a full chain)
            var certificates = new List<Org.BouncyCastle.X509.X509Certificate>();
            using var stringReader = new StringReader(pemData);
            var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(stringReader);

            object pemObject;
            while ((pemObject = pemReader.ReadObject()) != null)
            {
                if (pemObject is Org.BouncyCastle.X509.X509Certificate cert)
                {
                    certificates.Add(cert);
                    Logger.LogDebug("Found certificate in PEM: {Summary}", LoggingUtilities.GetCertificateSummary(cert));
                }
            }

            if (certificates.Count == 0)
            {
                // Try parsing as DER from the PEM content as a fallback
                var parser = new Org.BouncyCastle.X509.X509CertificateParser();
                var bcCert = parser.ReadCertificate(Encoding.UTF8.GetBytes(pemData));
                if (bcCert != null)
                {
                    certificates.Add(bcCert);
                }
            }

            if (certificates.Count == 0)
            {
                Logger.LogError("Failed to parse PEM certificate - no certificates found");
                return jobCertObject;
            }

            // First certificate is the leaf/end-entity certificate
            var leafCertificate = certificates[0];
            Logger.LogDebug("Leaf certificate: {Summary}", LoggingUtilities.GetCertificateSummary(leafCertificate));

            // Set the leaf certificate properties
            jobCertObject.CertPem = ConvertCertificateToPem(leafCertificate);
            jobCertObject.CertBytes = leafCertificate.GetEncoded();
            jobCertObject.CertThumbprint = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities.GetThumbprint(leafCertificate);
            jobCertObject.CertificateEntry = new Org.BouncyCastle.Pkcs.X509CertificateEntry(leafCertificate);
            jobCertObject.HasPrivateKey = false;

            // Set the full chain (including leaf as first entry)
            jobCertObject.CertificateEntryChain = certificates
                .Select(c => new Org.BouncyCastle.Pkcs.X509CertificateEntry(c))
                .ToArray();

            // Set chain PEM (all certificates)
            jobCertObject.ChainPem = certificates
                .Select(ConvertCertificateToPem)
                .ToList();

            Logger.LogInformation("PEM certificate(s) parsed successfully: {Count} certificate(s), no private key", certificates.Count);
            Logger.MethodExit(MsLogLevel.Debug);
            return jobCertObject;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error parsing PEM certificate: {Error}", ex.Message);
            throw new InvalidOperationException($"Failed to parse PEM-encoded certificate: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Converts a BouncyCastle X509Certificate to PEM format.
    /// This is a local helper method that doesn't depend on KubeClient initialization.
    /// </summary>
    /// <param name="certificate">The certificate to convert.</param>
    /// <returns>The certificate in PEM format.</returns>
    private static string ConvertCertificateToPem(Org.BouncyCastle.X509.X509Certificate certificate)
    {
        var pemObject = new Org.BouncyCastle.Utilities.IO.Pem.PemObject("CERTIFICATE", certificate.GetEncoded());
        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);
        pemWriter.WriteObject(pemObject);
        pemWriter.Writer.Flush();
        return stringWriter.ToString();
    }

}

/// <summary>
/// Exception thrown when a certificate store cannot be found in Kubernetes.
/// </summary>
public class StoreNotFoundException : Exception
{
    /// <summary>Initializes a new instance of StoreNotFoundException.</summary>
    public StoreNotFoundException()
    {
    }

    /// <summary>Initializes a new instance with the specified error message.</summary>
    /// <param name="message">The error message describing the missing store.</param>
    public StoreNotFoundException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with the specified error message and inner exception.</summary>
    /// <param name="message">The error message describing the missing store.</param>
    /// <param name="innerException">The exception that caused this exception.</param>
    public StoreNotFoundException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a Kubernetes secret is invalid, malformed, or missing required fields.
/// </summary>
public class InvalidK8SSecretException : Exception
{
    /// <summary>Initializes a new instance of InvalidK8SSecretException.</summary>
    public InvalidK8SSecretException()
    {
    }

    /// <summary>Initializes a new instance with the specified error message.</summary>
    /// <param name="message">The error message describing the invalid secret.</param>
    public InvalidK8SSecretException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with the specified error message and inner exception.</summary>
    /// <param name="message">The error message describing the invalid secret.</param>
    /// <param name="innerException">The exception that caused this exception.</param>
    public InvalidK8SSecretException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a JKS keystore contains PKCS12 data instead of proper JKS format,
/// or vice versa (format mismatch between expected and actual store format).
/// </summary>
public class JkSisPkcs12Exception : Exception
{
    /// <summary>Initializes a new instance of JkSisPkcs12Exception.</summary>
    public JkSisPkcs12Exception()
    {
    }

    /// <summary>Initializes a new instance with the specified error message.</summary>
    /// <param name="message">The error message describing the format mismatch.</param>
    public JkSisPkcs12Exception(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with the specified error message and inner exception.</summary>
    /// <param name="message">The error message describing the format mismatch.</param>
    /// <param name="innerException">The exception that caused this exception.</param>
    public JkSisPkcs12Exception(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}