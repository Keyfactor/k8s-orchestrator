// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Reflection;
using Common.Logging;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

/// <summary>
/// Abstract base class for all Kubernetes orchestrator jobs (Inventory, Management, Discovery, Reenrollment).
/// Provides common functionality for Kubernetes client initialization, credential parsing, store type detection,
/// certificate handling, and PAM integration.
/// </summary>
public abstract class JobBase
{
    private static readonly string ExtensionVersion =
        typeof(JobBase).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(JobBase).Assembly.GetName().Version?.ToString()
        ?? "unknown";

    protected IPAMSecretResolver _resolver;

    protected KubeCertificateManagerClient KubeClient;

    protected ILogger Logger;

    private StoreConfigurationParser _configParser;

    private StorePathResolver _storePathResolver;

    private JobCertificateParser _certParser;

    protected internal bool SeparateChain { get; set; } =
        false; //Don't arbitrarily change this to true without specifying BREAKING CHANGE in the release notes.

    protected internal bool IncludeCertChain { get; set; } =
        true; //Don't arbitrarily change this to false without specifying BREAKING CHANGE in the release notes.

    public K8SJobCertificate K8SCertificate { get; set; }

    protected internal string Capability { get; set; }

    public string StorePath { get; set; }

    protected internal string KubeNamespace { get; set; }

    protected internal string KubeSecretName { get; set; }

    protected internal string KubeSecretType { get; set; }

    protected internal string KubeSvcCreds { get; set; }

    protected internal bool UseSSL { get; set; } = true;

    protected internal string CertificateDataFieldName { get; set; }

    protected internal string PasswordFieldName { get; set; }

    protected internal bool PasswordIsSeparateSecret { get; set; }

    protected string StorePasswordPath { get; set; }

    private string ServerUsername { get; set; }

    protected string ServerPassword { get; set; }

    protected string StorePassword { get; set; }

    public string ExtensionName => "K8S";

    public bool PasswordIsK8SSecret { get; set; }

    public object KubeSecretPassword { get; set; }

    /// <summary>
    /// Initializes the store configuration for an Inventory job.
    /// </summary>
    protected void InitializeStore(InventoryJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(MsLogLevel.Debug);

        try
        {
            UseSSL = config.UseSSL;
            InitializeStoreCore(
                config.Capability,
                config.ServerUsername,
                config.ServerPassword,
                config.CertificateStoreDetails?.StorePath,
                config.CertificateStoreDetails?.StorePassword,
                JsonConvert.DeserializeObject<Dictionary<string, object>>(config.CertificateStoreDetails.Properties));
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "CRITICAL ERROR in InitializeStore(Inventory): {Message}", ex.Message);
            throw;
        }
    }

    /// <summary>
    /// Initializes the store configuration for a Discovery job.
    /// </summary>
    protected void InitializeStore(DiscoveryJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(MsLogLevel.Debug);

        try
        {
            UseSSL = config.UseSSL;
            Logger.LogInformation("UseSSL={UseSSL}", config.UseSSL);

            InitializeStoreCore(
                config.Capability,
                config.ServerUsername,
                config.ServerPassword,
                null,
                null,
                config.JobProperties);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "CRITICAL ERROR in InitializeStore(Discovery): {Message}", ex.Message);
            throw;
        }
    }

    /// <summary>
    /// Initializes the store configuration for a Management job.
    /// </summary>
    protected void InitializeStore(ManagementJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(MsLogLevel.Debug);

        try
        {
            UseSSL = config.UseSSL;
            InitializeStoreCore(
                config.Capability,
                config.ServerUsername,
                config.ServerPassword,
                config.CertificateStoreDetails?.StorePath,
                null,
                JsonConvert.DeserializeObject<Dictionary<string, object>>(config.CertificateStoreDetails.Properties));
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "CRITICAL ERROR in InitializeStore(Management): {Message}", ex.Message);
            throw;
        }
    }

    /// <summary>
    /// Shared initialization logic for all job types.
    /// </summary>
    private void InitializeStoreCore(string capability, string serverUsername,
        string serverPassword, string storePath, string storePassword,
        IDictionary<string, object> storeProperties)
    {
        Capability = capability;
        ServerUsername = serverUsername;
        ServerPassword = serverPassword;
        StorePath = storePath;
        StorePassword = storePassword;
        InitializeProperties(storeProperties);

        Logger.LogInformation(
            "Initialized Job Configuration for '{Capability}' with store path '{StorePath}'", Capability, StorePath);
        Logger.MethodExit(MsLogLevel.Debug);
    }

    /// <summary>
    /// Initializes a K8SJobCertificate from the job configuration's certificate data.
    /// Delegates to JobCertificateParser for format detection and extraction.
    /// </summary>
    protected K8SJobCertificate InitJobCertificate(ManagementJobConfiguration config)
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        _certParser ??= new JobCertificateParser(Logger);

        return _certParser.Parse(config, IncludeCertChain);
    }

    /// <summary>
    /// Resolves and parses the store path to extract namespace, secret name, and secret type.
    /// </summary>
    protected string ResolveStorePath(string spath)
    {
        Logger.MethodEntry(MsLogLevel.Debug);

        _storePathResolver ??= new StorePathResolver(Logger);

        var result = _storePathResolver.Resolve(spath, Capability, KubeNamespace, KubeSecretName);

        KubeNamespace = result.Namespace;
        KubeSecretName = result.SecretName;

        if (!string.IsNullOrEmpty(result.Warning))
        {
            Logger.LogWarning("{Warning}", result.Warning);
        }

        if (!result.Success)
        {
            Logger.LogError("Failed to resolve store path: {StorePath}", spath);
            throw new ConfigurationException($"Invalid store path '{spath}': {result.Warning ?? "path could not be resolved"}");
        }

        var resolvedPath = GetStorePath();
        Logger.LogDebug("Resolved store path: {ResolvedPath}", resolvedPath);
        Logger.MethodExit(MsLogLevel.Debug);
        return resolvedPath;
    }

    /// <summary>
    /// Resolves a PAM field with fallback key support.
    /// </summary>
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
    /// </summary>
    private void InitializeProperties(IDictionary<string, object> storeProperties)
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogInformation("K8S Orchestrator Extension version: {Version}", ExtensionVersion);
        _configParser ??= new StoreConfigurationParser(Logger);

        if (storeProperties == null)
        {
            Logger.MethodExit(MsLogLevel.Debug);
            throw new ConfigurationException(
                "Invalid configuration. Please provide KubeNamespace, KubeSecretName, KubeSecretType. Or review the documentation at https://github.com/Keyfactor/kubernetes-orchestrator#custom-fields-tab");
        }

        // Parse all store properties using centralized parser
        try
        {
            var config = _configParser.Parse(storeProperties, Capability);
            ApplyParsedConfiguration(config);
            Logger.LogDebug("KubeNamespace: '{Value}'", KubeNamespace ?? "(null)");
            Logger.LogDebug("KubeSecretName: '{Value}'", KubeSecretName ?? "(null)");
            Logger.LogDebug("KubeSecretType: '{Value}'", KubeSecretType ?? "(null)");
        }
        catch (Exception ex)
        {
            Logger.LogError("CRITICAL ERROR while parsing store properties: {Message}", ex.Message);
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
            storeProperties["KubeSvcCreds"] = ServerPassword;
            KubeSvcCreds = ServerPassword;
        }

        if (string.IsNullOrEmpty(KubeSvcCreds))
        {
            // Allow empty credentials when running inside a Kubernetes pod — GetKubeClient will
            // detect KUBERNETES_SERVICE_HOST and use the projected service account token instead.
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("KUBERNETES_SERVICE_HOST")))
            {
                Logger.LogInformation("No kubeconfig provided — detected in-cluster environment, will use projected service account token");
            }
            else
            {
                const string credsErr =
                    "No credentials provided to connect to Kubernetes. Please provide a kubeconfig file. See https://github.com/Keyfactor/kubernetes-orchestrator/blob/main/scripts/kubernetes/README.md";
                Logger.LogError(credsErr);
                throw new ConfigurationException(credsErr);
            }
        }

        // Apply keystore-specific defaults using centralized configuration parser
        ApplyKeystoreDefaultsFromParser(storeProperties);

        // Initialize the Kubernetes client
        InitializeKubeClient();

        // Clear kubeconfig reference from store properties after client construction
        storeProperties.Remove("KubeSvcCreds");

        // Resolve store path and apply namespace defaults
        ResolveStorePathAndApplyDefaults();

        Logger.MethodExit(MsLogLevel.Debug);
    }

    /// <summary>
    /// Initializes the Kubernetes client and retrieves cluster information.
    /// </summary>
    private void InitializeKubeClient()
    {
        Logger.LogTrace("Creating new KubeCertificateManagerClient object");

        try
        {
            KubeClient = new KubeCertificateManagerClient(KubeSvcCreds, UseSSL);
            // Zero out credential references immediately after client construction
            KubeSvcCreds = null;
            ServerPassword = null;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Failed to create KubeCertificateManagerClient: {Message}", ex.Message);
            throw;
        }

        try
        {
            var host = KubeClient.GetHost();
            var cluster = KubeClient.GetClusterName();
            Logger.LogTrace("KubeHost: {KubeHost}, KubeCluster: {KubeCluster}", host, cluster);
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
        var isAggregate = !string.IsNullOrEmpty(Capability) &&
            (Capability.Contains("NS") || Capability.Contains("Cluster") || Capability.Contains("Cert"));
        var needsResolution = !string.IsNullOrEmpty(StorePath) &&
            (string.IsNullOrEmpty(KubeSecretName) && !isAggregate || string.IsNullOrEmpty(KubeNamespace));

        if (needsResolution)
        {
            Logger.LogDebug("Resolving StorePath: {StorePath}", StorePath);
            ResolveStorePath(StorePath);
        }

        if (string.IsNullOrEmpty(KubeNamespace))
        {
            Logger.LogDebug("KubeNamespace is empty, setting to 'default'");
            KubeNamespace = "default";
        }

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
    /// </summary>
    private void ApplyKeystoreDefaultsFromParser(IDictionary<string, object> storeProperties)
    {
        var secretType = KubeSecretType?.ToLower();
        if (secretType is not ("pfx" or "p12" or "pkcs12" or "jks"))
        {
            return;
        }

        Logger.LogInformation("Kubernetes certificate store type is '{Type}'. Applying keystore defaults", secretType);

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

        _configParser.ApplyKeystoreDefaults(config, storeProperties);

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
    /// </summary>
    private string GetStorePath()
    {
        Logger.MethodEntry(MsLogLevel.Debug);
        try
        {
            var secretType = DeriveSecretType();
            Logger.LogTrace("secretType: {SecretType}", secretType);

            if (SecretTypes.IsNamespaceType(secretType))
            {
                Logger.LogDebug("Kubernetes namespace resource type");
                KubeSecretType = SecretTypes.Namespace;
                Logger.MethodExit(MsLogLevel.Debug);
                return $"{KubeClient.GetClusterName()}/namespace/{KubeNamespace}";
            }

            if (SecretTypes.IsClusterType(secretType))
            {
                Logger.LogDebug("Kubernetes cluster resource type");
                KubeSecretType = SecretTypes.Cluster;
                Logger.MethodExit(MsLogLevel.Debug);
                return StorePath;
            }

            secretType = NormalizeSecretTypeForPath(secretType);

            var storePath = $"{KubeClient.GetClusterName()}/{KubeNamespace}/{secretType}/{KubeSecretName}";
            Logger.LogDebug("Returning storePath: {StorePath}", storePath);
            Logger.MethodExit(MsLogLevel.Debug);
            return storePath;
        }
        catch (Exception e)
        {
            Logger.LogError("Unknown error constructing canonical store path: {Error}", e.Message);
            Logger.MethodExit(MsLogLevel.Debug);
            return StorePath;
        }
    }

    /// <summary>
    /// Derives the secret type from the capability string or normalizes from KubeSecretType.
    /// </summary>
    private string DeriveSecretType()
    {
        if (Capability.Contains("K8SNS")) return SecretTypes.Namespace;
        if (Capability.Contains("K8SCluster")) return SecretTypes.Cluster;
        return SecretTypes.Normalize(KubeSecretType);
    }

    /// <summary>
    /// Normalizes secret type strings to their canonical form for path construction.
    /// </summary>
    private string NormalizeSecretTypeForPath(string secretType)
    {
        if (SecretTypes.IsSimpleSecretType(secretType)) return SecretTypes.Opaque;
        if (SecretTypes.IsCsrType(secretType)) return SecretTypes.Certificate;
        if (!SecretTypes.IsKeystoreType(secretType))
            Logger.LogWarning("Unknown secret type '{SecretType}' will use value provided", secretType);
        return secretType;
    }
}
