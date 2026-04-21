// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using k8s.Exceptions;
using k8s.KubeConfigModels;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Keyfactor.Extensions.Orchestrator.K8S.Clients;

/// <summary>
/// Parses kubeconfig JSON strings into K8SConfiguration objects.
/// Handles base64 decoding, JSON escaping, and environment variable overrides.
/// </summary>
public class KubeconfigParser
{
    private readonly ILogger _logger;

    /// <summary>
    /// Environment variable name for overriding TLS verification.
    /// </summary>
    public const string SkipTlsVerifyEnvVar = "KEYFACTOR_ORCHESTRATOR_SKIP_TLS_VERIFY";

    /// <summary>
    /// Initializes a new instance of the KubeconfigParser.
    /// </summary>
    /// <param name="logger">Logger instance for diagnostic output.</param>
    public KubeconfigParser(ILogger logger = null)
    {
        _logger = logger ?? LogHandler.GetClassLogger<KubeconfigParser>();
    }

    /// <summary>
    /// Parses a kubeconfig JSON string into a K8SConfiguration object.
    /// </summary>
    /// <param name="kubeconfig">JSON-formatted kubeconfig string (may be base64 encoded).</param>
    /// <param name="skipTlsVerify">When true, skips TLS certificate verification.</param>
    /// <returns>Parsed K8SConfiguration object.</returns>
    /// <exception cref="KubeConfigException">Thrown when kubeconfig is invalid or missing required fields.</exception>
    public K8SConfiguration Parse(string kubeconfig, bool skipTlsVerify = false)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("Kubeconfig length: {Length}, skipTlsVerify: {SkipTLS}", kubeconfig?.Length ?? 0, skipTlsVerify);

        try
        {
            ValidateInput(kubeconfig);

            // Decode and normalize the kubeconfig
            kubeconfig = DecodeAndNormalize(kubeconfig);

            // Check for environment variable override
            skipTlsVerify = CheckTlsVerifyOverride(skipTlsVerify);

            // Parse the JSON
            var configDict = ParseJson(kubeconfig);

            // Build the configuration object
            var config = BuildConfiguration(configDict, skipTlsVerify);

            _logger.LogDebug("Finished parsing kubeconfig");
            _logger.MethodExit(LogLevel.Debug);
            return config;
        }
        catch (KubeConfigException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "CRITICAL ERROR in ParseKubeConfig: {Message}", ex.Message);
            throw new KubeConfigException($"Failed to parse kubeconfig: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Validates the kubeconfig input is not null or empty.
    /// </summary>
    private void ValidateInput(string kubeconfig)
    {
        if (string.IsNullOrEmpty(kubeconfig))
        {
            _logger.LogError("kubeconfig is null or empty");
            throw new KubeConfigException(
                "kubeconfig is null or empty, please provide a valid kubeconfig in JSON format. " +
                "For more information on how to create a kubeconfig file, please visit " +
                "https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json");
        }
    }

    /// <summary>
    /// Decodes base64 encoding and normalizes escaped JSON.
    /// </summary>
    private string DecodeAndNormalize(string kubeconfig)
    {
        // Try to decode from base64
        kubeconfig = TryDecodeBase64(kubeconfig);

        // Handle escaped JSON (fixes bug where all backslashes were removed before newline handling)
        kubeconfig = NormalizeEscapedJson(kubeconfig);

        // Validate it's a JSON object
        if (!kubeconfig.TrimStart().StartsWith("{"))
        {
            _logger.LogError("kubeconfig is not a JSON object");
            throw new KubeConfigException(
                "kubeconfig is not a JSON object, please provide a valid kubeconfig in JSON format. " +
                "For more information on how to create a kubeconfig file, please visit: " +
                "https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#get_service_account_credssh");
        }

        return kubeconfig;
    }

    /// <summary>
    /// Attempts to decode a base64-encoded kubeconfig.
    /// </summary>
    private string TryDecodeBase64(string kubeconfig)
    {
        try
        {
            _logger.LogDebug("Testing if kubeconfig is base64 encoded");
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(kubeconfig));
            _logger.LogDebug("Successfully decoded kubeconfig from base64");
            return decoded;
        }
        catch
        {
            _logger.LogTrace("Kubeconfig is not base64 encoded");
            return kubeconfig;
        }
    }

    /// <summary>
    /// Normalizes escaped JSON by handling backslash escaping properly.
    /// </summary>
    private string NormalizeEscapedJson(string kubeconfig)
    {
        if (!kubeconfig.StartsWith("\\"))
            return kubeconfig;

        _logger.LogDebug("Un-escaping kubeconfig JSON");

        // First convert escaped newlines to actual newlines, then remove escape characters
        // Note: Order matters - handle \\n before removing backslashes
        kubeconfig = kubeconfig.Replace("\\n", "\n");
        kubeconfig = kubeconfig.Replace("\\\"", "\"");
        kubeconfig = kubeconfig.Replace("\\\\", "\\");

        // Remove leading backslash if still present
        if (kubeconfig.StartsWith("\\"))
            kubeconfig = kubeconfig.TrimStart('\\');

        _logger.LogDebug("Successfully un-escaped kubeconfig JSON");
        return kubeconfig;
    }

    /// <summary>
    /// Checks for TLS verification override from environment variable.
    /// </summary>
    private bool CheckTlsVerifyOverride(bool skipTlsVerify)
    {
        var skipTlsEnvStr = Environment.GetEnvironmentVariable(SkipTlsVerifyEnvVar);
        if (string.IsNullOrEmpty(skipTlsEnvStr))
            return skipTlsVerify;

        _logger.LogTrace("{EnvVar} environment variable: {Value}", SkipTlsVerifyEnvVar, skipTlsEnvStr);

        if (bool.TryParse(skipTlsEnvStr, out var skipTlsVerifyEnv) || skipTlsEnvStr == "1")
        {
            if (skipTlsEnvStr == "1") skipTlsVerifyEnv = true;

            if (skipTlsVerifyEnv && !skipTlsVerify)
            {
                _logger.LogError(
                    "SECURITY_CONFIG_OVERRIDE: TLS certificate verification is disabled via environment variable " +
                    "{EnvVar}={EnvValue}. This overrides all other settings and removes server authentication. " +
                    "To re-enable TLS verification, set {EnvVar}=false or remove the environment variable.",
                    SkipTlsVerifyEnvVar, skipTlsEnvStr, SkipTlsVerifyEnvVar);
                return true;
            }
        }

        return skipTlsVerify;
    }

    /// <summary>
    /// Parses the kubeconfig JSON string into a dictionary.
    /// </summary>
    private Dictionary<string, object> ParseJson(string kubeconfig)
    {
        _logger.LogDebug("Parsing kubeconfig as JSON");
        var configDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(kubeconfig);

        if (configDict == null)
            throw new KubeConfigException("Failed to deserialize kubeconfig JSON");

        return configDict;
    }

    /// <summary>
    /// Builds the K8SConfiguration object from the parsed JSON.
    /// </summary>
    private K8SConfiguration BuildConfiguration(Dictionary<string, object> configDict, bool skipTlsVerify)
    {
        var config = new K8SConfiguration
        {
            ApiVersion = configDict["apiVersion"]?.ToString(),
            Kind = configDict["kind"]?.ToString(),
            CurrentContext = configDict["current-context"]?.ToString(),
            Clusters = ParseClusters(configDict, skipTlsVerify),
            Users = ParseUsers(configDict),
            Contexts = ParseContexts(configDict)
        };

        return config;
    }

    /// <summary>
    /// Parses the clusters array from the configuration.
    /// </summary>
    private List<Cluster> ParseClusters(Dictionary<string, object> configDict, bool skipTlsVerify)
    {
        _logger.LogDebug("Parsing clusters");
        var clusters = new List<Cluster>();

        var clustersJson = configDict["clusters"]?.ToString();
        if (string.IsNullOrEmpty(clustersJson))
            return clusters;

        foreach (var clusterMetadata in JsonConvert.DeserializeObject<JArray>(clustersJson))
        {
            var clusterObj = new Cluster
            {
                Name = clusterMetadata["name"]?.ToString(),
                ClusterEndpoint = new ClusterEndpoint
                {
                    Server = clusterMetadata["cluster"]?["server"]?.ToString(),
                    CertificateAuthorityData = clusterMetadata["cluster"]?["certificate-authority-data"]?.ToString(),
                    SkipTlsVerify = skipTlsVerify
                }
            };

            _logger.LogDebug("Cluster metadata - Name: {Name}, Server: {Server}, SkipTlsVerify: {SkipTls}",
                clusterObj.Name, clusterObj.ClusterEndpoint?.Server, skipTlsVerify);

            clusters.Add(clusterObj);
        }

        _logger.LogTrace("Finished parsing clusters");
        return clusters;
    }

    /// <summary>
    /// Parses the users array from the configuration.
    /// </summary>
    private List<User> ParseUsers(Dictionary<string, object> configDict)
    {
        _logger.LogDebug("Parsing users");
        var users = new List<User>();

        var usersJson = configDict["users"]?.ToString();
        if (string.IsNullOrEmpty(usersJson))
            return users;

        foreach (var user in JsonConvert.DeserializeObject<JArray>(usersJson))
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

            users.Add(userObj);
        }

        _logger.LogTrace("Finished parsing users");
        return users;
    }

    /// <summary>
    /// Parses the contexts array from the configuration.
    /// </summary>
    private List<Context> ParseContexts(Dictionary<string, object> configDict)
    {
        _logger.LogDebug("Parsing contexts");
        var contexts = new List<Context>();

        var contextsJson = configDict["contexts"]?.ToString();
        if (string.IsNullOrEmpty(contextsJson))
            return contexts;

        foreach (var ctx in JsonConvert.DeserializeObject<JArray>(contextsJson))
        {
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
                contextObj.Name, contextObj.ContextDetails?.Cluster,
                contextObj.ContextDetails?.Namespace, contextObj.ContextDetails?.User);

            contexts.Add(contextObj);
        }

        _logger.LogTrace("Finished parsing contexts");
        return contexts;
    }
}
