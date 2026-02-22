// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Constants;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.Orchestrator.K8S.Services;

/// <summary>
/// Service for parsing job configurations into SecretOperationContext objects.
/// Extracts and normalizes configuration from various job types.
/// </summary>
public class JobConfigurationParser
{
    private readonly ILogger _logger;
    private readonly StorePathResolver _pathResolver;

    /// <summary>
    /// Creates a new JobConfigurationParser.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    public JobConfigurationParser(ILogger logger = null)
    {
        _logger = logger ?? LogHandler.GetClassLogger(typeof(JobConfigurationParser));
        _pathResolver = new StorePathResolver(logger);
    }

    /// <summary>
    /// Parses an inventory job configuration into a SecretOperationContext.
    /// </summary>
    /// <param name="config">The inventory job configuration.</param>
    /// <returns>Populated SecretOperationContext.</returns>
    public SecretOperationContext ParseConfig(InventoryJobConfiguration config)
    {
        _logger.LogDebug("Parsing InventoryJobConfiguration for capability: {Capability}", config.Capability);

        var context = new SecretOperationContext
        {
            Capability = config.Capability,
            JobHistoryId = config.JobHistoryId,
            JobId = config.JobId,
            StorePath = config.CertificateStoreDetails?.StorePath ?? ""
        };

        var storeType = SecretTypeParser.ParseStoreType(config.Capability);
        context.StoreType = storeType;
        context.SecretType = SecretTypeParser.GetDefaultSecretType(storeType);

        // Parse store properties
        var props = ParseProperties(config.CertificateStoreDetails?.Properties);
        PopulateContextFromProperties(context, props);

        // Resolve store path
        var pathInfo = _pathResolver.Resolve(
            context.StorePath,
            storeType,
            context.Namespace,
            context.SecretName);

        if (pathInfo.IsValid)
        {
            context.Namespace = pathInfo.Namespace;
            context.SecretName = pathInfo.SecretName;
            context.SecretType = pathInfo.SecretType != SecretType.Unknown
                ? pathInfo.SecretType
                : context.SecretType;
        }

        // Get store password
        context.StorePassword = config.CertificateStoreDetails?.StorePassword ?? "";

        _logger.LogInformation(
            "Parsed inventory config: Namespace={Namespace}, SecretName={SecretName}, StoreType={StoreType}",
            context.Namespace, context.SecretName, context.StoreType);

        return context;
    }

    /// <summary>
    /// Parses a management job configuration into a SecretOperationContext.
    /// </summary>
    /// <param name="config">The management job configuration.</param>
    /// <returns>Populated SecretOperationContext.</returns>
    public SecretOperationContext ParseConfig(ManagementJobConfiguration config)
    {
        _logger.LogDebug("Parsing ManagementJobConfiguration for capability: {Capability}", config.Capability);

        var context = new SecretOperationContext
        {
            Capability = config.Capability,
            JobHistoryId = config.JobHistoryId,
            JobId = config.JobId,
            StorePath = config.CertificateStoreDetails?.StorePath ?? "",
            Overwrite = config.Overwrite
        };

        var storeType = SecretTypeParser.ParseStoreType(config.Capability);
        context.StoreType = storeType;
        context.SecretType = SecretTypeParser.GetDefaultSecretType(storeType);

        // Parse store properties
        var props = ParseProperties(config.CertificateStoreDetails?.Properties);
        PopulateContextFromProperties(context, props);

        // Resolve store path
        var pathInfo = _pathResolver.Resolve(
            context.StorePath,
            storeType,
            context.Namespace,
            context.SecretName);

        if (pathInfo.IsValid)
        {
            context.Namespace = pathInfo.Namespace;
            context.SecretName = pathInfo.SecretName;
            context.SecretType = pathInfo.SecretType != SecretType.Unknown
                ? pathInfo.SecretType
                : context.SecretType;
        }

        // Get store password
        context.StorePassword = config.CertificateStoreDetails?.StorePassword ?? "";

        _logger.LogInformation(
            "Parsed management config: Namespace={Namespace}, SecretName={SecretName}, StoreType={StoreType}, Overwrite={Overwrite}",
            context.Namespace, context.SecretName, context.StoreType, context.Overwrite);

        return context;
    }

    /// <summary>
    /// Parses a discovery job configuration into a SecretOperationContext.
    /// </summary>
    /// <param name="config">The discovery job configuration.</param>
    /// <returns>Populated SecretOperationContext.</returns>
    public SecretOperationContext ParseConfig(DiscoveryJobConfiguration config)
    {
        _logger.LogDebug("Parsing DiscoveryJobConfiguration for capability: {Capability}", config.Capability);

        var context = new SecretOperationContext
        {
            Capability = config.Capability,
            JobHistoryId = config.JobHistoryId,
            JobId = config.JobId
        };

        var storeType = SecretTypeParser.ParseStoreType(config.Capability);
        context.StoreType = storeType;
        context.SecretType = SecretTypeParser.GetDefaultSecretType(storeType);

        _logger.LogInformation(
            "Parsed discovery config: StoreType={StoreType}",
            context.StoreType);

        return context;
    }

    private dynamic ParseProperties(string propertiesJson)
    {
        if (string.IsNullOrEmpty(propertiesJson))
        {
            _logger.LogDebug("No properties to parse");
            return null;
        }

        try
        {
            return JsonConvert.DeserializeObject(propertiesJson);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse properties JSON: {Error}", ex.Message);
            return null;
        }
    }

    private void PopulateContextFromProperties(SecretOperationContext context, dynamic props)
    {
        if (props == null)
            return;

        try
        {
            // Extract namespace
            if (HasProperty(props, "KubeNamespace"))
            {
                context.Namespace = (string)props["KubeNamespace"] ?? "";
            }

            // Extract secret name
            if (HasProperty(props, "KubeSecretName"))
            {
                context.SecretName = (string)props["KubeSecretName"] ?? "";
            }

            // Extract secret type
            if (HasProperty(props, "KubeSecretType"))
            {
                var secretTypeStr = (string)props["KubeSecretType"] ?? "";
                var parsedType = SecretTypeParser.ParseSecretType(secretTypeStr);
                if (parsedType != SecretType.Unknown)
                {
                    context.SecretType = parsedType;
                }
            }

            // Extract password configuration
            if (HasProperty(props, "PasswordIsSeparateSecret"))
            {
                context.PasswordIsK8SSecret = (bool)props["PasswordIsSeparateSecret"];
            }

            if (HasProperty(props, "StorePasswordPath"))
            {
                context.PasswordSecretPath = (string)props["StorePasswordPath"] ?? "";
            }

            if (HasProperty(props, "PasswordFieldName"))
            {
                context.PasswordFieldName = (string)props["PasswordFieldName"] ?? SecretFieldNames.DefaultPassword;
            }

            // Extract certificate data field name
            if (HasProperty(props, "KubeSecretKey"))
            {
                context.CertDataFieldName = (string)props["KubeSecretKey"] ?? "";
            }

            // Extract chain options
            if (HasProperty(props, "SeparateChain"))
            {
                context.SeparateChain = (bool)props["SeparateChain"];
            }

            if (HasProperty(props, "IncludeCertChain"))
            {
                context.IncludeCertChain = (bool)props["IncludeCertChain"];
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error extracting properties: {Error}", ex.Message);
        }
    }

    private static bool HasProperty(dynamic obj, string propertyName)
    {
        if (obj == null)
            return false;

        try
        {
            return obj.ContainsKey(propertyName);
        }
        catch
        {
            return false;
        }
    }
}
