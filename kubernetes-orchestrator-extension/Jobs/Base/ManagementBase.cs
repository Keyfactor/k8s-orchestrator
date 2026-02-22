// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;

/// <summary>
/// Base class for store-type-specific management job implementations.
/// Provides shared infrastructure for processing Add and Remove operations using the handler pattern.
/// </summary>
public abstract class ManagementBase : K8SJobBase, IManagementJobExtension
{
    /// <summary>
    /// Creates a new ManagementBase with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    protected ManagementBase(IPAMSecretResolver resolver) : base(resolver)
    {
    }

    /// <summary>
    /// Main entry point for the management job.
    /// Processes Add, Remove, or Create operations for certificates.
    /// </summary>
    /// <param name="config">Management job configuration containing operation details and certificate data.</param>
    /// <returns>JobResult indicating success or failure of the management operation.</returns>
    public JobResult ProcessJob(ManagementJobConfiguration config)
    {
        InitializeInfrastructure();
        Logger.MethodEntry(MsLogLevel.Debug);

        try
        {
            Logger.LogInformation("Begin MANAGEMENT for {StoreType} job {JobId} - Operation: {OperationType}",
                GetStoreType(), config.JobId, config.OperationType);

            // Parse configuration
            var context = ConfigParser.ParseConfig(config);
            Logger.LogDebug("Parsed config - Namespace: {Namespace}, SecretName: {SecretName}, StoreType: {StoreType}",
                context.Namespace, context.SecretName, context.StoreType);

            // Initialize Kubernetes client
            InitializeKubeClient(config.ServerPassword, true);

            // Initialize handler factory with job properties
            InitializeHandlerFactory(config.CertificateStoreDetails?.Properties);

            // Get the handler
            var handler = GetHandler(GetSecretType());

            // Route based on operation type
            return config.OperationType switch
            {
                CertStoreOperationType.Add or CertStoreOperationType.Create =>
                    ProcessAdd(config, context, handler),

                CertStoreOperationType.Remove =>
                    ProcessRemove(config, context, handler),

                _ => FailJob(
                    $"Operation type '{config.OperationType}' is not supported for {GetStoreType()}",
                    config.JobHistoryId)
            };
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Management failed: {Message}", ex.Message);
            return FailJob(ex.Message, config.JobHistoryId);
        }
        finally
        {
            Logger.LogInformation("End MANAGEMENT for {StoreType} job {JobId}",
                GetStoreType(), config.JobId);
            Logger.MethodExit(MsLogLevel.Debug);
        }
    }

    /// <summary>
    /// Processes an Add operation by parsing the certificate and delegating to the handler.
    /// </summary>
    /// <param name="config">The management job configuration.</param>
    /// <param name="context">The parsed operation context.</param>
    /// <param name="handler">The handler to use for the operation.</param>
    /// <returns>JobResult indicating success or failure.</returns>
    protected virtual JobResult ProcessAdd(
        ManagementJobConfiguration config,
        Models.SecretOperationContext context,
        Handlers.ISecretHandler handler)
    {
        Logger.LogDebug("Processing Add operation for certificate alias: {Alias}",
            config.JobCertificate?.Alias ?? "(none)");

        // Parse the job certificate
        var certificate = ParseJobCertificate(config);
        if (certificate == null && !string.IsNullOrEmpty(config.JobCertificate?.Contents))
        {
            return FailJob("Failed to parse certificate from job configuration", config.JobHistoryId);
        }

        // If no certificate provided, we may be creating an empty store
        if (certificate == null)
        {
            certificate = new K8SJobCertificate { Alias = config.JobCertificate?.Alias };
        }

        // Delegate to handler
        return handler.ProcessAdd(context, certificate, KubeClient);
    }

    /// <summary>
    /// Processes a Remove operation by delegating to the handler.
    /// </summary>
    /// <param name="config">The management job configuration.</param>
    /// <param name="context">The parsed operation context.</param>
    /// <param name="handler">The handler to use for the operation.</param>
    /// <returns>JobResult indicating success or failure.</returns>
    protected virtual JobResult ProcessRemove(
        ManagementJobConfiguration config,
        Models.SecretOperationContext context,
        Handlers.ISecretHandler handler)
    {
        var alias = config.JobCertificate?.Alias;
        Logger.LogDebug("Processing Remove operation for certificate alias: {Alias}", alias);

        return handler.ProcessRemove(context, alias, KubeClient);
    }

    /// <summary>
    /// Parses the job certificate from the configuration.
    /// </summary>
    /// <param name="config">The management job configuration.</param>
    /// <returns>The parsed K8SJobCertificate, or null if parsing fails.</returns>
    protected virtual K8SJobCertificate ParseJobCertificate(ManagementJobConfiguration config)
    {
        if (string.IsNullOrEmpty(config.JobCertificate?.Contents))
        {
            Logger.LogDebug("No certificate contents provided");
            return null;
        }

        CertProcessor ??= new CertificateProcessor(Logger);

        var certificate = CertProcessor.ParseJobCertificate(
            config.JobCertificate.Contents,
            config.JobCertificate.PrivateKeyPassword);

        if (certificate != null)
        {
            certificate.Alias = config.JobCertificate.Alias;
        }

        return certificate;
    }
}
