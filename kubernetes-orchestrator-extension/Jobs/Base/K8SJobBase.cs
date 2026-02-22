// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;

/// <summary>
/// Slimmed-down base class for store-type-specific job implementations.
/// Provides shared infrastructure for logging, PAM resolution, Kubernetes client creation,
/// and job result helpers. Does NOT contain store-type-specific logic.
/// </summary>
public abstract class K8SJobBase
{
    /// <summary>
    /// Logger instance for this job.
    /// </summary>
    protected ILogger Logger;

    /// <summary>
    /// PAM secret resolver for retrieving secrets from Privileged Access Management systems.
    /// </summary>
    protected IPAMSecretResolver Resolver;

    /// <summary>
    /// Kubernetes client for API operations.
    /// </summary>
    protected KubeCertificateManagerClient KubeClient;

    /// <summary>
    /// Service for parsing job configurations into SecretOperationContext.
    /// </summary>
    protected JobConfigurationParser ConfigParser;

    /// <summary>
    /// Service for resolving credentials and passwords.
    /// </summary>
    protected CredentialResolver CredResolver;

    /// <summary>
    /// Service for processing certificate data from jobs.
    /// </summary>
    protected CertificateProcessor CertProcessor;

    /// <summary>
    /// Factory for creating store-type-specific secret handlers.
    /// </summary>
    protected SecretHandlerFactory HandlerFactory;

    /// <summary>
    /// Creates a new K8SJobBase with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    protected K8SJobBase(IPAMSecretResolver resolver)
    {
        Resolver = resolver;
    }

    /// <summary>
    /// Initializes the job infrastructure including logger and service instances.
    /// </summary>
    protected virtual void InitializeInfrastructure()
    {
        Logger ??= LogHandler.GetClassLogger(GetType());
        ConfigParser ??= new JobConfigurationParser(Logger);
        CredResolver ??= new CredentialResolver(Logger);
        CertProcessor ??= new CertificateProcessor(Logger);
    }

    /// <summary>
    /// Initializes the Kubernetes client using the provided credentials and SSL setting.
    /// </summary>
    /// <param name="kubeconfig">The kubeconfig JSON for Kubernetes API authentication.</param>
    /// <param name="useSSL">Whether to validate SSL/TLS certificates.</param>
    /// <exception cref="InvalidOperationException">Thrown when client creation fails.</exception>
    protected virtual void InitializeKubeClient(string kubeconfig, bool useSSL)
    {
        Logger.LogDebug("Initializing Kubernetes client");
        KubeClient = new KubeCertificateManagerClient(kubeconfig, useSSL);

        if (KubeClient == null)
        {
            throw new InvalidOperationException("Failed to create KubeCertificateManagerClient");
        }

        Logger.LogDebug("Kubernetes client initialized successfully. Host: {Host}", KubeClient.GetHost());
    }

    /// <summary>
    /// Initializes the SecretHandlerFactory with job properties.
    /// </summary>
    /// <param name="jobProperties">Optional job properties JSON for handler configuration.</param>
    protected virtual void InitializeHandlerFactory(string jobProperties = null)
    {
        HandlerFactory = new SecretHandlerFactory(Logger, jobProperties);
    }

    /// <summary>
    /// Gets the appropriate secret handler for the specified secret type.
    /// </summary>
    /// <param name="secretType">The secret type to get a handler for.</param>
    /// <returns>The appropriate ISecretHandler.</returns>
    protected ISecretHandler GetHandler(SecretType secretType)
    {
        if (HandlerFactory == null)
        {
            InitializeHandlerFactory();
        }

        return HandlerFactory.GetHandler(secretType);
    }

    /// <summary>
    /// Creates a successful JobResult.
    /// </summary>
    /// <param name="jobHistoryId">The job history ID.</param>
    /// <param name="message">Optional success message.</param>
    /// <returns>A success JobResult.</returns>
    protected JobResult SuccessJob(long jobHistoryId, string message = null)
    {
        Logger?.LogInformation("Job {JobHistoryId} completed successfully", jobHistoryId);
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Success,
            JobHistoryId = jobHistoryId,
            FailureMessage = message
        };
    }

    /// <summary>
    /// Creates a failed JobResult.
    /// </summary>
    /// <param name="errorMessage">The error message.</param>
    /// <param name="jobHistoryId">The job history ID.</param>
    /// <returns>A failure JobResult.</returns>
    protected JobResult FailJob(string errorMessage, long jobHistoryId)
    {
        Logger?.LogError("Job {JobHistoryId} failed: {ErrorMessage}", jobHistoryId, errorMessage);
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Failure,
            JobHistoryId = jobHistoryId,
            FailureMessage = errorMessage
        };
    }

    /// <summary>
    /// Creates a warning JobResult.
    /// </summary>
    /// <param name="warningMessage">The warning message.</param>
    /// <param name="jobHistoryId">The job history ID.</param>
    /// <returns>A warning JobResult.</returns>
    protected JobResult WarningJob(string warningMessage, long jobHistoryId)
    {
        Logger?.LogWarning("Job {JobHistoryId} completed with warning: {WarningMessage}", jobHistoryId, warningMessage);
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Warning,
            JobHistoryId = jobHistoryId,
            FailureMessage = warningMessage
        };
    }

    /// <summary>
    /// Gets the secret type that this job class handles.
    /// Store-type-specific implementations override this to return their secret type.
    /// </summary>
    protected abstract SecretType GetSecretType();

    /// <summary>
    /// Gets the store type that this job class handles.
    /// Store-type-specific implementations override this to return their store type.
    /// </summary>
    protected abstract StoreType GetStoreType();

    /// <summary>
    /// Gets the extension name for this job.
    /// Required by IOrchestratorJobExtension interface.
    /// </summary>
    public string ExtensionName => "K8S";
}
