// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using k8s.Autorest;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SJKS;
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SPKCS12;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.PKI.PEM;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

public abstract class ManagementBase : JobBase
{
    protected K8SJobCertificate JobCertObj { get; set; }
 
    protected ManagementJobConfiguration JobConfig { get; set; }
    //Job Entry Point
    protected void Init(ManagementJobConfiguration config)
    {
        //METHOD ARGUMENTS...
        //config - contains context information passed from KF Command to this job run:
        //
        // config.Server.Username, config.Server.Password - credentials for orchestrated server - use to authenticate to certificate store server.
        //
        // config.ServerUsername, config.ServerPassword - credentials for orchestrated server - use to authenticate to certificate store server.
        // config.CertificateStoreDetails.ClientMachine - server name or IP address of orchestrated server
        // config.CertificateStoreDetails.StorePath - location path of certificate store on orchestrated server
        // config.CertificateStoreDetails.StorePassword - if the certificate store has a password, it would be passed here
        // config.CertificateStoreDetails.Properties - JSON string containing custom store properties for this specific store type
        //
        // config.JobCertificate.EntryContents - Base64 encoded string representation (PKCS12 if private key is included, DER if not) of the certificate to add for Management-Add jobs.
        // config.JobCertificate.Alias - optional string value of certificate alias (used in java keystores and some other store types)
        // config.OperationType - enumeration representing function with job type.  Used only with Management jobs where this value determines whether the Management job is a CREATE/ADD/REMOVE job.
        // config.Overwrite - Boolean value telling the Orchestrator Extension whether to overwrite an existing certificate in a store.  How you determine whether a certificate is "the same" as the one provided is AnyAgent implementation dependent
        // config.JobCertificate.PrivateKeyPassword - For a Management Add job, if the certificate being added includes the private key (therefore, a pfx is passed in config.JobCertificate.EntryContents), this will be the password for the pfx.

        //NLog Logging to c:\CMS\Logs\CMS_Agent_Log.txt

        Logger = LogHandler.GetClassLogger(GetType());
        Logger.LogInformation("Begin MANAGEMENT for K8S Orchestrator Extension for job '{JobId}'", config.JobHistoryId);
        Logger.LogInformation("Management for store type: {Capability}", config.Capability);

        JobConfig = config;
        
        Logger.LogDebug("Calling InitializeStore()");
        InitializeStore(config);
        Logger.LogDebug("Returned from InitializeStore()");

        Logger.LogDebug("Calling InitializeJobCertificate()");
        JobCertObj = InitJobCertificate(config);
        Logger.LogDebug("Returned from InitializeJobCertificate()");

        JobCertObj.PasswordIsK8SSecret = PasswordIsK8SSecret;
        Logger.LogTrace("PasswordIsK8SSecret: {PasswordIsK8SSecret}", PasswordIsK8SSecret);
        JobCertObj.StorePasswordPath = StorePasswordPath;
        Logger.LogTrace("StorePasswordPath: {StorePasswordPath}", StorePasswordPath);

        var storePath = config.CertificateStoreDetails.StorePath;
        Logger.LogTrace("StorePath: {StorePath}", storePath);
        var canonicalStorePath = GetStorePath();
        Logger.LogTrace("Canonical Store Path: {StorePath}", canonicalStorePath);
        var certPassword = config.JobCertificate.PrivateKeyPassword ?? string.Empty;
        Logger.LogTrace("{Message}",
            string.IsNullOrEmpty(certPassword) ? "CertPassword is empty" : "CertPassword is not empty");
    }

    public JobResult ProcessJob(ManagementJobConfiguration config)
    {
        //METHOD ARGUMENTS...
        //config - contains context information passed from KF Command to this job run:
        //
        // config.Server.Username, config.Server.Password - credentials for orchestrated server - use to authenticate to certificate store server.
        //
        // config.ServerUsername, config.ServerPassword - credentials for orchestrated server - use to authenticate to certificate store server.
        // config.CertificateStoreDetails.ClientMachine - server name or IP address of orchestrated server
        // config.CertificateStoreDetails.StorePath - location path of certificate store on orchestrated server
        // config.CertificateStoreDetails.StorePassword - if the certificate store has a password, it would be passed here
        // config.CertificateStoreDetails.Properties - JSON string containing custom store properties for this specific store type
        //
        // config.JobCertificate.EntryContents - Base64 encoded string representation (PKCS12 if private key is included, DER if not) of the certificate to add for Management-Add jobs.
        // config.JobCertificate.Alias - optional string value of certificate alias (used in java keystores and some other store types)
        // config.OperationType - enumeration representing function with job type.  Used only with Management jobs where this value determines whether the Management job is a CREATE/ADD/REMOVE job.
        // config.Overwrite - Boolean value telling the Orchestrator Extension whether to overwrite an existing certificate in a store.  How you determine whether a certificate is "the same" as the one provided is AnyAgent implementation dependent
        // config.JobCertificate.PrivateKeyPassword - For a Management Add job, if the certificate being added includes the private key (therefore, a pfx is passed in config.JobCertificate.EntryContents), this will be the password for the pfx.

        //NLog Logging to c:\CMS\Logs\CMS_Agent_Log.txt
        try
        {
            Init(config: config);

            Logger.LogTrace("Entering switch statement for OperationType");
            switch (config.OperationType)
            {
                case CertStoreOperationType.Add:
                case CertStoreOperationType.Create:
                    //OperationType == Add - Add a certificate to the certificate store passed in the config object
                    Logger.LogInformation(
                        "Processing Management-{OpType} job for certificate '{Alias}'", config.OperationType.GetType(),
                        config.JobCertificate.Alias);
                    return HandleCreateOrUpdate(config);
                case CertStoreOperationType.Remove:
                    Logger.LogInformation(
                        "Processing Management-{OpType} job for certificate '{Alias}'", config.OperationType.GetType(),
                        config.JobCertificate.Alias);
                    Logger.LogDebug("Returning HandleRemove() for KubeSecretType: {KubeSecretType}", KubeSecretType);
                    return HandleRemove(config);
                case CertStoreOperationType.Unknown:
                case CertStoreOperationType.Inventory:
                case CertStoreOperationType.CreateAdd:
                case CertStoreOperationType.Reenrollment:
                case CertStoreOperationType.Discovery:
                case CertStoreOperationType.SetPassword:
                case CertStoreOperationType.FetchLogs:
                default:
                    //Invalid OperationType.  Return error.  Should never happen though
                    Logger.LogInformation("End MANAGEMENT for K8S Orchestrator Extension for job '{JobId}' operation '{OperationType}' not supported",
                        JobConfig.JobId, JobConfig.OperationType.GetType());
                    return FailJob(
                        $"OperationType '{JobConfig.OperationType.GetType()}' not supported by Kubernetes certificate store job.",
                        config.JobHistoryId);
            }
        }
        catch (Exception ex)
        {
            Logger.LogError("{Message}",ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogInformation("End MANAGEMENT for K8S Orchestrator Extension for job '{JobId}' in failure",
                JobConfig.JobId);
            return FailJob(ex.Message, config.JobHistoryId);
        }
    }

    protected V1Secret CreatEmptySecret(string secretType)
    {
        Logger.LogWarning(
            "Certificate object and certificate alias are both null or empty.  Assuming this is a 'create_store' action and populating an empty store.");
        var emptyStrArray = Array.Empty<string>();
        var createResponse = KubeClient.CreateOrUpdateCertificateStoreSecret(
            "",
            "",
            new List<string>(),
            KubeSecretName,
            KubeNamespace,
            secretType,
            false,
            true
        );
        Logger.LogTrace(createResponse.ToString());
        Logger.LogInformation(
            $"Successfully created or updated secret '{KubeSecretName}' in Kubernetes namespace '{KubeNamespace}' on cluster '{KubeClient.GetHost()}' with no data.");
        return createResponse;
    }

    protected virtual JobResult HandleCreateOrUpdate(ManagementJobConfiguration config)
    {
        Logger.LogInformation("Creating or updating certificate '{Alias}' in Kubernetes client '{KubeHost}' cert store '{KubeSecretName}' in namespace '{KubeNamespace}'",
            JobCertObj.Alias, KubeHost, KubeSecretName, KubeNamespace);
        Logger.LogDebug("Returning HandleCreate() for KubeSecretType: {KubeSecretType}", KubeSecretType);
        return HandleCreate(config);
    }

    protected abstract JobResult HandleCreate(ManagementJobConfiguration config);
    
    protected virtual JobResult HandleUpdate(ManagementJobConfiguration config)
    {
        Logger.LogInformation("Updating certificate '{Alias}' in Kubernetes client '{KubeHost}' cert store '{KubeSecretName}' in namespace '{KubeNamespace}'",
            JobCertObj.Alias, KubeHost, KubeSecretName, KubeNamespace);
        Logger.LogDebug("Returning HandleCreate() for KubeSecretType: {KubeSecretType}", KubeSecretType);
        return HandleCreate(config);
    }
    protected virtual JobResult HandleRemove(ManagementJobConfiguration config)
    {
        Logger.LogInformation(
            "Removing certificate '{Alias}' from Kubernetes client '{KubeHost}' cert store '{KubeSecretName}' in namespace '{KubeNamespace}'",
            JobCertObj.Alias, KubeHost, KubeSecretName, KubeNamespace);
        try
        {
            Logger.LogDebug(
                "Calling KubeClient.DeleteCertificateStoreSecret() with KubeSecretName: {KubeSecretName}, KubeNamespace: {KubeNamespace}, KubeSecretType: {KubeSecretType}, JobCertObj.Alias: {Alias}",
                KubeSecretName, KubeNamespace, KubeSecretType, JobCertObj.Alias);
            var response = KubeClient.DeleteCertificateStoreSecret(
                KubeSecretName,
                KubeNamespace,
                KubeSecretType,
                JobCertObj.Alias
            );
            Logger.LogDebug("Returned from KubeClient.DeleteCertificateStoreSecret()");
            Logger.LogTrace("Response: {Response}", response);
        }
        catch (HttpOperationException rErr)
        {
            Logger.LogError("{Message}", rErr.Message);
            Logger.LogTrace("{Message}", rErr.ToString());
            if (!rErr.Message.Contains("NotFound")) return FailJob(rErr.Message, config.JobHistoryId);

            var certDataErrorMsg =
                $"Kubernetes secret type '{KubeSecretType}' named '{KubeSecretName}' was not found in namespace '{KubeNamespace}' on Kubernetes client '{KubeHost}'";
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Success,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = certDataErrorMsg
            };
        }
        catch (Exception e)
        {
            Logger.LogError(e,
                "Error removing certificate '{Alias}' from Kubernetes client '{KubeHost}' cert store {KubeSecretName} in namespace {KubeNamespace}",
                JobCertObj.Alias, KubeHost, KubeSecretName, KubeNamespace);
            Logger.LogInformation("End REMOVE MANAGEMENT job '{JobId}' with failure", config.JobId);
            return FailJob(e.Message, config.JobHistoryId);
        }

        Logger.LogInformation("End REMOVE MANAGEMENT job '{JobId}' with success", config.JobId);
        return SuccessJob(config.JobHistoryId);
    }
}