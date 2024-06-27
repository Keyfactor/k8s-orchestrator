// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8STLSSecr;

public class Management : ManagementBase, IManagementJobExtension
{
    public Management(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    protected override JobResult HandleCreate(ManagementJobConfiguration config)
    {
        Logger.LogDebug("Entered HandleCreate() for KubeSecretType: {KubeSecretType}", KubeSecretType);
        try
        {
            if (string.IsNullOrEmpty(JobCertObj.Alias) && string.IsNullOrEmpty(JobCertObj.CertPem))
            {
                Logger.LogWarning("Certificate '{Thumbprint}' with alias '{Alias}' is empty, creating empty secret",
                    JobCertObj.CertThumbprint, JobCertObj.Alias);
                var emptySecret = CreatEmptySecret(KubeSecretType);
                if (emptySecret != null)
                {
                    Logger.LogInformation("Successfully created empty secret for certificate '{Alias}'",
                        JobCertObj.Alias);
                    return SuccessJob(config.JobHistoryId);
                }

                Logger.LogError("Failed to create empty secret for certificate '{Alias}'", JobCertObj.Alias);
                return FailJob("Failed to create empty secret", config.JobHistoryId);
            }
            
            Logger.LogDebug(
                "Calling CreateOrUpdateCertificateStoreSecret() to create or update secret in Kubernetes...");
            var createResponse = KubeClient.CreateOrUpdateCertificateStoreSecret(
                JobCertObj.PrivateKeyPem,
                JobCertObj.CertPem,
                JobCertObj.ChainPem,
                KubeSecretName,
                KubeNamespace,
                KubeSecretType,
                true, //todo: is this useful?
                JobConfig.Overwrite
            );
            if (createResponse == null)
            {
                Logger.LogError("Response from Kubernetes client '{KubeHost}' is null. Failed to create secret",
                    KubeHost);
                return FailJob("No response from Kubernetes client", config.JobHistoryId);
            }

            Logger.LogTrace("{Response}", createResponse.ToString());

            Logger.LogInformation(
                "Successfully created secret '{KubeSecretName}' in Kubernetes namespace '{KubeNamespace}' on cluster '{KubeHost}' with certificate '{Alias}'",
                KubeSecretName, KubeNamespace, KubeHost, JobCertObj.Alias);
            
            Logger.LogInformation("End CREATE MANAGEMENT job '{JobId}' with success", config.JobId);
            Logger.LogDebug("Returning SuccessJob() for JobHistoryId: {JobHistoryId}", config.JobHistoryId);
            return SuccessJob(config.JobHistoryId);
        }
        catch (Exception ex)
        {
            Logger.LogError("{Message}", ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            return FailJob(ex.Message, config.JobHistoryId);
        }
    }
}