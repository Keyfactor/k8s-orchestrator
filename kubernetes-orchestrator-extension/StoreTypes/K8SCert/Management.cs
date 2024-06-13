// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using k8s.Autorest;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SCert;

public class Management : ManagementBase, IManagementJobExtension
{
    public Management(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    private JobResult NotSupportedResult(ManagementJobConfiguration config)
    {
        Logger.LogError("Operation '{Operation}' is not supported for KubeSecretType: {KubeSecretType}",
            JobConfig.OperationType.GetType(), KubeSecretType);
        Logger.LogInformation("End CREATE MANAGEMENT job '{JobId}' with failure", config.JobId);
        return FailJob("Operation not supported", config.JobHistoryId);
    }
    protected override JobResult HandleCreate(ManagementJobConfiguration config)
    {
        Logger.LogDebug("Entered HandleCreate() for KubeSecretType: {KubeSecretType}", KubeSecretType);
        try
        {
            Logger.LogDebug("Returning NotSupportedResult() for KubeSecretType: {KubeSecretType}", KubeSecretType);
            return NotSupportedResult(config);
        }
        catch (Exception ex)
        {
            Logger.LogError("{Message}", ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            return FailJob(ex.Message, config.JobHistoryId);
        }
    }

    protected override JobResult HandleUpdate(ManagementJobConfiguration config)
    {
        Logger.LogInformation("Updating certificate '{Alias}' in Kubernetes client '{KubeHost}' cert store '{KubeSecretName}' in namespace '{KubeNamespace}'",
            JobCertObj.Alias, KubeHost, KubeSecretName, KubeNamespace);
        Logger.LogDebug("Returning HandleCreate() for KubeSecretType: {KubeSecretType}", KubeSecretType);
        return HandleCreate(config);
    }

    protected override JobResult HandleRemove(ManagementJobConfiguration config)
    {
        Logger.LogInformation(
            "Removing certificate '{Alias}' from Kubernetes client '{KubeHost}' cert store '{KubeSecretName}' in namespace '{KubeNamespace}'",
            JobCertObj.Alias, KubeHost, KubeSecretName, KubeNamespace);
        Logger.LogDebug("Returning HandleCreate() for KubeSecretType: {KubeSecretType}", KubeSecretType);
        return HandleCreate(config);
    }
}