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

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SNS;

public class Management : ManagementBase, IManagementJobExtension
{
    public Management(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    private void ParseStorePath()
    {
        Logger.LogDebug("Entered ParseStorePath() for KubeSecretType: {KubeSecretType}", KubeSecretType);
        
        Logger.LogDebug("Attempting to split Alias '{Alias}' by '/'", JobCertObj.Alias);
        var nsSplitAlias = JobCertObj.Alias.Split("/");
        Logger.LogTrace("Split Alias: {ClusterSplitAlias}", nsSplitAlias.ToString());
                
        // Check splitAlias length
        if (nsSplitAlias.Length < 2)
        {
            var invalidAliasErrMsg = $"Invalid alias format '{JobCertObj.Alias}' for K8SNS store type pattern is `<secret_type>/<secret_name>`";
            Logger.LogError("{Message}", invalidAliasErrMsg);
            throw new InvalidCertificateAlias(invalidAliasErrMsg);
        }
        
        KubeSecretType = nsSplitAlias[^2]; //secret type must always come before secret name
        Logger.LogTrace("KubeSecretType: {KubeSecretType}", KubeSecretType);
        KubeSecretName = nsSplitAlias[^1]; //secret name must always come last
        Logger.LogTrace("KubeSecretName: {KubeSecretName}", KubeSecretName);
        
        Logger.LogDebug("Returning from ParseStorePath()");
        
    }
    protected override JobResult HandleCreate(ManagementJobConfiguration config)
    {
        Logger.LogDebug("Entered HandleCreate() for KubeSecretType: {KubeSecretType}", KubeSecretType);
        ParseStorePath();
        try
        {
            if (string.IsNullOrEmpty(JobCertObj.Alias) && string.IsNullOrEmpty(JobCertObj.CertPem))
            {
                Logger.LogWarning("Certificate '{Thumbprint}' with alias '{Alias}' is empty, creating empty secret",
                    JobCertObj.CertThumbprint, JobCertObj.Alias);
                var emptySecret = creatEmptySecret(KubeSecretType);
                if (emptySecret != null)
                {
                    Logger.LogInformation("Successfully created empty secret for certificate '{Alias}'",
                        JobCertObj.Alias);
                    return SuccessJob(config.JobHistoryId);
                }

                Logger.LogError("Failed to create empty secret for certificate '{Alias}'", JobCertObj.Alias);
                return FailJob("Failed to create empty secret", config.JobHistoryId);
            }
            
            switch (KubeSecretType)
            {
                case "tls_secret":
                case "tls":
                    Logger.LogDebug("Cluster secret type is 'tls', calling K8STLSSecr.Management()");
                    var tlsJob = new Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8STLSSecr.Management(_resolver);
                    
                    config.JobProperties["KubeSecretType"] = KubeSecretType;
                    Logger.LogDebug("Returning tlsJob.ProcessJob() for K8STLSSecr.Management()");
                    return tlsJob.ProcessJob(config);
                case "opaque":
                    Logger.LogDebug("Cluster secret type is 'opaque', calling K8SSecret.Management()");
                    var opaqueJob = new Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SSecret.Management(_resolver);
                    Logger.LogDebug("Returning opaqueJob.ProcessJob() for K8SSecret.Management()");
                    
                    config.JobProperties["KubeSecretType"] = KubeSecretType;
                    return opaqueJob.ProcessJob(config);
                default:
                {
                    var nsErrMsg = $"Unsupported secret type '{KubeSecretType}' for store types of '{Capability}'";
                    Logger.LogError("{Message}", nsErrMsg);
                    Logger.LogInformation("End MANAGEMENT job '{JobId}' with failure", config.JobId);
                    return FailJob(nsErrMsg, config.JobHistoryId);
                }
            }
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
}