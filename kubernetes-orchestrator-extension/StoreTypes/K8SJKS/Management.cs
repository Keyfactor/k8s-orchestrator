// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SJKS;

public class Management : ManagementBase, IManagementJobExtension
{
    private KubeCertificateManagerClient.JksSecret _secret;

    private JksCertificateStoreSerializer _serializedStore;

    private const string K8SSecretFieldName = "jks";

    public Management(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    private byte[] ReadSecret()
    {
        Logger.LogDebug("Attempting to serialize JKS store");
        _serializedStore = new JksCertificateStoreSerializer(JobConfig.JobProperties?.ToString());
        //getJksBytesFromKubeSecret
        _secret = new KubeCertificateManagerClient.JksSecret();
        if (JobConfig.OperationType is CertStoreOperationType.Add or CertStoreOperationType.Remove)
        {
            Logger.LogTrace("OperationType is: {OperationType}", JobConfig.OperationType.GetType());
            try
            {
                Logger.LogDebug("Attempting to get JKS store from Kubernetes secret {Name} in namespace {Namespace}",
                    KubeSecretName, KubeNamespace);
                _secret = KubeClient.GetJksSecret(KubeSecretName, KubeNamespace);
            }
            catch (StoreNotFoundException ex)
            {
                Logger.LogWarning("'{SecretType}' '{Name}' not found in Kubernetes namespace '{Ns}'", KubeSecretType,
                    KubeSecretName, KubeNamespace);
                Logger.LogError("{Message}", ex.Message);
                Logger.LogTrace("{Message}", ex.ToString());
                if (JobConfig.OperationType != CertStoreOperationType.Remove) throw;
                Logger.LogWarning("Secret '{Name}' not found in Kubernetes namespace '{Ns}' so nothing to remove...",
                    KubeSecretName, KubeNamespace);
                return null;
            }
        }

        // get newCert bytes from config.JobCertificate.Contents
        Logger.LogDebug("Attempting to get newCert bytes from config.JobCertificate.Contents");
        var existingDataFieldName = "jks"; //todo: should this be configurable?
        // if alias contains a '/' then the pattern is 'k8s-secret-field-name/alias'
        if (K8SCertificate.Alias.Contains('/'))
        {
            Logger.LogDebug("alias contains a '/' so splitting on '/'...");
            var aliasParts = K8SCertificate.Alias.Split("/");
            existingDataFieldName = aliasParts[0];
            K8SCertificate.Alias = aliasParts[1];
        }

        Logger.LogTrace("existingDataFieldName: {Name}", existingDataFieldName);
        Logger.LogTrace("alias: {Alias}", K8SCertificate.Alias);
        byte[] existingData = null;
        if (_secret.Secret?.Data != null)
        {
            Logger.LogDebug(
                "k8sData.Secret.Data is not null so attempting to get existingData from secret data field {Name}...",
                existingDataFieldName);
            existingData = _secret.Secret.Data.TryGetValue(existingDataFieldName, out var value) ? value : null;
        }

        if (!string.IsNullOrEmpty(K8SCertificate.StorePassword))
        {
            Logger.LogDebug(
                "StorePassword is not null or empty so setting StorePassword to config.CertificateStoreDetails.StorePassword");
            StorePassword = K8SCertificate.StorePassword;
            var hashedStorePassword = GetSha256Hash(StorePassword);
            Logger.LogTrace("hashedStorePassword: {Hash}", hashedStorePassword);
        }

        Logger.LogDebug("Getting store password");
        StorePassword = GetK8SStorePassword(_secret.Secret);
        return existingData;
    }

    protected override JobResult HandleCreate(ManagementJobConfiguration config)
    {
        Logger.LogDebug("Entered HandleCreate() for KubeSecretType: {KubeSecretType}", KubeSecretType);
        try
        {
            var existingK8SSecretData = ReadSecret();
            var newCertBytes = Convert.FromBase64String(config.JobCertificate.Contents);
            var newJksStore = _serializedStore.CreateOrUpdateJks(newCertBytes,
                JobConfig.JobCertificate.PrivateKeyPassword, JobCertObj.Alias, existingK8SSecretData, StorePassword);
            if (_secret.Inventory == null || _secret.Inventory.Count == 0)
            {
                Logger.LogDebug("k8sData.JksInventory is null or empty so creating new Dictionary...");
                _secret.Inventory = new Dictionary<string, byte[]>();
                _secret.Inventory.Add(K8SSecretFieldName, newJksStore);
            }
            else
            {
                Logger.LogDebug("k8sData.JksInventory is not null or empty so updating existing Dictionary...");
                _secret.Inventory[K8SSecretFieldName] = newJksStore;
            }

            // update the secret
            Logger.LogDebug("Calling CreateOrUpdateJksSecret()...");
            var updateResponse = KubeClient.CreateOrUpdateJksSecret(_secret, KubeSecretName, KubeNamespace);
            if (updateResponse == null)
            {
                Logger.LogError("Response from Kubernetes client '{KubeHost}' is null. Failed to create secret",
                    KubeHost);
                return FailJob("No response from Kubernetes client", config.JobHistoryId);
            }

            updateResponse.Data.TryGetValue(K8SSecretFieldName, out var updatedJksStore);
            if (updatedJksStore == null)
            {
                Logger.LogError("Failed to update JKS store Kubernetes secret '{Name}' in namespace '{Namespace}'",
                    KubeSecretName, KubeNamespace);
                return FailJob("Failed to updated JKS store from Kubernetes secret", config.JobHistoryId);
            }

            Logger.LogInformation(
                "Successfully created secret '{KubeSecretName}' in Kubernetes namespace '{KubeNamespace}' on cluster '{KubeHost}' with certificate '{Alias}'",
                KubeSecretName, KubeNamespace, KubeHost, JobCertObj.Alias);

            Logger.LogInformation("End CREATE MANAGEMENT job '{JobId}' with success", config.JobId);
            Logger.LogDebug("Returning SuccessJob() for JobHistoryId: {JobHistoryId}", config.JobHistoryId);
            return SuccessJob(config.JobHistoryId);
        }
        catch (JkSisPkcs12Exception)
        {
            // call a pkcs12 management job
            Logger.LogDebug("Caught JkSisPkcs12Exception so calling PKCS12 management job...");
            config.JobProperties["KubeSecretType"] = KubeSecretType;
            var pkcs12Job = new Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SPKCS12.Management(_resolver)
            {
                SeparateChain = SeparateChain,
                IncludeCertChain = IncludeCertChain,
                OperationType = OperationType,
                SkipTlsValidation = SkipTlsValidation,
                K8SCertificate = K8SCertificate,
                Capability = Capability,
                StorePath = StorePath,
                CertificateDataFieldName = CertificateDataFieldName,
                PasswordFieldName = PasswordFieldName,
                PasswordIsSeparateSecret = PasswordIsSeparateSecret,
                ManagementConfig = config,
                DiscoveryConfig = DiscoveryConfig,
                InventoryConfig = InventoryConfig,
                KubeSecretPassword = KubeSecretPassword
            };
            Logger.LogDebug("Returning pkcs12Job.ProcessJob() for K8SJKS.Management()");
            return pkcs12Job.ProcessJob(config);
        }
        catch (Exception ex)
        {
            Logger.LogError("{Message}", ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            return FailJob(ex.Message, config.JobHistoryId);
        }
    }
}