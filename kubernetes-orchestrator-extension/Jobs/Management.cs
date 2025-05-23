﻿// Copyright 2024 Keyfactor
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

public class Management : JobBase, IManagementJobExtension
{
    public Management(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    //Job Entry Point
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

        Logger = LogHandler.GetClassLogger(GetType());
        K8SJobCertificate jobCertObj;
        try
        {
            InitializeStore(config);
            jobCertObj = InitJobCertificate(config);
            jobCertObj.PasswordIsK8SSecret = PasswordIsK8SSecret;
            jobCertObj.StorePasswordPath = StorePasswordPath;
        }
        catch (Exception e)
        {
            var initErrMsg = "Error initializing job. " + e.Message;
            Logger.LogError(e, initErrMsg);
            return FailJob(initErrMsg, config.JobHistoryId);
        }

        Logger.LogInformation("Begin MANAGEMENT for K8S Orchestrator Extension for job " + config.JobId);
        Logger.LogInformation($"Management for store type: {config.Capability}");

        var storePath = config.CertificateStoreDetails.StorePath;
        Logger.LogTrace("StorePath: " + storePath);
        Logger.LogDebug($"Canonical Store Path: {GetStorePath()}");
        var certPassword = config.JobCertificate.PrivateKeyPassword ?? string.Empty;
        // Logger.LogTrace("CertPassword: " + certPassword);
        Logger.LogDebug(string.IsNullOrEmpty(certPassword) ? "CertPassword is empty" : "CertPassword is not empty");

        //Convert properties string to dictionary
        try
        {
            switch (config.OperationType)
            {
                case CertStoreOperationType.Add:
                case CertStoreOperationType.Create:
                    //OperationType == Add - Add a certificate to the certificate store passed in the config object
                    Logger.LogInformation($"Processing Management-{config.OperationType.GetType()} job for certificate '{config.JobCertificate.Alias}'...");
                    return HandleCreateOrUpdate(KubeSecretType, config, jobCertObj, Overwrite);
                case CertStoreOperationType.Remove:
                    Logger.LogInformation($"Processing Management-{config.OperationType.GetType()} job for certificate '{config.JobCertificate.Alias}'...");
                    return HandleRemove(KubeSecretType, config);
                case CertStoreOperationType.Unknown:
                case CertStoreOperationType.Inventory:
                case CertStoreOperationType.CreateAdd:
                case CertStoreOperationType.Reenrollment:
                case CertStoreOperationType.Discovery:
                case CertStoreOperationType.SetPassword:
                case CertStoreOperationType.FetchLogs:
                    Logger.LogInformation("End MANAGEMENT for K8S Orchestrator Extension for job " + config.JobId +
                                          $" - OperationType '{config.OperationType.GetType()}' not supported by Kubernetes certificate store job. Failed!");
                    return FailJob($"OperationType '{config.OperationType.GetType()}' not supported by Kubernetes certificate store job.", config.JobHistoryId);
                default:
                    //Invalid OperationType.  Return error.  Should never happen though
                    var impError = $"Invalid OperationType '{config.OperationType.GetType()}' passed to Kubernetes certificate store job.  This should never happen.";
                    Logger.LogError(impError);
                    Logger.LogInformation("End MANAGEMENT for K8S Orchestrator Extension for job " + config.JobId +
                                          $" - OperationType '{config.OperationType.GetType()}' not supported by Kubernetes certificate store job. Failed!");
                    return FailJob(impError, config.JobHistoryId);
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error processing job" + config.JobId);
            Logger.LogError(ex.Message);
            Logger.LogTrace(ex.StackTrace);
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogInformation("End MANAGEMENT for K8S Orchestrator Extension for job " + config.JobId + " with failure.");
            return FailJob(ex.Message, config.JobHistoryId);
        }
    }


    private V1Secret creatEmptySecret(string secretType)
    {
        Logger.LogWarning("Certificate object and certificate alias are both null or empty.  Assuming this is a 'create_store' action and populating an empty store.");
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

    private V1Secret HandleOpaqueSecret(string certAlias, K8SJobCertificate certObj, string keyPasswordStr = "", bool overwrite = false, bool append = false)
    {
        Logger.LogTrace("Entered HandleOpaqueSecret()");
        Logger.LogTrace("certAlias: " + certAlias);
        // Logger.LogTrace("keyPasswordStr: " + keyPasswordStr);
        Logger.LogTrace("overwrite: " + overwrite);
        Logger.LogTrace("append: " + append);
        
        Logger.LogDebug("Calling CreateOrUpdateCertificateStoreSecret() to create or update secret in Kubernetes...");
        var createResponse = KubeClient.CreateOrUpdateCertificateStoreSecret(
            certObj.PrivateKeyPem,
            certObj.CertPem,
            certObj.ChainPem,
            KubeSecretName,
            KubeNamespace,
            "secret",
            append,
            overwrite
        );
        if (createResponse == null)
        {
            Logger.LogError("createResponse is null");
        }
        else
        {
            Logger.LogTrace(createResponse.ToString());
        }

        Logger.LogInformation(
            $"Successfully created or updated secret '{KubeSecretName}' in Kubernetes namespace '{KubeNamespace}' on cluster '{KubeClient.GetHost()}' with certificate '{certAlias}'");
        return createResponse;

    }
    
    private V1Secret HandleJksSecret(ManagementJobConfiguration config, bool remove = false)
    {
        Logger.LogDebug("Entering HandleJKSSecret()...");
        // get the jks store from the secret
        Logger.LogDebug("Attempting to serialize JKS store");
        var jksStore = new JksCertificateStoreSerializer(config.JobProperties?.ToString());
        //getJksBytesFromKubeSecret
        var k8sData = new KubeCertificateManagerClient.JksSecret();
        if (config.OperationType is CertStoreOperationType.Add or CertStoreOperationType.Remove)
        {
            Logger.LogTrace("OperationType is: {OperationType}", config.OperationType.GetType());
            try
            {
                Logger.LogDebug("Attempting to get JKS store from Kubernetes secret {Name} in namespace {Namespace}", KubeSecretName, KubeNamespace);
                k8sData = KubeClient.GetJksSecret(KubeSecretName, KubeNamespace);
            }
            catch (StoreNotFoundException)
            {
                if (config.OperationType == CertStoreOperationType.Remove)
                {
                    Logger.LogWarning("Secret '{Name}' not found in Kubernetes namespace '{Ns}' so nothing to remove...", KubeSecretName, KubeNamespace);
                    return null;
                }
                Logger.LogWarning("Secret '{Name}' not found in Kubernetes namespace '{Ns}' so creating new secret...", KubeSecretName, KubeNamespace);
            }
        }
        // get newCert bytes from config.JobCertificate.Contents
        Logger.LogDebug("Attempting to get newCert bytes from config.JobCertificate.Contents");
        var newCertBytes = Convert.FromBase64String(config.JobCertificate.Contents);

        var alias = config.JobCertificate.Alias;
        Logger.LogTrace("alias: " + alias);
        var existingDataFieldName = "jks";
        // if alias contains a '/' then the pattern is 'k8s-secret-field-name/alias'
        if (alias.Contains('/'))
        {
            Logger.LogDebug("alias contains a '/' so splitting on '/'...");
            var aliasParts = alias.Split("/");
            existingDataFieldName = aliasParts[0];
            alias = aliasParts[1];
        }
        Logger.LogTrace("existingDataFieldName: {Name}", existingDataFieldName);
        Logger.LogTrace("alias: {Alias}", alias);
        byte[] existingData = null;
        if (k8sData.Secret?.Data != null)
        {
            Logger.LogDebug("k8sData.Secret.Data is not null so attempting to get existingData from secret data field {Name}...", existingDataFieldName);
            existingData = k8sData.Secret.Data.TryGetValue(existingDataFieldName, out var value) ? value : null;
        }

        if (!string.IsNullOrEmpty(config.CertificateStoreDetails.StorePassword))
        {
            Logger.LogDebug("StorePassword is not null or empty so setting StorePassword to config.CertificateStoreDetails.StorePassword");
            StorePassword = config.CertificateStoreDetails.StorePassword;
            var hashedStorePassword = GetSHA256Hash(StorePassword);
            Logger.LogTrace("hashedStorePassword: {Hash}", hashedStorePassword);
        }
        Logger.LogDebug("Getting store password");
        var sPass = getK8SStorePassword(k8sData.Secret);
        var hashedSPass = GetSHA256Hash(sPass);
        Logger.LogTrace("hashedStorePassword: {Hash}", hashedSPass);
        Logger.LogDebug("Calling CreateOrUpdateJks()...");
        try
        {
            var newJksStore = jksStore.CreateOrUpdateJks(newCertBytes, config.JobCertificate.PrivateKeyPassword, alias, existingData, sPass, remove);
            if (k8sData.Inventory == null || k8sData.Inventory.Count == 0)
            {
                Logger.LogDebug("k8sData.JksInventory is null or empty so creating new Dictionary...");
                k8sData.Inventory = new Dictionary<string, byte[]>();
                k8sData.Inventory.Add(existingDataFieldName, newJksStore);
            }
            else
            {
                Logger.LogDebug("k8sData.JksInventory is not null or empty so updating existing Dictionary...");
                k8sData.Inventory[existingDataFieldName] = newJksStore;
            }
            // update the secret
            Logger.LogDebug("Calling CreateOrUpdateJksSecret()...");
            var updateResponse = KubeClient.CreateOrUpdateJksSecret(k8sData, KubeSecretName, KubeNamespace);
            Logger.LogDebug("Exiting HandleJKSSecret()...");
            return updateResponse;
        }
        catch (JkSisPkcs12Exception)
        {
            return HandlePkcs12Secret(config, remove);
        }
        
    }

    private V1Secret HandlePkcs12Secret(ManagementJobConfiguration config, bool remove = false)
    {
        Logger.LogDebug("Entering HandlePkcs12Secret()...");
        // get the pkcs12 store from the secret
        var pkcs12Store = new Pkcs12CertificateStoreSerializer(config.JobProperties?.ToString());
        //getPkcs12BytesFromKubeSecret
        var k8sData = new KubeCertificateManagerClient.Pkcs12Secret();
        if (config.OperationType is CertStoreOperationType.Add or CertStoreOperationType.Remove)
        {
            try
            {
                k8sData = KubeClient.GetPkcs12Secret(KubeSecretName, KubeNamespace);
            }
            catch (StoreNotFoundException)
            {
                if (config.OperationType == CertStoreOperationType.Remove)
                {
                    Logger.LogWarning("Secret {Name} not found in Kubernetes, nothing to remove...", KubeSecretName);
                    return null;
                }
                Logger.LogWarning("Secret {Name} not found in Kubernetes, creating new secret...", KubeSecretName);
            }
        }

        // get newCert bytes from config.JobCertificate.Contents
        var newCertBytes = Convert.FromBase64String(config.JobCertificate.Contents);

        var alias = config.JobCertificate.Alias;
        Logger.LogDebug("alias: " + alias);
        var existingDataFieldName = "pkcs12";
        // if alias contains a '/' then the pattern is 'k8s-secret-field-name/alias'
        if (alias.Contains('/'))
        {
            Logger.LogDebug("alias contains a '/' so splitting on '/'...");
            var aliasParts = alias.Split("/");
            existingDataFieldName = aliasParts[0];
            alias = aliasParts[1];
        }

        Logger.LogDebug("existingDataFieldName: " + existingDataFieldName);
        Logger.LogDebug("alias: " + alias);
        byte[] existingData = null;
        if (k8sData.Secret?.Data != null)
        {
            existingData = k8sData.Secret.Data.TryGetValue(existingDataFieldName, out var value) ? value : null;
        }

        if (!string.IsNullOrEmpty(config.CertificateStoreDetails.StorePassword))
        {
            StorePassword = config.CertificateStoreDetails.StorePassword;
        }
        Logger.LogDebug("Getting store password");
        var sPass = getK8SStorePassword(k8sData.Secret);
        Logger.LogDebug("Calling CreateOrUpdatePkcs12()...");
        var newPkcs12Store = pkcs12Store.CreateOrUpdatePkcs12(newCertBytes, config.JobCertificate.PrivateKeyPassword, alias, existingData, sPass, remove);
        if (k8sData.Inventory == null || k8sData.Inventory.Count == 0)
        {
            Logger.LogDebug("k8sData.Pkcs12Inventory is null or empty so creating new Dictionary...");
            k8sData.Inventory = new Dictionary<string, byte[]>();
            k8sData.Inventory.Add(existingDataFieldName, newPkcs12Store);
        }
        else
        {
            Logger.LogDebug("k8sData.Pkcs12Inventory is not null or empty so updating existing Dictionary...");
            k8sData.Inventory[existingDataFieldName] = newPkcs12Store;
        }
        // update the secret
        Logger.LogDebug("Calling CreateOrUpdatePkcs12Secret()...");
        var updateResponse = KubeClient.CreateOrUpdatePkcs12Secret(k8sData, KubeSecretName, KubeNamespace);
        Logger.LogDebug("Exiting HandlePKCS12Secret()...");
        return updateResponse;
    }

    // private V1Secret HandlePKCS12Secret(string certAlias, K8SJobCertificate certObj, string certPassword, bool overwrite = false, bool append = true, bool remove = false)
    // {
    //     Logger.LogTrace("Entered HandlePKCS12Secret()");
    //     Logger.LogTrace("certAlias: " + certAlias);
    //     // Logger.LogTrace("keyPasswordStr: " + keyPasswordStr);
    //     Logger.LogTrace("overwrite: " + overwrite);
    //     Logger.LogTrace("append: " + append);
    //
    //     try
    //     {
    //         if (string.IsNullOrEmpty(certAlias) && string.IsNullOrEmpty(certObj.CertPEM) && !remove)
    //         {
    //             Logger.LogWarning("No alias or certificate found.  Creating empty secret.");
    //             return creatEmptySecret("pfx");
    //         }
    //     }
    //     catch (Exception ex)
    //     {
    //         if (!string.IsNullOrEmpty(certAlias))
    //         {
    //             Logger.LogWarning("This is fine");
    //         }
    //         else
    //         {
    //             Logger.LogError(ex, "Unknown error processing HandleTlsSecret(). Will try to continue as if everything is fine...for now.");
    //         }
    //     }
    //
    //     var keyPems = new string[] { };
    //     var certPems = new string[] { };
    //     var caPems = new string[] { };
    //     var chainPems = new string[] { };
    //
    //
    //     Logger.LogDebug("Calling CreateOrUpdateCertificateStoreSecret() to create or update secret in Kubernetes...");
    //
    //     var createResponse = KubeClient.CreateOrUpdatePkcs12Secret(default, null, null);
    //
    //     if (createResponse == null)
    //     {
    //         Logger.LogError("createResponse is null");
    //     }
    //     else
    //     {
    //         Logger.LogTrace(createResponse.ToString());
    //     }
    //
    //     Logger.LogInformation(
    //         $"Successfully created or updated secret '{KubeSecretName}' in Kubernetes namespace '{KubeNamespace}' on cluster '{KubeClient.GetHost()}' with certificate '{certAlias}'");
    //     return createResponse;
    // }

    private V1Secret HandleTlsSecret(string certAlias, K8SJobCertificate certObj, string certPassword, bool overwrite = false, bool append = true)
    {
        Logger.LogTrace("Entered HandleTlsSecret()");
        Logger.LogTrace("certAlias: " + certAlias);
        // Logger.LogTrace("keyPasswordStr: " + keyPasswordStr);
        Logger.LogTrace("overwrite: " + overwrite);
        Logger.LogTrace("append: " + append);

        try
        {
            //if (certObj.Equals(new X509Certificate2()) && string.IsNullOrEmpty(certAlias))
            if (string.IsNullOrEmpty(certAlias) && string.IsNullOrEmpty(certObj.CertPem))
            {
                Logger.LogWarning("No alias or certificate found.  Creating empty secret.");
                return creatEmptySecret("tls");
            }
        }
        catch (Exception ex)
        {
            if (!string.IsNullOrEmpty(certAlias))
            {
                Logger.LogWarning("This is fine");
            }
            else
            {
                Logger.LogError(ex, "Unknown error processing HandleTlsSecret(). Will try to continue as if everything is fine...for now.");
            }
        }
        var pemString = certObj.CertPem;
        Logger.LogTrace("pemString: " + pemString);

        Logger.LogDebug("Splitting PEM string into array of PEM strings by ';' delimiter...");
        var certPems = pemString.Split(";");
        Logger.LogTrace("certPems: " + certPems);

        Logger.LogDebug("Splitting CA PEM string into array of PEM strings by ';' delimiter...");
        var caPems = "".Split(";");
        Logger.LogTrace("caPems: " + caPems);

        Logger.LogDebug("Splitting chain PEM string into array of PEM strings by ';' delimiter...");
        var chainPems = "".Split(";");
        Logger.LogTrace("chainPems: " + chainPems);

        string[] keyPems = { "" };

        Logger.LogInformation($"Secret type is 'tls_secret', so extracting private key from certificate '{certAlias}'...");

        Logger.LogTrace("Calling GetKeyBytes() to extract private key from certificate...");
        var keyBytes = certObj.PrivateKeyBytes;

        var keyPem = certObj.PrivateKeyPem;
        if (!string.IsNullOrEmpty(keyPem))
        {
            keyPems = new[] { keyPem };
        }

        Logger.LogDebug("Calling CreateOrUpdateCertificateStoreSecret() to create or update secret in Kubernetes...");
        var createResponse = KubeClient.CreateOrUpdateCertificateStoreSecret(
            certObj.PrivateKeyPem,
            certObj.CertPem,
            certObj.ChainPem,
            KubeSecretName,
            KubeNamespace,
            "tls_secret",
            append,
            overwrite
        );
        if (createResponse == null)
        {
            Logger.LogError("createResponse is null");
        }
        else
        {
            Logger.LogTrace(createResponse.ToString());
        }

        Logger.LogInformation(
            $"Successfully created or updated secret '{KubeSecretName}' in Kubernetes namespace '{KubeNamespace}' on cluster '{KubeClient.GetHost()}' with certificate '{certAlias}'");
        return createResponse;
    }

    private JobResult HandleCreateOrUpdate(string secretType, ManagementJobConfiguration config, K8SJobCertificate jobCertObj, bool overwrite = false)
    {
        var certPassword = jobCertObj.Password;
        Logger.LogDebug("Entered HandleCreateOrUpdate()");
        var jobCert = config.JobCertificate;
        var certAlias = config.JobCertificate.Alias;

        if (string.IsNullOrEmpty(certAlias))
        {
            certAlias = jobCertObj.CertThumbprint;
        }

        Logger.LogTrace("secretType: " + secretType);
        Logger.LogTrace("certAlias: " + certAlias);
        // Logger.LogTrace("certPassword: " + certPassword);
        Logger.LogTrace("overwrite: " + overwrite);
        Logger.LogDebug(string.IsNullOrEmpty(jobCertObj.Password)
            ? "No cert password provided for certificate " + certAlias
            : "Cert password provided for certificate " + certAlias);


        Logger.LogDebug($"Converting certificate '{certAlias}' to Cert object...");

        if (!string.IsNullOrEmpty(jobCert.Contents))
        {
            Logger.LogTrace("Converting job certificate contents to byte array...");
            Logger.LogTrace("Successfully converted job certificate contents to byte array.");

            Logger.LogTrace($"Creating X509Certificate2 object from job certificate '{certAlias}'.");

            certAlias = jobCertObj.CertThumbprint;
            Logger.LogTrace($"Successfully created X509Certificate2 object from job certificate '{certAlias}'.");
        }

        Logger.LogDebug($"Successfully created X509Certificate2 object from job certificate '{certAlias}'.");
        Logger.LogTrace($"Entering switch statement for secret type: {secretType}...");
        switch (secretType)
        {
            // Process request based on secret type
            case "tls_secret":
            case "tls":
            case "tlssecret":
            case "tls_secrets":
                Logger.LogInformation("Secret type is 'tls_secret', calling HandleTlsSecret() for certificate " + certAlias + "...");
                _ = HandleTlsSecret(certAlias, jobCertObj, certPassword, overwrite);
                Logger.LogInformation("Successfully called HandleTlsSecret() for certificate " + certAlias + ".");
                break;
            case "opaque":
            case "secret":
            case "secrets":
                Logger.LogInformation("Secret type is 'secret', calling HandleOpaqueSecret() for certificate " + certAlias + "...");
                _ = HandleOpaqueSecret(certAlias, jobCertObj, certPassword, overwrite, false);
                Logger.LogInformation("Successfully called HandleOpaqueSecret() for certificate " + certAlias + ".");
                break;
            case "certificate":
            case "cert":
            case "csr":
            case "csrs":
            case "certs":
            case "certificates":
                const string csrErrorMsg = "ADD operation not supported by Kubernetes CSR type.";
                Logger.LogError(csrErrorMsg);
                Logger.LogInformation("End MANAGEMENT job " + config.JobId + " " + csrErrorMsg + " Failed!");
                return FailJob(csrErrorMsg, config.JobHistoryId);
            case "pfx":
            case "pkcs12":
                Logger.LogInformation("Secret type is 'pkcs12', calling HandlePKCS12Secret() for certificate " + certAlias + "...");
                _ = HandlePkcs12Secret(config);
                Logger.LogInformation("Successfully called HandlePKCS12Secret() for certificate " + certAlias + ".");
                break;
            case "jks":
                _ = HandleJksSecret(config);
                Logger.LogInformation("Successfully called HandleJKSSecret() for certificate " + certAlias + ".");
                break;
            case "namespace":
                jobCertObj.Alias = config.JobCertificate.Alias;
                // Split alias by / and get second to last element KubeSecretType
                var splitAlias = jobCertObj.Alias.Split("/");
                if (splitAlias.Length < 2)
                {
                    var invalidAliasErrMsg = "Invalid alias format for K8SNS store type. Alias pattern: `<secret_type>/<secret_name>` where `secret_type` is one of 'opaque' or 'tls' and `secret_name` is the name of the secret.";
                    Logger.LogError(invalidAliasErrMsg);
                    Logger.LogInformation("End MANAGEMENT job " + config.JobId + " " + invalidAliasErrMsg + " Failed!");
                    return FailJob(invalidAliasErrMsg, config.JobHistoryId);
                }
                KubeSecretType = splitAlias[^2];
                KubeSecretName = splitAlias[^1];
                Logger.LogDebug("Handling managment add job for K8SNS secret type '" + KubeSecretType + "(" + jobCertObj.Alias + ")'...");

                switch (KubeSecretType)
                {
                    case "tls":
                        Logger.LogInformation("Secret type is 'tls_secret', calling HandleTlsSecret() for certificate " + certAlias + "...");
                        _ = HandleTlsSecret(certAlias, jobCertObj, certPassword, overwrite);
                        Logger.LogInformation("Successfully called HandleTlsSecret() for certificate " + certAlias + ".");
                        break;
                    case "opaque":
                        Logger.LogInformation("Secret type is 'secret', calling HandleOpaqueSecret() for certificate " + certAlias + "...");
                        _ = HandleOpaqueSecret(certAlias, jobCertObj, certPassword, overwrite, false);
                        Logger.LogInformation("Successfully called HandleOpaqueSecret() for certificate " + certAlias + ".");
                        break;
                    default:
                    {
                        var nsErrMsg = "Unsupported secret type " + KubeSecretType + " for store types of 'K8SNS'.";
                        Logger.LogError(nsErrMsg);
                        Logger.LogInformation("End MANAGEMENT job " + config.JobId + " " + nsErrMsg + " Failed!");
                        return FailJob(nsErrMsg, config.JobHistoryId);
                    }
                }
                break;
            case "cluster":
                jobCertObj.Alias = config.JobCertificate.Alias;
                // Split alias by / and get second to last element KubeSecretType
                //pattern: namespace/secrets/secret_type/secert_name
                var clusterSplitAlias = jobCertObj.Alias.Split("/");
                
                // Check splitAlias length
                if (clusterSplitAlias.Length < 3)
                {
                    var invalidAliasErrMsg = "Invalid alias format for K8SCluster store type. Alias";
                    Logger.LogError(invalidAliasErrMsg);
                    Logger.LogInformation("End MANAGEMENT job " + config.JobId + " " + invalidAliasErrMsg + " Failed!");
                    return FailJob(invalidAliasErrMsg, config.JobHistoryId);
                }
                
                KubeSecretType = clusterSplitAlias[^2];
                KubeSecretName = clusterSplitAlias[^1];
                KubeNamespace = clusterSplitAlias[0];
                Logger.LogDebug("Handling managment add job for K8SNS secret type '" + KubeSecretType + "(" + jobCertObj.Alias + ")'...");

                switch (KubeSecretType)
                {
                    case "tls":
                        Logger.LogInformation("Secret type is 'tls_secret', calling HandleTlsSecret() for certificate " + certAlias + "...");
                        _ = HandleTlsSecret(certAlias, jobCertObj, certPassword, overwrite);
                        Logger.LogInformation("Successfully called HandleTlsSecret() for certificate " + certAlias + ".");
                        break;
                    case "opaque":
                        Logger.LogInformation("Secret type is 'secret', calling HandleOpaqueSecret() for certificate " + certAlias + "...");
                        _ = HandleOpaqueSecret(certAlias, jobCertObj, certPassword, overwrite, false);
                        Logger.LogInformation("Successfully called HandleOpaqueSecret() for certificate " + certAlias + ".");
                        break;
                    default:
                    {
                        var nsErrMsg = "Unsupported secret type " + KubeSecretType + " for store types of 'K8SNS'.";
                        Logger.LogError(nsErrMsg);
                        Logger.LogInformation("End MANAGEMENT job " + config.JobId + " " + nsErrMsg + " Failed!");
                        return FailJob(nsErrMsg, config.JobHistoryId);
                    }
                }
                break;
            default:
                var errMsg = $"Unsupported secret type {secretType}.";
                Logger.LogError(errMsg);
                Logger.LogInformation("End MANAGEMENT job " + config.JobId + " " + errMsg + " Failed!");
                return FailJob(errMsg, config.JobHistoryId);
        }
        Logger.LogInformation("End MANAGEMENT job " + config.JobId + " Success!");
        return SuccessJob(config.JobHistoryId);
    }


    private JobResult HandleRemove(string secretType, ManagementJobConfiguration config)
    {
        //OperationType == Remove - Delete a certificate from the certificate store passed in the config object
        var kubeHost = KubeClient.GetHost();
        var jobCert = config.JobCertificate;
        var certAlias = config.JobCertificate.Alias;

        var cert = new K8SJobCertificate
        {
            Alias = certAlias,
            StorePassword = config.CertificateStoreDetails.StorePassword,
            PasswordIsK8SSecret = PasswordIsK8SSecret,
            StorePasswordPath = StorePasswordPath
        };

        switch (secretType)
        {
            case "pkcs12":
                _ = HandlePkcs12Secret(config, true);
                return SuccessJob(config.JobHistoryId);
            case "jks":
                _ = HandleJksSecret(config, true);
                return SuccessJob(config.JobHistoryId);
        }


        if (!string.IsNullOrEmpty(certAlias))
        {
            var splitAlias = certAlias.Split("/");
            if (Capability.Contains("K8SNS"))
            {
                // Split alias by / and get second to last element KubeSecretType
                KubeSecretType = splitAlias[^2];
                KubeSecretName = splitAlias[^1];
                if (string.IsNullOrEmpty(KubeNamespace))
                {
                    KubeNamespace = StorePath;
                }
            }
            else if (Capability.Contains("K8SCluster"))
            {
                KubeSecretType = splitAlias[^2];
                KubeSecretName = splitAlias[^1];
                KubeNamespace = splitAlias[0];
            }
        }
        Logger.LogInformation(
            $"Removing certificate '{certAlias}' from Kubernetes client '{kubeHost}' cert store {KubeSecretName} in namespace {KubeNamespace}...");
        Logger.LogTrace("Calling DeleteCertificateStoreSecret() to remove certificate from Kubernetes...");
        try
        {
            var response = KubeClient.DeleteCertificateStoreSecret(
                KubeSecretName,
                KubeNamespace,
                KubeSecretType,
                jobCert.Alias
            );
            Logger.LogTrace($"REMOVE '{kubeHost}/{KubeNamespace}/{KubeSecretType}/{KubeSecretName}' response from Kubernetes:\n\t{response}");
        }
        catch (HttpOperationException rErr)
        {
            if (!rErr.Message.Contains("NotFound")) return FailJob(rErr.Message, config.JobHistoryId);

            var certDataErrorMsg =
                $"Kubernetes {KubeSecretType} '{KubeSecretName}' was not found in namespace '{KubeNamespace}'. Delete not necessary.";
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Success,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = certDataErrorMsg
            };
        }
        catch (Exception e)
        {
            Logger.LogError(e, $"Error removing certificate '{certAlias}' from Kubernetes client '{kubeHost}' cert store {KubeSecretName} in namespace {KubeNamespace}.");
            Logger.LogInformation("End MANAGEMENT job " + config.JobId + " Failed!");
            return FailJob(e.Message, config.JobHistoryId);
        }

        Logger.LogInformation("End MANAGEMENT job " + config.JobId + " Success!");
        return SuccessJob(config.JobHistoryId);
    }
}
