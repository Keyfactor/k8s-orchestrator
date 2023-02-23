// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using k8s.Models;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.PKI.PEM;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using static Keyfactor.Extensions.Orchestrator.Kube.Jobs.Inventory;

namespace Keyfactor.Extensions.Orchestrator.Kube.Jobs;

public class Management : JobBase, IManagementJobExtension
{
    public Management(IPAMSecretResolver resolver)
    {
        Resolver = resolver;
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
        InitializeStore(config);
        
        Logger.LogDebug("Begin Management...");
        var storePath = config.CertificateStoreDetails.StorePath;
        Logger.LogTrace("StorePath: " + storePath);
        Logger.LogDebug($"Canonical Store Path: {GetStorePath()}");
        var certPassword = config.JobCertificate.PrivateKeyPassword ?? string.Empty;
        

        //Convert properties string to dictionary
        try
        {
            switch (config.OperationType)
            {
                case CertStoreOperationType.Add:
                case CertStoreOperationType.Create:
                    //OperationType == Add - Add a certificate to the certificate store passed in the config object
                    Logger.LogDebug($"Processing Management-{config.OperationType.GetType()} job...");
                    return HandleCreateOrUpdate(KubeSecretType, config, certPassword, Overwrite);
                case CertStoreOperationType.Remove:
                    Logger.LogDebug("Processing Management-Remove job...");
                    return HandleRemove(config);
                case CertStoreOperationType.Unknown:
                case CertStoreOperationType.Inventory:
                case CertStoreOperationType.CreateAdd:
                case CertStoreOperationType.Reenrollment:
                case CertStoreOperationType.Discovery:
                case CertStoreOperationType.SetPassword:
                case CertStoreOperationType.FetchLogs:
                    return FailJob($"OperationType '{config.OperationType.GetType()}' not supported by Kubernetes certificate store job.", config.JobHistoryId);
                default:
                    //Invalid OperationType.  Return error.  Should never happen though
                    var impError = $"Invalid OperationType '{config.OperationType.GetType()}' passed to Kubernetes certificate store job.  This should never happen.";
                    Logger.LogError(impError);
                    return FailJob(impError, config.JobHistoryId);
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error processing job");
            //Status: 2=Success, 3=Warning, 4=Error
            return FailJob(ex.Message, config.JobHistoryId);
        }
        return SuccessJob(config.JobHistoryId);
    }

    private V1Secret HandleOpaqueSecret(string certAlias, X509Certificate2 certObj, string keyPasswordStr = "", bool overwrite = false, bool append = false)
    {
        try
        {
            Logger.LogDebug($"Converting certificate '{certAlias}' in DER format to PEM format...");
            var pemString = PemUtilities.DERToPEM(certObj.RawData, PemUtilities.PemObjectType.Certificate);
            var certPems = pemString.Split(";");
            var caPems = "".Split(";");
            var chainPems = "".Split(";");

            string[] keyPems = { "" };

            Logger.LogInformation($"Secret type is 'tls_secret', so extracting private key from certificate '{certAlias}'...");
            var pkey = certObj.GetRSAPrivateKey();

            var keyBytes = new byte[] { };
            
            if (pkey != null)
            {
                try
                {
                    keyBytes = pkey?.ExportRSAPrivateKey();
                    if (keyBytes != null)
                    {
                        var pem = PemUtilities.DERToPEM(keyBytes, PemUtilities.PemObjectType.PrivateKey);
                        keyPems = new[] { pem };
                    }    
                }
                catch (Exception ex)
                {
                    var pem = ParseJobPrivateKey(ManagementConfig);
                    // Add to keyPems
                    keyPems = new[] { pem };
                }
            }

            var createResponse = KubeClient.CreateOrUpdateCertificateStoreSecret(
                keyPems,
                certPems,
                caPems,
                chainPems,
                KubeSecretName,
                KubeNamespace,
                "secret",
                append,
                overwrite
            );
            Logger.LogTrace(createResponse.ToString());
            return createResponse;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, $"Error converting certificate '{certAlias}' to PEM format.");
            throw;
        }
    }

    private V1Secret HandleTlsSecret(string certAlias, X509Certificate2 certObj, string certPassword, bool overwrite = false, bool append = true)
    {
        Logger.LogDebug($"Converting certificate '{certAlias}' in DER format to PEM format...");
        var pemString = PemUtilities.DERToPEM(certObj.RawData, PemUtilities.PemObjectType.Certificate);
        var certPems = pemString.Split(";");
        var caPems = "".Split(";");
        var chainPems = "".Split(";");

        string[] keyPems = { "" };

        Logger.LogInformation($"Secret type is 'tls_secret', so extracting private key from certificate '{certAlias}'...");

        Logger.LogDebug("Attempting to extract private key from certificate as ");

        var keyBytes = GetKeyBytes(certObj, certPassword);
        if (keyBytes != null)
        {
            Logger.LogDebug($"Converting key '{certAlias}' to PEM format...");
            var kemPem = PemUtilities.DERToPEM(keyBytes, PemUtilities.PemObjectType.PrivateKey);
            keyPems = new[] { kemPem };
            Logger.LogDebug($"Key '{certAlias}' converted to PEM format.");
        }

        var createResponse = KubeClient.CreateOrUpdateCertificateStoreSecret(
            keyPems,
            certPems,
            caPems,
            chainPems,
            KubeSecretName,
            KubeNamespace,
            "tls_secret",
            append,
            overwrite
        );
        Logger.LogTrace(createResponse.ToString());
        return createResponse;
    }

    private JobResult HandleCreateOrUpdate(string secretType, ManagementJobConfiguration config, string certPassword = "", bool overwrite = false)
    {
        var jobCert = config.JobCertificate;
        var certAlias = jobCert.Alias;

        Logger.LogDebug($"Converting job certificate '{jobCert.Alias}' to Cert object...");
        var certBytes = Convert.FromBase64String(jobCert.Contents);

        Logger.LogDebug($"Creating X509Certificate2 object from job certificate '{jobCert.Alias}'.");
        var certObj = new X509Certificate2(certBytes, certPassword);

        Logger.LogDebug("Setting Keyfactor cert object properties...");

        switch (secretType)
        {
            // Process request based on secret type
            case "tls_secret":
            case "tls":
            case "tlssecret":
            case "tls_secrets":
                _ = HandleTlsSecret(certAlias, certObj, certPassword, overwrite);
                break;
            case "secret":
            case "secrets":
                _ = HandleOpaqueSecret(certAlias, certObj, certPassword, overwrite, true);
                break;
            case "certificate":
            case "cert":
            case "csr":
            case "csrs":
            case "certs":
            case "certificates":
                const string csrErrorMsg = "ADD operation not supported by Kubernetes CSR type.";
                Logger.LogError(csrErrorMsg);
                return FailJob(csrErrorMsg, config.JobHistoryId);
            default:
                var errMsg = $"Unsupported secret type {secretType}.";
                Logger.LogError(errMsg);
                return FailJob(errMsg, config.JobHistoryId);
        }
        return SuccessJob(config.JobHistoryId);
    }

    private JobResult HandleRemove(ManagementJobConfiguration config)
    {
        //OperationType == Remove - Delete a certificate from the certificate store passed in the config object
        var kubeHost = KubeClient.GetHost();
        var jobCert = config.JobCertificate;
        var certAlias = jobCert.Alias;


        Logger.LogInformation(
            $"Removing certificate '{certAlias}' from Kubernetes client '{kubeHost}' cert store {KubeSecretName} in namespace {KubeNamespace}...");
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
        catch (Exception e)
        {
            Logger.LogError(e, $"Error removing certificate '{certAlias}' from Kubernetes client '{kubeHost}' cert store {KubeSecretName} in namespace {KubeNamespace}.");
            return FailJob(e.Message, config.JobHistoryId);
        }

        return SuccessJob(config.JobHistoryId);
    }
}
