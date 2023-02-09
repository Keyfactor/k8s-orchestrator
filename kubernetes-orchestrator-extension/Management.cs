// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using k8s.Models;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.PKI.PEM;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using static Keyfactor.Extensions.Orchestrator.Kube.Inventory;

namespace Keyfactor.Extensions.Orchestrator.Kube;

public class Management : IManagementJobExtension
{
    private static readonly string[] SupportedKubeStoreTypes = { "secret", "certificate" };

    // private static readonly string[] RequiredProperties = { "kube_namespace", "kube_secret_name", "kube_secret_type", "kube_svc_creds" };
    private static readonly string[] RequiredProperties = { "KubeNamespace", "KubeSecretName", "KubeSecretType", "KubeSvcCreds" };

    public static string CertChainSeparator = ",";

    private readonly IPAMSecretResolver _resolver;

    private KubeCertificateManagerClient _kubeClient;

    private ILogger _logger;

    public Management(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    private string KubeNamespace { get; set; }

    private string KubeSecretName { get; set; }

    private string KubeSecretType { get; set; }

    private string KubeSvcCreds { get; set; }

    private string ServerUsername { get; set; }

    private string ServerPassword { get; set; }

    //Necessary to implement IManagementJobExtension but not used.  Leave as empty string.
    public string ExtensionName => "Kube";

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

        _logger = LogHandler.GetClassLogger(GetType());
        _logger.LogDebug("Begin Management...");

        ServerUsername = ResolvePamField("Server User Name", config.ServerUsername);
        ServerPassword = ResolvePamField("Server Password", config.ServerPassword);
        var storePassword = ResolvePamField("Store Password", config.CertificateStoreDetails.StorePassword);

        if (storePassword != null)
        {
            _logger.LogWarning($"Store password provided but is not supported by store type {config.Capability}).");
        }

        var storeTypeName = "kubernetes";
        _logger.LogTrace("StoreTypeName: " + storeTypeName);
        var storePath = config.CertificateStoreDetails.StorePath;
        _logger.LogTrace("StorePath: " + storePath);
        var certPassword = config.JobCertificate.PrivateKeyPassword ?? string.Empty;

        var properties = config.CertificateStoreDetails.Properties;
        var overwrite = config.Overwrite;

        //Convert properties string to dictionary
        var storeProperties = JsonConvert.DeserializeObject<Dictionary<string, string>>(properties);

        //Check for required properties
        foreach (var prop in RequiredProperties)
        {
            if (storeProperties.ContainsKey(prop)) continue;

            var propError = $"Required property {prop} not found in store properties.";
            _logger.LogError(propError);
            return FailJob(propError, config.JobHistoryId);
        }

        try
        {
            KubeNamespace = storeProperties["KubeNamespace"];
            KubeSecretName = storeProperties["KubeSecretName"];
            KubeSecretType = storeProperties["KubeSecretType"];
            KubeSvcCreds = storeProperties["KubeSvcCreds"];
            _logger.LogDebug($"KubeNamespace: {KubeNamespace}");
            _logger.LogDebug($"KubeSecretName: {KubeSecretName}");
            _logger.LogDebug($"KubeSecretType: {KubeSecretType}");


            var localCertStore = JsonConvert.DeserializeObject<KubernetesCertStore>(config.CertificateStoreDetails.Properties);
            _logger.LogDebug($"KubernetesCertStore: {localCertStore}");
            // _logger.LogTrace($"KubeSvcCreds: {KubeSvcCreds}");
            _logger.LogTrace($"Certs: {localCertStore.Certs}");

            if (ServerUsername == "kubeconfig")
            {
                _logger.LogInformation("Using kubeconfig provided by 'Server Password' field");
                storeProperties["KubeSvcCreds"] = ServerPassword;
                KubeSvcCreds = ServerPassword;
                // _logger.LogTrace($"KubeSvcCreds: {localCertStore.KubeSvcCreds}"); //Do not log passwords
            }

            _kubeClient = new KubeCertificateManagerClient(KubeSvcCreds);

            switch (config.OperationType)
            {
                case CertStoreOperationType.Add:
                case CertStoreOperationType.Create:
                    //OperationType == Add - Add a certificate to the certificate store passed in the config object
                    _logger.LogDebug($"Processing Management-{config.OperationType.GetType()} job...");
                    return HandleCreateOrUpdate(KubeSecretType, config, certPassword, overwrite);
                case CertStoreOperationType.Remove:
                    _logger.LogDebug("Processing Management-Remove job...");
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
                    _logger.LogError(impError);
                    return FailJob(impError, config.JobHistoryId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing job");
            //Status: 2=Success, 3=Warning, 4=Error
            return FailJob(ex.Message, config.JobHistoryId);
        }
        return SuccessJob(config.JobHistoryId);
    }

    private V1Secret HandleOpaqueSecret(string certAlias, X509Certificate2 certObj, bool overwrite = false, bool append = false)
    {
        try
        {
            _logger.LogDebug($"Converting certificate '{certAlias}' in DER format to PEM format...");
            var pemString = PemUtilities.DERToPEM(certObj.RawData, PemUtilities.PemObjectType.Certificate);
            var certPems = pemString.Split(";");
            var caPems = "".Split(";");
            var chainPems = "".Split(";");

            string[] keyPems = { "" };

            _logger.LogInformation($"Secret type is 'tls_secret', so extracting private key from certificate '{certAlias}'...");
            var pkey = certObj.GetRSAPrivateKey();
            var keyBytes = pkey?.ExportRSAPrivateKey();
            if (keyBytes != null)
            {
                var pem = PemUtilities.DERToPEM(keyBytes, PemUtilities.PemObjectType.PrivateKey);
                keyPems = new[] { pem };
            }

            var createResponse = _kubeClient.CreateOrUpdateCertificateStoreSecret(
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
            _logger.LogTrace(createResponse.ToString());
            return createResponse;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, $"Error converting certificate '{certAlias}' to PEM format.");
            throw;
        }
    }

    private V1Secret HandleTlsSecret(string certAlias, X509Certificate2 certObj, string certPassword, bool overwrite = false, bool append = true)
    {
        _logger.LogDebug($"Converting certificate '{certAlias}' in DER format to PEM format...");
        var pemString = PemUtilities.DERToPEM(certObj.RawData, PemUtilities.PemObjectType.Certificate);
        var certPems = pemString.Split(";");
        var caPems = "".Split(";");
        var chainPems = "".Split(";");

        string[] keyPems = { "" };

        _logger.LogInformation($"Secret type is 'tls_secret', so extracting private key from certificate '{certAlias}'...");

        _logger.LogDebug("Attempting to extract private key from certificate as ");

        var keyBytes = GetKeyBytes(certObj, certPassword);
        if (keyBytes != null)
        {
            _logger.LogDebug($"Converting key '{certAlias}' to PEM format...");
            var kemPem = PemUtilities.DERToPEM(keyBytes, PemUtilities.PemObjectType.PrivateKey);
            keyPems = new[] { kemPem };
            _logger.LogDebug($"Key '{certAlias}' converted to PEM format.");
        }

        var createResponse = _kubeClient.CreateOrUpdateCertificateStoreSecret(
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
        _logger.LogTrace(createResponse.ToString());
        return createResponse;
    }

    private JobResult HandleCreateOrUpdate(string secretType, ManagementJobConfiguration config, string certPassword = "", bool overwrite = false)
    {
        var jobCert = config.JobCertificate;
        var certAlias = jobCert.Alias;

        _logger.LogDebug($"Converting job certificate '{jobCert.Alias}' to Cert object...");
        var certBytes = Convert.FromBase64String(jobCert.Contents);

        _logger.LogDebug($"Creating X509Certificate2 object from job certificate '{jobCert.Alias}'.");
        var certObj = new X509Certificate2(certBytes, certPassword);

        _logger.LogDebug("Setting Keyfactor cert object properties...");

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
                _ = HandleOpaqueSecret(certAlias, certObj, overwrite);
                break;
            case "certificate":
            case "cert":
            case "csr":
            case "csrs":
            case "certs":
            case "certificates":
                const string csrErrorMsg = "ADD operation not supported by Kubernetes CSR type.";
                _logger.LogError(csrErrorMsg);
                return FailJob(csrErrorMsg, config.JobHistoryId);
            default:
                var errMsg = $"Unsupported secret type {secretType}.";
                _logger.LogError(errMsg);
                return FailJob(errMsg, config.JobHistoryId);
        }
        return SuccessJob(config.JobHistoryId);
    }

    private JobResult HandleRemove(ManagementJobConfiguration config)
    {
        //OperationType == Remove - Delete a certificate from the certificate store passed in the config object
        var kubeHost = _kubeClient.GetHost();
        var jobCert = config.JobCertificate;
        var certAlias = jobCert.Alias;


        _logger.LogInformation(
            $"Removing certificate '{certAlias}' from Kubernetes client '{kubeHost}' cert store {KubeSecretName} in namespace {KubeNamespace}...");
        try
        {
            var response = _kubeClient.DeleteCertificateStoreSecret(
                KubeSecretName,
                KubeNamespace,
                KubeSecretType,
                jobCert.Alias
            );
            _logger.LogTrace($"REMOVE '{kubeHost}/{KubeNamespace}/{KubeSecretType}/{KubeSecretName}' response from Kubernetes:\n\t{response}");
        }
        catch (Exception e)
        {
            _logger.LogError(e, $"Error removing certificate '{certAlias}' from Kubernetes client '{kubeHost}' cert store {KubeSecretName} in namespace {KubeNamespace}.");
            return FailJob(e.Message, config.JobHistoryId);
        }

        return SuccessJob(config.JobHistoryId);
    }

    private byte[] GetKeyBytes(X509Certificate2 certObj, string certPassword = null)
    {
        byte[] keyBytes;

        switch (certObj.GetKeyAlgorithm())
        {
            case "RSA":
                _logger.LogDebug("Key algorithm is RSA, so attempting to extract private key as RSA...");
                keyBytes = certObj.GetRSAPrivateKey()?.ExportRSAPrivateKey();
                break;
            case "ECDSA":
                _logger.LogDebug("Key algorithm is ECDSA, so attempting to extract private key as ECDSA...");
                keyBytes = certObj.GetECDsaPrivateKey()?.ExportECPrivateKey();
                break;
            case "DSA":
                _logger.LogDebug("Key algorithm is DSA, so attempting to extract private key as DSA...");
                keyBytes = certObj.GetDSAPrivateKey()?.ExportPkcs8PrivateKey();
                break;
            default:
                _logger.LogDebug("Key algorithm is not RSA, ECDSA, or DSA, so attempting to extract private key as PKCS#12...");
                keyBytes = certObj.Export(X509ContentType.Pkcs12, certPassword);
                break;
        }
        return keyBytes;
    }
    private string ResolvePamField(string name, string value)
    {
        _logger.LogTrace($"Attempting to resolved PAM eligible field {name}");
        return _resolver.Resolve(value);
    }

    private static JobResult FailJob(string message, long jobHistoryId)
    {
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Failure,
            JobHistoryId = jobHistoryId,
            FailureMessage = message
        };
    }

    private static JobResult SuccessJob(long jobHistoryId)
    {
        return new JobResult
        {
            Result = OrchestratorJobStatusJobResult.Success,
            JobHistoryId = jobHistoryId
        };
    }
}
