// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using k8s.Autorest;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.Orchestrator.Kube;

// The Inventory class implements IAgentJobExtension and is meant to find all of the certificates in a given certificate store on a given server
//  and return those certificates back to Keyfactor for storing in its database.  Private keys will NOT be passed back to Keyfactor Command 
public class Inventory : IInventoryJobExtension
{
    private static readonly string[] SupportedKubeStoreTypes = { "secret", "certificate" };

    // private static readonly string[] RequiredProperties = { "kube_namespace", "kube_secret_name", "kube_secret_type", "kube_svc_creds" };
    private static readonly string[] RequiredProperties = { "KubeNamespace", "KubeSecretName", "KubeSecretType", "KubeSvcCreds" };

    private static readonly string CertChainSeparator = ",";

    private readonly IPAMSecretResolver _resolver;

    private KubeCertificateManagerClient _kubeClient;

    private ILogger _logger;

    public Inventory(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    private string KubeNamespace { get; set; }

    private string KubeSecretName { get; set; }

    private string KubeSecretType { get; set; }

    private string KubeSvcCreds { get; set; }

    private string ServerUsername { get; set; }

    private string ServerPassword { get; set; }

    //Necessary to implement IInventoryJobExtension but not used.  Leave as empty string.
    // public string ExtensionName => "Kubernetes";
    public string ExtensionName => "Kube";

    //Job Entry Point
    public JobResult ProcessJob(InventoryJobConfiguration config, SubmitInventoryUpdate submitInventory)
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

        //NLog Logging to c:\CMS\Logs\CMS_Agent_Log.txt
        _logger = LogHandler.GetClassLogger(GetType());
        _logger.LogDebug("Begin Inventory...");

        var storepath = config.CertificateStoreDetails.StorePath;
        var properties = config.CertificateStoreDetails.Properties;
        _logger.LogInformation($"Inventory for store path: {storepath}");

        ServerUsername = ResolvePamField("Server User Name", config.ServerUsername);
        ServerPassword = ResolvePamField("Server Password", config.ServerPassword);
        var storePassword = ResolvePamField("Store Password", config.CertificateStoreDetails.StorePassword);

        if (storePassword != null)
        {
            _logger.LogWarning($"Store password provided but is not supported by store type {config.Capability}).");
        }

        _logger.LogDebug($"Begin {config.Capability} for job id {config.JobId.ToString()}...");
        // logger.LogTrace($"Store password: {storePassword}"); //Do not log passwords
        _logger.LogTrace($"Server: {config.CertificateStoreDetails.ClientMachine}");
        _logger.LogTrace($"Store Path: {config.CertificateStoreDetails.StorePath}");

        //Convert properties string to dictionary
        var storeProperties = JsonConvert.DeserializeObject<Dictionary<string, string>>(properties);

        //Check for required properties
        foreach (var prop in RequiredProperties)
        {
            if (storeProperties.ContainsKey(prop)) continue;

            var propErr = $"Required property {prop} not found in store properties.";
            _logger.LogError(propErr);
            return FailJob(propErr, config.JobHistoryId);
        }

        KubeNamespace = storeProperties["KubeNamespace"];
        KubeSecretName = storeProperties["KubeSecretName"];
        KubeSecretType = storeProperties["KubeSecretType"];
        KubeSvcCreds = storeProperties["KubeSvcCreds"];

        if (ServerUsername == "kubeconfig")
        {
            _logger.LogInformation("Using kubeconfig provided by 'Server Password' field");
            storeProperties["KubeSvcCreds"] = ServerPassword;
            KubeSvcCreds = ServerPassword;
            // logger.LogTrace($"KubeSvcCreds: {localCertStore.KubeSvcCreds}"); //Do not log passwords
        }

        _logger.LogDebug($"KubeNamespace: {KubeNamespace}");
        _logger.LogDebug($"KubeSecretName: {KubeSecretName}");
        _logger.LogDebug($"KubeSecretType: {KubeSecretType}");
        // logger.LogTrace($"KubeSvcCreds: {kubeSvcCreds}"); //Do not log passwords

        if (string.IsNullOrEmpty(KubeSvcCreds))
        {
            const string credsErr =
                "No credentials provided to connect to Kubernetes. Please provide a kubeconfig file. See https://github.com/Keyfactor/kubernetes-orchestrator/blob/main/scripts/kubernetes/get_service_account_creds.sh";
            _logger.LogError(credsErr);
            return FailJob(credsErr, config.JobHistoryId);
        }


        try
        {
            _kubeClient = new KubeCertificateManagerClient(KubeSvcCreds);

            if (config.CertificateStoreDetails.Properties == "")
                return FailJob(
                    $"Invalid configuration. A KubernetesCertStore type must have addition properties: {string.Join(", ", RequiredProperties)}, {string.Join(", ", SupportedKubeStoreTypes)}",
                    config.JobHistoryId);

            var hasPrivateKey = false;

            switch (KubeSecretType)
            {
                case "secret":
                case "secrets":
                    return HandleOpaqueSecret(config.JobHistoryId, submitInventory);
                case "tls_secret":
                case "tls":
                case "tlssecret":
                case "tls_secrets":
                    return HandleTlsSecret(config.JobHistoryId, submitInventory);
                case "certificate":
                case "cert":
                case "csr":
                case "csrs":
                case "certs":
                case "certificates":
                    return HandleCertificate(config.JobHistoryId, submitInventory);
                default:
                    var errorMsg = $"{KubeSecretType} not supported.";
                    _logger.LogError(errorMsg);
                    return new JobResult
                    {
                        Result = OrchestratorJobStatusJobResult.Failure,
                        JobHistoryId = config.JobHistoryId,
                        FailureMessage = errorMsg
                    };
            }
        }
        catch (Exception ex)
        {
            //Status: 2=Success, 3=Warning, 4=Error
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = ex.ToString()
            };
        }
    }

    private JobResult HandleCertificate(long jobId, SubmitInventoryUpdate submitInventory)
    {
        const bool hasPrivateKey = false;
        try
        {
            var certificates = _kubeClient.GetCertificateSigningRequestStatus(KubeSecretName);
            return PushInventory(certificates, jobId, submitInventory);
        }
        catch (HttpOperationException e)
        {
            _logger.LogError(e.Message);
            var certDataErrorMsg =
                $"Kubernetes {KubeSecretType} '{KubeSecretName}' was not found in namespace '{KubeNamespace}'.";
            _logger.LogError(certDataErrorMsg);
            return FailJob(certDataErrorMsg, jobId);
        }
        catch (Exception e)
        {
            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
            _logger.LogError(certDataErrorMsg);
            return FailJob(certDataErrorMsg, jobId);
        }
    }

    private JobResult PushInventory(string[] certsList, long jobId, SubmitInventoryUpdate submitInventory, bool hasPrivateKey = false)
    {
        var inventoryItems = new List<CurrentInventoryItem>();
        foreach (var cert in certsList)
        {
            _logger.LogTrace($"Cert:\n{cert}");
            // load as x509
            string alias;
            if (string.IsNullOrEmpty(cert))
            {
                _logger.LogInformation($"Kubernetes returned an empty inventory for store {KubeSecretName}");
                continue;
            }
            try
            {
                var certFormatted = cert.Contains("BEGIN CERTIFICATE")
                    ? new X509Certificate2(Encoding.UTF8.GetBytes(cert))
                    : new X509Certificate2(Convert.FromBase64String(cert));
                alias = certFormatted.Thumbprint;
            }
            catch (Exception e)
            {
                _logger.LogError(e.Message);
                return FailJob(e.Message, jobId);
            }

            var certs = new[] { cert };
            inventoryItems.Add(new CurrentInventoryItem
            {
                ItemStatus = OrchestratorInventoryItemStatus
                    .Unknown, //There are other statuses, but Command can determine how to handle new vs modified certificates
                Alias = alias,
                PrivateKeyEntry =
                    hasPrivateKey, //You will not pass the private key back, but you can identify if the main certificate of the chain contains a private key in the store
                UseChainLevel =
                    true, //true if Certificates will contain > 1 certificate, main cert => intermediate CA cert => root CA cert.  false if Certificates will contain an array of 1 certificate
                Certificates =
                    certs //Array of single X509 certificates in Base64 string format (certificates if chain, single cert if not), something like:
            });
        }
        try
        {
            //Sends inventoried certificates back to KF Command
            submitInventory.Invoke(inventoryItems);
            //Status: 2=Success, 3=Warning, 4=Error
            return new JobResult
                { Result = OrchestratorJobStatusJobResult.Success, JobHistoryId = jobId };
        }
        catch (Exception ex)
        {
            // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
            //  may not be reflected in Keyfactor Command.
            return FailJob(ex.Message, jobId);
        }
    }

    private JobResult HandleOpaqueSecret(long jobId, SubmitInventoryUpdate submitInventory)
    {
        const bool hasPrivateKey = true;

        _logger.LogDebug(
            $"Querying Kubernetes {KubeSecretType} API for {KubeSecretName} in namespace {KubeNamespace}");
        try
        {
            var certData = _kubeClient.GetCertificateStoreSecret(
                KubeSecretName,
                KubeNamespace
            );
            var certificatesBytes = certData.Data["certificates"];
            var certificates = Encoding.UTF8.GetString(certificatesBytes);
            var certsList = certificates.Split(CertChainSeparator);
            return PushInventory(certsList, jobId, submitInventory, hasPrivateKey);
        }
        catch (HttpOperationException e)
        {
            _logger.LogError(e.Message);
            var certDataErrorMsg =
                $"Kubernetes {KubeSecretType} '{KubeSecretName}' was not found in namespace '{KubeNamespace}'.";
            _logger.LogError(certDataErrorMsg);
            return FailJob(certDataErrorMsg, jobId);
        }
        catch (Exception e)
        {
            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
            _logger.LogError(certDataErrorMsg);
            return FailJob(certDataErrorMsg, jobId);
        }
    }

    private JobResult HandleTlsSecret(long jobId, SubmitInventoryUpdate submitInventory)
    {

        _logger.LogDebug(
            $"Querying Kubernetes {KubeSecretType} API for {KubeSecretName} in namespace {KubeNamespace}");
        var hasPrivateKey = true;
        try
        {
            var certData = _kubeClient.GetCertificateStoreSecret(
                KubeSecretName,
                KubeNamespace
            );
            var certificatesBytes = certData.Data["tls.crt"];
            var privateKeyBytes = certData.Data["tls.key"];
            if (privateKeyBytes == null)
            {
                hasPrivateKey = false;
            }
            var certificates = Encoding.UTF8.GetString(certificatesBytes);
            var certsList = certificates.Split(CertChainSeparator);
            return PushInventory(certsList, jobId, submitInventory, hasPrivateKey);
        }
        catch (HttpOperationException e)
        {
            _logger.LogError(e.Message);
            var certDataErrorMsg =
                $"Kubernetes {KubeSecretType} '{KubeSecretName}' was not found in namespace '{KubeNamespace}'.";
            _logger.LogError(certDataErrorMsg);
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = jobId,
                FailureMessage = certDataErrorMsg
            };
        }
        catch (Exception e)
        {
            _logger.LogError(e.Message);
            var certDataErrorMsg = $"Error querying Kubernetes secret API: {e.Message}";
            _logger.LogError(certDataErrorMsg);
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = jobId,
                FailureMessage = certDataErrorMsg
            };
        }
    }
    private string ResolvePamField(string name, string value)
    {
        var logger = LogHandler.GetClassLogger(GetType());
        logger.LogTrace($"Attempting to resolved PAM eligible field {name}");
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

    public class KubernetesCertStore
    {
        public string KubeNamespace { get; set; } = "";

        public string KubeSecretName { get; set; } = "";

        public string KubeSecretType { get; set; } = "";

        public string KubeSvcCreds { get; set; } = "";

        public Cert[] Certs { get; set; }
    }

    public class KubeCreds
    {
        public string KubeServer { get; set; } = "";

        public string KubeToken { get; set; } = "";

        public string KubeCert { get; set; } = "";
    }

    public class Cert
    {
        public string Alias { get; set; } = "";

        public string CertData { get; set; } = "";

        public string PrivateKey { get; set; } = "";
    }
}
