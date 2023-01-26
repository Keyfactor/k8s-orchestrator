// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.PKI.PEM;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using static Keyfactor.Extensions.Orchestrator.Kube.Inventory;

namespace Keyfactor.Extensions.Orchestrator.Kube;

public class Management : IManagementJobExtension
{
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
        // config.OpeerationType - enumeration representing function with job type.  Used only with Management jobs where this value determines whether the Management job is a CREATE/ADD/REMOVE job.
        // config.Overwrite - Boolean value telling the Orchestrator Extension whether to overwrite an existing certificate in a store.  How you determine whether a certificate is "the same" as the one provided is AnyAgent implementation dependent
        // config.JobCertificate.PrivateKeyPassword - For a Management Add job, if the certificate being added includes the private key (therefore, a pfx is passed in config.JobCertificate.EntryContents), this will be the password for the pfx.

        //NLog Logging to c:\CMS\Logs\CMS_Agent_Log.txt

        var logger = LogHandler.GetClassLogger(GetType());
        logger.LogDebug($"Begin Management...");
        logger.LogDebug($"Following info received from command:");
        logger.LogDebug(JsonConvert.SerializeObject(config));
        logger.LogDebug(config.ToString());
        var storeTypeName = "kubernetes";
        var storePath = config.CertificateStoreDetails.StorePath + @"\" + storeTypeName;
        var certPassword = config.JobCertificate.PrivateKeyPassword ?? string.Empty;
        // var certAlias = config.JobCertificate.Alias;
        try
        {
            //Management jobs, unlike Discovery, Inventory, and Reenrollment jobs can have 3 different purposes:
            switch (config.OperationType)
            {
                case CertStoreOperationType.Add:
                    //OperationType == Add - Add a certificate to the certificate store passed in the config object
                    //Code logic to:
                    // 1) Connect to the orchestrated server (config.CertificateStoreDetails.ClientMachine) containing the certificate store
                    // 2) Custom logic to add certificate to certificate store (config.CertificateStoreDetails.StorePath) possibly using alias as an identifier if applicable (config.JobCertificate.Alias).  Use alias and overwrite flag (config.Overwrite)
                    //     to determine if job should overwrite an existing certificate in the store, for example a renewal.
                    // KubernetesCertStore localCertStore = JsonConvert.DeserializeObject<KubernetesCertStore>(File.ReadAllText(storepath));
                    // Read KubernetesCertStore depending on type
                    var localCertStore = JsonConvert.DeserializeObject<KubernetesCertStore>(config.CertificateStoreDetails.Properties);

                    logger.LogDebug($"KubernetesCertStore: {localCertStore}");
                    logger.LogDebug($"KubeNamespace: {localCertStore.KubeNamespace}");
                    logger.LogDebug($"KubeSecretName: {localCertStore.KubeSecretName}");
                    logger.LogDebug($"KubeSecretType: {localCertStore.KubeSecretType}");
                    logger.LogTrace($"KubeSvcCreds: {localCertStore.KubeSvcCreds}");
                    logger.LogTrace($"Certs: {localCertStore.Certs}");
                    logger.LogInformation($"Adding certificate to Kubernetes cert store {localCertStore.KubeSecretName} in namespace {localCertStore.KubeNamespace}...");

                    // Load credentials file from localCertStore.KubeSvcCreds // TODO: Implement config passed from store params or password input
                    // var kubeCreds = JsonConvert.DeserializeObject<KubeCreds>(File.ReadAllText(localCertStore.KubeSvcCreds));
                    var c = new KubeCertificateManagerClient("", "default");

                    var newCert = new Cert();
                    var certBytes = Convert.FromBase64String(config.JobCertificate.Contents);
                    var cert = new X509Certificate2(certBytes, certPassword);

                    newCert.Alias = cert.Thumbprint;
                    newCert.CertData = config.JobCertificate.Contents;
                    newCert.PrivateKey = config.JobCertificate.PrivateKeyPassword;

                    // Process entryparameters if applicable
                    // newcert.sampleentryparameter1 = config.JobProperties["sampleentryparameter1"].ToString();
                    // newcert.sampleentryparameter2 = config.JobProperties["sampleentryparameter2"].ToString();

                    // Process request based on secret type
                    if (localCertStore.KubeSecretType == "secret" || localCertStore.KubeSecretType == "tls_secret")
                    {
                        logger.LogInformation("Creating Kubernetes secret...");
                        try
                        {
                            var pemString = PemUtilities.DERToPEM(cert.RawData, PemUtilities.PemObjectType.Certificate);

                            string[] keyPems;
                            if (localCertStore.KubeSecretType == "tls_secret")
                            {
                                var keyBytes = cert.GetRSAPrivateKey().ExportRSAPrivateKey();
                                var kemPem = PemUtilities.DERToPEM(keyBytes, PemUtilities.PemObjectType.PrivateKey);
                                keyPems = new string[] { kemPem };
                            }
                            else
                            {
                                keyPems = cert.GetRSAPrivateKey()?.ToString().Split(";") ?? string.Empty.Split(";");
                            }

                            var certPems = pemString.Split(";"); // TODO: Implement multiple certs
                            var caPems = "".Split(";"); // TODO: Implement CA certs
                            var chainPems = "".Split(";"); // TODO: Implement chain certs
                            var kfid = 0; // TODO: Implement KFID
                            // var secretName = localCertStore.KubeSecretName;
                            // var namespaceName = localCertStore.KubeNamespace;
                            var secretType = localCertStore.KubeSecretType;

                            if (secretType == "secret" || secretType == "tls_secret")
                            {
                                var createResponse = c.CreateCertificateStoreSecret(
                                    keyPems,
                                    certPems,
                                    caPems,
                                    chainPems,
                                    kfid,
                                    localCertStore.KubeSecretName,
                                    localCertStore.KubeNamespace,
                                    localCertStore.KubeSecretType,
                                    true,
                                    config.Overwrite
                                );
                                logger.LogTrace(createResponse.ToString());
                            }
                            else
                            {
                                return new JobResult()
                                {
                                    Result = OrchestratorJobStatusJobResult.Failure,
                                    JobHistoryId = config.JobHistoryId,
                                    FailureMessage = $"Secret type {secretType} not supported."
                                };
                            }


                            // throw new Exception("Force break");

                            return new JobResult()
                            {
                                Result = OrchestratorJobStatusJobResult.Success,
                                JobHistoryId = config.JobHistoryId
                            };
                        }
                        catch (Exception e)
                        {
                            logger.LogError(e,
                                $"Unknown error creating Kubernetes secret {localCertStore.KubeSecretName} in namespace {localCertStore.KubeNamespace}.");
                            return new JobResult()
                            {
                                Result = OrchestratorJobStatusJobResult.Failure,
                                JobHistoryId = config.JobHistoryId,
                                FailureMessage = e.Message
                            };
                        }

                    }
                    if (localCertStore.KubeSecretType == "csr")
                    {
                        var csrErrorMsg = "ADD operation not supported by Kubernetes CSR type.";
                        logger.LogError(csrErrorMsg);
                        return new JobResult()
                        {
                            Result = OrchestratorJobStatusJobResult.Failure,
                            JobHistoryId = config.JobHistoryId,
                            FailureMessage = csrErrorMsg
                        };
                    }
                    else
                    {
                        var unknownTypeErrorMsg = $"Unknown Kubernetes secret type {localCertStore.KubeSecretType}. Operation not supported.";
                        logger.LogError(unknownTypeErrorMsg);
                        return new JobResult()
                        {
                            Result = OrchestratorJobStatusJobResult.Failure,
                            JobHistoryId = config.JobHistoryId,
                            FailureMessage = unknownTypeErrorMsg
                        };
                    }

                case CertStoreOperationType.Remove:
                    //OperationType == Remove - Delete a certificate from the certificate store passed in the config object
                    //Code logic to:
                    // 1) Connect to the orchestrated server (config.CertificateStoreDetails.ClientMachine) containing the certificate store
                    // 2) Custom logic to remove the certificate in a certificate store (config.CertificateStoreDetails.StorePath), possibly using alias (config.JobCertificate.Alias) or certificate thumbprint to identify the certificate (implementation dependent)
                    var removeLocalCertStore = JsonConvert.DeserializeObject<KubernetesCertStore>(File.ReadAllText(storePath));
                    var removealias = config.JobCertificate.Alias;
                    var converted = removeLocalCertStore.Certs.ToList();
                    converted.RemoveAll(x => x.Alias == removealias);
                    var rmarray = converted.ToArray<Cert>();
                    removeLocalCertStore.Certs = rmarray;
                    var remconvertedcertstore = JsonConvert.SerializeObject(removeLocalCertStore);
                    File.WriteAllText(storePath, remconvertedcertstore);
                    break;
                case CertStoreOperationType.Create:
                    //OperationType == Create - Create an empty certificate store in the provided location
                    //Code logic to:
                    // 1) Connect to the orchestrated server (config.CertificateStoreDetails.ClientMachine) where the certificate store (config.CertificateStoreDetails.StorePath) will be located
                    // 2) Custom logic to first check if the store already exists and add it if not.  If it already exists, implementation dependent as to how to handle - error, warning, success
                    if (!File.Exists(storePath))
                    {
                        var newstore = new KubernetesCertStore();
                        var newstoreconv = JsonConvert.SerializeObject(newstore);
                        File.WriteAllText(storePath, newstoreconv);
                    }
                    break;
                default:
                    //Invalid OperationType.  Return error.  Should never happen though
                    return new JobResult()
                    {
                        Result = OrchestratorJobStatusJobResult.Failure, JobHistoryId = config.JobHistoryId,
                        FailureMessage =
                            $"Site {config.CertificateStoreDetails.StorePath} on server {config.CertificateStoreDetails.ClientMachine}: Unsupported operation: {config.OperationType.ToString()}"
                    };
            }
        }
        catch (Exception ex)
        {
            //Status: 2=Success, 3=Warning, 4=Error
            return new JobResult()
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = ex.Message
            };
        }

        //Status: 2=Success, 3=Warning, 4=Error
        return new JobResult()
        {
            Result = OrchestratorJobStatusJobResult.Success,
            JobHistoryId = config.JobHistoryId
        };
    }
}
