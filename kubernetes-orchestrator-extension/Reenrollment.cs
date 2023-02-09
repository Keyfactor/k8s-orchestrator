// Copyright 2021 Keyfactor                                                   
// Licensed under the Apache License, Version 2.0 (the "License"); you may    
// not use this file except in compliance with the License.  You may obtain a 
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless 
// required by applicable law or agreed to in writing, software distributed   
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for  
// the specific language governing permissions and limitations under the       
// License. 

using System;
using System.Collections.Generic;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Security.Cryptography;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using static Keyfactor.Extensions.Orchestrator.Kube.Inventory;

namespace Keyfactor.Extensions.Orchestrator.Kube;
// The Re-enrollment class implements IAgentJobExtension and is meant to:
//  1) Generate a new public/private keypair locally
//  2) Generate a CSR from the keypair,
//  3) Submit the CSR to KF Command to enroll the certificate and retrieve the certificate back
//  4) Deploy the newly re-enrolled certificate to a certificate store

public class Reenrollment : IReenrollmentJobExtension
{

    private static readonly string[] SupportedKubeStoreTypes = { "secret", "certificate" };

    // private static readonly string[] RequiredProperties = { "kube_namespace", "kube_secret_name", "kube_secret_type", "kube_svc_creds" };
    private static readonly string[] RequiredProperties = { "KubeNamespace", "KubeSecretName", "KubeSecretType", "KubeSvcCreds" };
    
    private readonly IPAMSecretResolver _resolver;

    private KubeCertificateManagerClient _kubeClient;

    private ILogger _logger;

    public Reenrollment(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    private string KubeNamespace { get; set; }

    private string KubeSecretName { get; set; }

    private string KubeSecretType { get; set; }

    private string KubeSvcCreds { get; set; }

    private string ServerUsername { get; set; }

    private string ServerPassword { get; set; }
    
    //Necessary to implement IReenrollmentJobExtension but not used.  Leave as empty string.
    public string ExtensionName => "Kube";

    //Job Entry Point
    public JobResult ProcessJob(ReenrollmentJobConfiguration config, SubmitReenrollmentCSR submitReenrollment)
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
        // config.JobProperties = Dictionary of custom parameters to use in building CSR and placing enrolled certificate in a the proper certificate store

        //NLog Logging to c:\CMS\Logs\CMS_Agent_Log.txt
        _logger = LogHandler.GetClassLogger(GetType());
        _logger.LogDebug($"Begin Reenrollment...");
        _logger.LogDebug($"Following info received from command:");
        _logger.LogDebug(JsonConvert.SerializeObject(config));
        //this is passed as a string
        // var storeTypeName = JsonConvert.DeserializeObject<Dictionary<string, string>>
        //     (config.CertificateStoreDetails.Properties)["storeparameter1"];
        // var storePath = config.CertificateStoreDetails.StorePath + @"\" + storeTypeName;
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
        var storeProperties = JsonConvert.DeserializeObject<Dictionary<string, string>>(config.CertificateStoreDetails.Properties);

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
        

        //Status: 2=Success, 3=Warning, 4=Error
        return FailJob($"Re-enrollment not implemented for {config.Capability}", config.JobHistoryId);
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
}

//var kpGenerator = new RsaKeyPairGenerator();
//kpGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
//var kp = kpGenerator.GenerateKeyPair();

//var key = kp;

//Dictionary<DerObjectIdentifier, string> values = CreateSubjectValues("myname");

//var subject = new X509Name(values.Keys.Reverse().ToList(), values);


//GeneralName name = new GeneralName(GeneralName.DnsName, "a1.example.ca");
//X509ExtensionsGenerator extGen = new X509ExtensionsGenerator();

//extGen.AddExtension(X509Extensions.SubjectAlternativeName, false, name);
//extGen.Generate()

// Potential solution with bouncycastle - non functional due to lack of BC csr builder in c#.
//var attributes = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, converted);
//attributes.

//var pkcs10Csr = new Pkcs10CertificationRequest(
//"SHA512withRSA",
//subject,
//key.Public,
//converted,
//key.Private);


//byte[] derEncoded = pkcs10Csr.GetDerEncoded();


//RSA rsa = RSA.Create(2048);
//var csr = new CertificateRequest(
//  new X500DistinguishedName("CN=myname"),
//rsa,
//HashAlgorithmName.SHA256,
//RSASignaturePadding.Pkcs1).CreateSigningRequest();
