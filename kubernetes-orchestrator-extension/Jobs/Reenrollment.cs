// Copyright 2021 Keyfactor                                                   
// Licensed under the Apache License, Version 2.0 (the "License"); you may    
// not use this file except in compliance with the License.  You may obtain a 
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless 
// required by applicable law or agreed to in writing, software distributed   
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for  
// the specific language governing permissions and limitations under the       
// License. 

using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Keyfactor.Orchestrators.Extensions.Interfaces;

namespace Keyfactor.Extensions.Orchestrator.Kube.Jobs;
// The Re-enrollment class implements IAgentJobExtension and is meant to:
//  1) Generate a new public/private keypair locally
//  2) Generate a CSR from the keypair,
//  3) Submit the CSR to KF Command to enroll the certificate and retrieve the certificate back
//  4) Deploy the newly re-enrolled certificate to a certificate store

public class Reenrollment : JobBase, IReenrollmentJobExtension
{
    public Reenrollment(IPAMSecretResolver resolver)
    {
        Resolver = resolver;
    }
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
        Logger = LogHandler.GetClassLogger(GetType());
        Logger.LogDebug($"Begin Reenrollment...");
        Logger.LogDebug($"Following info received from command:");
        Logger.LogDebug(JsonConvert.SerializeObject(config));

        Logger.LogDebug($"Begin {config.Capability} for job id {config.JobId.ToString()}...");
        // logger.LogTrace($"Store password: {storePassword}"); //Do not log passwords
        Logger.LogTrace($"Server: {config.CertificateStoreDetails.ClientMachine}");
        Logger.LogTrace($"Store Path: {config.CertificateStoreDetails.StorePath}");
        Logger.LogTrace($"Canonical Store Path: {GetStorePath()}");
        
        //Status: 2=Success, 3=Warning, 4=Error
        return FailJob($"Re-enrollment not implemented for {config.Capability}", config.JobHistoryId);
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
