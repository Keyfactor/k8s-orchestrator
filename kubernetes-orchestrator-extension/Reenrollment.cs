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
using static Keyfactor.Extensions.Orchestrator.Kube.Inventory;

namespace Keyfactor.Extensions.Orchestrator.Kube;
// The Re-enrollment class implements IAgentJobExtension and is meant to:
//  1) Generate a new public/private keypair locally
//  2) Generate a CSR from the keypair,
//  3) Submit the CSR to KF Command to enroll the certificate and retrieve the certificate back
//  4) Deploy the newly re-enrolled certificate to a certificate store

public class Reenrollment : IReenrollmentJobExtension
{

    //Necessary to implement IReenrollmentJobExtension but not used.  Leave as empty string.
    public string ExtensionName => "";

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
        var logger = LogHandler.GetClassLogger(GetType());
        logger.LogDebug($"Begin Reenrollment... test");
        logger.LogDebug($"Following info received from command:");
        logger.LogDebug(JsonConvert.SerializeObject(config));
        //this is passed as a string
        var storeTypeName = JsonConvert.DeserializeObject<Dictionary<string, string>>
            (config.CertificateStoreDetails.Properties)["storeparameter1"];
        var storePath = config.CertificateStoreDetails.StorePath + @"\" + storeTypeName;
        try
        {
            //Code logic to:
            //  1) Generate a new public/private keypair locally from any config.JobProperties passed
            //  2) Generate a CSR from the keypair (PKCS10),
            //  3) Submit the CSR to KF Command to enroll the certificate using:
            //      string resp = (string)submitEnrollmentRequest.Invoke(Convert.ToBase64String(PKCS10_bytes);
            //      X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(resp));
            //  4) Deploy the newly re-enrolled certificate (cert in #3) to a certificate store
            // RSAKeyPairGenerator generates the RSA Key pair based on the random number


            var infoFromCommand = new X500DistinguishedName
                (config.JobProperties["subjectText"].ToString());

            var rsa = RSA.Create(2048);
            var certificateRequest
                = new CertificateRequest(infoFromCommand.Name, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            certificateRequest.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));
            certificateRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                    false));

            // Add the SubjectAlternativeName extension
            var sanBuilder = new SubjectAlternativeNameBuilder();
            var sanList = new List<string>("test.com,*.test.com".Split(','));
            foreach (var sanItem in sanList)
            {
                sanBuilder.AddDnsName(sanItem.Trim());
            }

            certificateRequest.CertificateExtensions.Add(sanBuilder.Build());

            //Timestamp oid
            certificateRequest.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection
                    {
                        new("1.3.6.1.5.5.7.3.8")
                    },
                    true));

            certificateRequest.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

            var byteCsr = certificateRequest.CreateSigningRequest();


            var csr64 = Convert.ToBase64String(byteCsr);
            logger.LogDebug("Submitting csr.");
            logger.LogDebug(csr64);
            /** START Option 2 --- */
            // Get the enrollment data from config.Job.Properties

            var returnCert = submitReenrollment.Invoke(csr64);


            var localCertStore = JsonConvert.DeserializeObject<KubernetesCertStore>
                (File.ReadAllText(storePath));
            var newcert = new Cert();

            newcert.Alias = returnCert.Thumbprint;
            newcert.CertData = returnCert.GetRawCertDataString();
            newcert.PrivateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

            // if (config.JobProperties["sampleentryparameter1"].ToString() != null || config.JobProperties["sampleentryparameter1"].ToString() != "")
            // {
            //     newcert.sampleentryparameter1 = config.JobProperties["sampleentryparameter1"].ToString();
            // }
            // else
            // {
            //     newcert.sampleentryparameter1 = "";
            // }
            // try
            // {
            //     if (config.JobProperties["sampleentryparameter2"] != null || config.JobProperties["sampleentryparameter2"].ToString() != "")
            //     {
            //         newcert.sampleentryparameter2 = config.JobProperties["sampleentryparameter2"].ToString();
            //     }
            //     else
            //     {
            //         newcert.sampleentryparameter2 = "";
            //     }
            // }
            // catch (Exception)
            // {
            //     newcert.sampleentryparameter2 = "";
            // }
            Cert[] newCertArray = { newcert };
            newCertArray = newCertArray.Concat(localCertStore.Certs).ToArray();
            localCertStore.Certs = newCertArray;

            var convertedCertStore = JsonConvert.SerializeObject(localCertStore);
            File.WriteAllText(storePath, convertedCertStore);


        }
        catch (Exception ex)
        {
            //Status: 2=Success, 3=Warning, 4=Error
            return new JobResult()
            {
                Result = Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = ex.Message
            };
        }

        //Status: 2=Success, 3=Warning, 4=Error
        return new JobResult()
        {
            Result = Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Success,
            JobHistoryId = config.JobHistoryId
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
