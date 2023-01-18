// Copyright 2021 Keyfactor                                                   
// Licensed under the Apache License, Version 2.0 (the "License"); you may    
// not use this file except in compliance with the License.  You may obtain a 
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless 
// required by applicable law or agreed to in writing, software distributed   
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for  
// thespecific language governing permissions and limitations under the       
// License. 

using System;
using System.Collections.Generic;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;

using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.Orchestrator.SOS
{
    // The Inventory class implementes IAgentJobExtension and is meant to find all of the certificates in a given certificate store on a given server
    //  and return those certificates back to Keyfactor for storing in its database.  Private keys will NOT be passed back to Keyfactor Command 


    public class Inventory : IInventoryJobExtension
    {
        public class SampleCertStore
        {
            public string storeparameter1 { get; set; } = "";
            public Cert[] certs { get; set; }
        }

        public class Cert
        {
            public string alias { get; set; } = "";
            public string certdata { get; set; } = "";
            public string privatekey { get; set; } = "";
            public string sampleentryparameter1 { get; set; } = "";
            public string sampleentryparameter2 { get; set; } = "";
        }
        //Necessary to implement IInventoryJobExtension but not used.  Leave as empty string.
        public string ExtensionName => "SOS";

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
            ILogger logger = LogHandler.GetClassLogger(this.GetType());
            logger.LogDebug($"Begin Inventory...");

            logger.LogDebug($"Following info received from command:");
            logger.LogDebug(JsonConvert.SerializeObject(config));

            string storepath = config.CertificateStoreDetails.StorePath.ToString();
            string properties = config.CertificateStoreDetails.Properties.ToString();
            string storepassword = config.CertificateStoreDetails.StorePassword.ToString();
   
            logger.LogDebug($"Processing store");
            //List<AgentCertStoreInventoryItem> is the collection that the interface expects to return from this job.  It will contain a collection of certificates found in the store along with other information about those certificates
            List<CurrentInventoryItem> inventoryItems = new List<CurrentInventoryItem>();

            try
            {
                //Code logic to:
                // 1) Connect to the orchestrated server (config.CertificateStoreDetails.ClientMachine) containing the certificate store to be inventoried (config.CertificateStoreDetails.StorePath)

                // 2) Custom logic to retrieve certificates from certificate store.
                // read file into a string and deserialize JSON to a type
                // string storetypename = "Kubernetes";
                // SampleCertStore LocalCertStore = JsonConvert.DeserializeObject<SampleCertStore>(File.ReadAllText(storepath + @"\" + storetypename));
                var c = new KubeCertificateManagerClient("", "default");
                // var certRequest = c.GenerateCertificateRequest("CN=MEOW",new string[]{"meow.com", "MEOW"}, Array.Empty<IPAddress>(), "RSA", 4096);
                // var kubeSigningRequest = c.CreateCertificateSigningRequest("meow", "default", certRequest.CSR);
                // Console.WriteLine(certRequest.CSR);
                // Console.WriteLine(certRequest.PrivateKey);
                // Console.WriteLine(certRequest.PublicKey);
                var csrs = c.GetKubeCertInventory();
                foreach (var csr in csrs)
                {
                    logger.LogInformation(csr);
                }
                // To prevents the screen from 
                // running and closing quickly
                // Console.ReadKey();
                
                foreach (var cert in csrs)
                {
                    string[] certs = { cert };
                
                    string alias = cert;
                    inventoryItems.Add(new CurrentInventoryItem()
                    {
                        ItemStatus = OrchestratorInventoryItemStatus.Unknown, //There are other statuses, but Command can determine how to handle new vs modified certificates
                        Alias = alias,
                        PrivateKeyEntry = false, //You will not pass the private key back, but you can identify if the main certificate of the chain contains a private key in the store
                        UseChainLevel = false,  //true if Certificates will contain > 1 certificate, main cert => intermediate CA cert => root CA cert.  false if Certificates will contain an array of 1 certificate
                        Certificates = certs //Array of single X509 certificates in Base64 string format (certificates if chain, single cert if not), something like:
                });
                } 

                // 3) Add certificates (no private keys) to the collection below.  If multiple certs in a store comprise a chain, the Certificates array will house multiple certs per InventoryItem.  If multiple certs
                //     in a store comprise separate unrelated certs, there will be one InventoryItem object created per certificate.

                //**** Will need to uncomment the block below and code to the extension's specific needs.  This builds the collection of certificates and related information that will be passed back to the KF Orchestrator service and then Command.


            }
            catch (Exception ex)
            {
                //Status: 2=Success, 3=Warning, 4=Error
                return new JobResult()
                {
                    Result = Keyfactor.Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Failure, 
                    JobHistoryId = config.JobHistoryId, 
                    FailureMessage = ex.ToString()
                };
            }

            try
            {
                //Sends inventoried certificates back to KF Command
                submitInventory.Invoke(inventoryItems);
                //Status: 2=Success, 3=Warning, 4=Error
                return new JobResult()
                {
                    Result = Keyfactor.Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Success, 
                    JobHistoryId = config.JobHistoryId
                };
            }
            catch (Exception ex)
            {
                // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
                //  may not be reflected in Keyfactor Command.
                return new JobResult()
                {
                    Result = Keyfactor.Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Failure, 
                    JobHistoryId = config.JobHistoryId, 
                    FailureMessage = ex.ToString()
                };
            }
        }
    }
}