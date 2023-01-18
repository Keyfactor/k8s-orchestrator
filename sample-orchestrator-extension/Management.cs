﻿// Copyright 2021 Keyfactor                                                   
// Licensed under the Apache License, Version 2.0 (the "License"); you may    
// not use this file except in compliance with the License.  You may obtain a 
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless 
// required by applicable law or agreed to in writing, software distributed   
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for  
// thespecific language governing permissions and limitations under the       
// License. 


using System;

using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Common.Enums;

using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using static Keyfactor.Extensions.Orchestrator.SOS.Inventory;
using System.IO;
using Newtonsoft.Json.Linq;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;

namespace Keyfactor.Extensions.Orchestrator.SOS
{
    public class Management : IManagementJobExtension
    {
        //Necessary to implement IManagementJobExtension but not used.  Leave as empty string.
        public string ExtensionName => "SOS";

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
            ILogger logger = LogHandler.GetClassLogger(this.GetType());
            logger.LogDebug($"Begin Management...");
            logger.LogDebug($"Following info received from command:");
            logger.LogDebug(JsonConvert.SerializeObject(config));

            logger.LogDebug(config.ToString());
            string storetypename = "kubernetes";
            string storepath = config.CertificateStoreDetails.StorePath + @"\" + storetypename;
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
                        SampleCertStore LocalCertStore = JsonConvert.DeserializeObject<SampleCertStore>(File.ReadAllText(storepath));
                        Cert newcert = new Cert();
                        byte[] bytes = Convert.FromBase64String(config.JobCertificate.Contents.ToString());
                        var cert = new X509Certificate2(bytes);

                        newcert.alias = cert.Thumbprint.ToString();
                        newcert.certdata = config.JobCertificate.Contents.ToString();
                        newcert.privatekey = config.JobCertificate.PrivateKeyPassword;

                        newcert.sampleentryparameter1 = config.JobProperties["sampleentryparameter1"].ToString();
                        newcert.sampleentryparameter2 = config.JobProperties["sampleentryparameter2"].ToString();
                        Cert[] newcertarray = { newcert };
                        newcertarray = newcertarray.Concat(LocalCertStore.certs).ToArray();
                        LocalCertStore.certs = newcertarray;

                        string convertedcertstore = JsonConvert.SerializeObject(LocalCertStore);
                        File.WriteAllText(storepath, convertedcertstore);
                        break;
                    case CertStoreOperationType.Remove:
                        //OperationType == Remove - Delete a certificate from the certificate store passed in the config object
                        //Code logic to:
                        // 1) Connect to the orchestrated server (config.CertificateStoreDetails.ClientMachine) containing the certificate store
                        // 2) Custom logic to remove the certificate in a certificate store (config.CertificateStoreDetails.StorePath), possibly using alias (config.JobCertificate.Alias) or certificate thumbprint to identify the certificate (implementation dependent)
                        SampleCertStore RemoveLocalCertStore= JsonConvert.DeserializeObject<SampleCertStore>(File.ReadAllText(storepath));
                        var removealias = config.JobCertificate.Alias.ToString();
                        var converted = RemoveLocalCertStore.certs.ToList();
                        converted.RemoveAll(x => x.alias == removealias);
                        var rmarray = converted.ToArray<Cert>();
                        RemoveLocalCertStore.certs = rmarray;
                        string remconvertedcertstore = JsonConvert.SerializeObject(RemoveLocalCertStore);
                        File.WriteAllText(storepath, remconvertedcertstore);
                        break;
                    case CertStoreOperationType.Create:
                        //OperationType == Create - Create an empty certificate store in the provided location
                        //Code logic to:
                        // 1) Connect to the orchestrated server (config.CertificateStoreDetails.ClientMachine) where the certificate store (config.CertificateStoreDetails.StorePath) will be located
                        // 2) Custom logic to first check if the store already exists and add it if not.  If it already exists, implementation dependent as to how to handle - error, warning, success
                        if (!File.Exists(storepath))
                        {
                            SampleCertStore newstore = new SampleCertStore();
                            string newstoreconv = JsonConvert.SerializeObject(newstore);
                            File.WriteAllText(storepath, newstoreconv);
                        }
                        break;
                    default:
                        //Invalid OperationType.  Return error.  Should never happen though
                        return new JobResult() { Result = Keyfactor.Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Failure, JobHistoryId = config.JobHistoryId, FailureMessage = $"Site {config.CertificateStoreDetails.StorePath} on server {config.CertificateStoreDetails.ClientMachine}: Unsupported operation: {config.OperationType.ToString()}" };
                }
            }
            catch (Exception ex)
            {
                //Status: 2=Success, 3=Warning, 4=Error
                return new JobResult()
                {
                    Result = Keyfactor.Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Failure, 
                    JobHistoryId = config.JobHistoryId, 
                    FailureMessage = ex.Message
                };
            }

            //Status: 2=Success, 3=Warning, 4=Error
            return new JobResult()
            {
                Result = Keyfactor.Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Success, 
                JobHistoryId = config.JobHistoryId
            };
        }
    }
}