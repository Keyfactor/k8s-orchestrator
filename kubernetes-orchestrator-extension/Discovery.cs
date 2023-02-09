// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.Kube;

// The Discovery class implements IAgentJobExtension and is meant to find all certificate stores based on the information passed when creating the job in KF Command 
public class Discovery : IDiscoveryJobExtension
{
    private static readonly string CertChainSeparator = ",";

    private readonly IPAMSecretResolver _resolver;

    private KubeCertificateManagerClient _kubeClient;

    private ILogger _logger;

    public Discovery(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    private string KubeSvcCreds { get; set; }

    private string ServerUsername { get; set; }

    private string ServerPassword { get; set; }

    //Necessary to implement IDiscoveryJobExtension but not used.  Leave as empty string.
    public string ExtensionName => "Kube";

    //Job Entry Point
    public JobResult ProcessJob(DiscoveryJobConfiguration config, SubmitDiscoveryUpdate submitDiscovery)
    {
        //METHOD ARGUMENTS...
        //config - contains context information passed from KF Command to this job run:
        //
        // config.ServerUsername, config.ServerPassword - credentials for orchestrated server - use to authenticate to certificate store server.
        // config.ClientMachine - server name or IP address of orchestrated server
        //
        // config.JobProperties["dirs"] - Directories to search
        // config.JobProperties["extensions"] - Extensions to search
        // config.JobProperties["ignoreddirs"] - Directories to ignore
        // config.JobProperties["patterns"] - File name patterns to match


        //NLog Logging to c:\CMS\Logs\CMS_Agent_Log.txt
        _logger.LogDebug("Begin Discovery...");

        _logger.LogInformation($"Discovery for store type: {config.Capability}");

        ServerUsername = ResolvePamField("Server User Name", config.ServerUsername);
        ServerPassword = ResolvePamField("Server Password", config.ServerPassword);

        _logger.LogDebug($"Begin {config.Capability} for job id {config.JobId.ToString()}...");
        // logger.LogTrace($"Store password: {storePassword}"); //Do not log passwords
        _logger.LogTrace($"Server: {config.ClientMachine}");

        var locations = new List<string>();

        KubeSvcCreds = ServerPassword;

        if (ServerUsername == "kubeconfig")
        {
            _logger.LogInformation("Using kubeconfig provided by 'Server Password' field");
            KubeSvcCreds = ServerPassword;
            // logger.LogTrace($"KubeSvcCreds: {localCertStore.KubeSvcCreds}"); //Do not log passwords
        }

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
            //Code logic to:
            // 1) Connect to the orchestrated server if necessary (config.CertificateStoreDetails.ClientMachine)
            // 2) Custom logic to search for valid certificate stores based on passed in:
            //      a) Directories to search
            //      b) Extensions
            //      c) Directories to ignore
            //      d) File name patterns to match
            // 3) Place found and validated store locations (path and file name) in "locations" collection instantiated above
            _kubeClient = new KubeCertificateManagerClient(KubeSvcCreds);

            var discoveredSecrets = _kubeClient.DiscoverSecrets(); // This gets all secrets in the namespace but will filter by opaque and tls types below
            var discoveredCerts = _kubeClient.DiscoverCertificates(); // This gets all certs in the namespace but will filter by tls type below
            locations.AddRange(discoveredSecrets);
            locations.AddRange(discoveredCerts);

        }
        catch (Exception ex)
        {
            //Status: 2=Success, 3=Warning, 4=Error
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = ex.Message
            };
        }

        try
        {
            //Sends store locations back to KF command where they can be approved or rejected
            submitDiscovery.Invoke(locations);
            //Status: 2=Success, 3=Warning, 4=Error
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Success,
                JobHistoryId = config.JobHistoryId
            };
        }
        catch (Exception ex)
        {
            // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
            //  may not be reflected in Keyfactor Command.
            return new JobResult
            {
                Result = OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = ex.Message
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
}
