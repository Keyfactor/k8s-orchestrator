// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.Orchestrator.Kube;

// The Discovery class implements IAgentJobExtension and is meant to find all certificate stores based on the information passed when creating the job in KF Command 
public class Discovery : IDiscoveryJobExtension
{
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
        var logger = LogHandler.GetClassLogger(GetType());
        logger.LogDebug($"Begin Discovery...");
        logger.LogDebug($"Following info received from command:");
        logger.LogDebug(JsonConvert.SerializeObject(config));

        //Instantiate collection of certificate store locations to pass back
        var locations = new List<string>();

        var dirs = config.JobProperties["Dirs"].ToString().Split(',').ToList();
        var ignoreddirs = config.JobProperties["IgnoredDirs"].ToString().Split(',').ToList();
        var patterns = config.JobProperties["Patterns"].ToString().Split(',').ToList();


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
            foreach (var dir in dirs)
            {
                if (Directory.Exists(dir))
                {
                    if (!ignoreddirs.Contains(dir))
                    {
                        var filelist = Directory.GetFiles(dir).ToList<string>();
                        foreach (var file in filelist)
                        {
                            foreach (var pattern in patterns)
                            {
                                if (Regex.Match(file, pattern).Success)
                                {
                                    var location = dir + file;
                                    locations.Add(location);
                                }
                            }
                        }
                    }
                }
            }
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

        try
        {
            //Sends store locations back to KF command where they can be approved or rejected
            submitDiscovery.Invoke(locations);
            //Status: 2=Success, 3=Warning, 4=Error
            return new JobResult()
            {
                Result = Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Success,
                JobHistoryId = config.JobHistoryId
            };
        }
        catch (Exception ex)
        {
            // NOTE: if the cause of the submitInventory.Invoke exception is a communication issue between the Orchestrator server and the Command server, the job status returned here
            //  may not be reflected in Keyfactor Command.
            return new JobResult()
            {
                Result = Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Failure,
                JobHistoryId = config.JobHistoryId,
                FailureMessage = ex.Message
            };
        }
    }
}
