using System;
using System.Collections.Generic;
using k8s.Exceptions;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

// The Discovery class implements IAgentJobExtension and is meant to find all certificate stores based on the information passed when creating the job in KF Command 
public abstract class DiscoveryBase : JobBase
{
    protected List<string> DiscoveredLocations = new();
    protected string[] SearchNamespaces = Array.Empty<string>();
    protected string[] IgnoredNamespaces = Array.Empty<string>();
    protected string[] SecretAllowedKeys = Array.Empty<string>();
    protected string SecretType;

    protected void Init(DiscoveryJobConfiguration config)
    {
        //NLog Logging to c:\CMS\Logs\CMS_Agent_Log.txt
        Logger = LogHandler.GetClassLogger(GetType());
        Logger.LogInformation("Begin Discovery for K8S Orchestrator Extension for job {JobID}", config.JobId);
        Logger.LogInformation("Discovery for store type: {Capability}", config.Capability);
        try
        {
            Logger.LogDebug("Calling InitializeStore()");
            InitializeStore(config);
            Logger.LogDebug("Store initialized successfully");
        }
        catch (Exception ex)
        {
            Logger.LogError("Failed to initialize store: {Error}", ex.Message);
            Logger.LogTrace("{StackTrace}", ex.ToString());
            // return FailJob("Failed to initialize store: " + ex.Message, config.JobHistoryId);
            throw new Exception("Failed to initialize store: " + ex.Message);
        }

        KubeSvcCreds = ServerPassword;
        Logger.LogDebug("Calling KubeCertificateManagerClient()");
        KubeClient = new KubeCertificateManagerClient(KubeSvcCreds, config.UseSSL); //todo does this throw an exception?
        Logger.LogDebug("Returned from KubeCertificateManagerClient()");
        if (KubeClient == null)
        {
            Logger.LogError("Failed to create KubeCertificateManagerClient");
            throw new KubeConfigException("Failed to create KubeCertificateManagerClient");
        }

        SearchNamespaces = config.JobProperties["dirs"].ToString()?.Split(',') ?? Array.Empty<string>();
        if (SearchNamespaces is null or { Length: 0 })
        {
            Logger.LogDebug("No namespaces provided, using `default` namespace");
            SearchNamespaces = new[] { "default" };
        }

        Logger.LogDebug("Namespaces: {Namespaces}", string.Join(",", SearchNamespaces));

        IgnoredNamespaces = config.JobProperties["ignoreddirs"].ToString()?.Split(',') ?? Array.Empty<string>();
        Logger.LogDebug("Ignored Namespaces: {Namespaces}", string.Join(",", IgnoredNamespaces));

        SecretAllowedKeys = config.JobProperties["patterns"].ToString()?.Split(',') ?? Array.Empty<string>();
        Logger.LogDebug("Secret Allowed Keys: {AllowedKeys}", string.Join(",", SecretAllowedKeys));

        Logger.LogDebug("Returning from DiscoveryBase Init()");
    }
}