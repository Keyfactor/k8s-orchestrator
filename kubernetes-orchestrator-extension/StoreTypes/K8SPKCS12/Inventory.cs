using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SPKCS12;

public class Inventory : InventoryBase, IInventoryJobExtension
{
    public Inventory(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

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

        Init(config);

        var allowedKeys = new List<string>();
        if (!string.IsNullOrEmpty(CertificateDataFieldName))
            allowedKeys = CertificateDataFieldName.Split(',').ToList();
        
        try
        {
            //combine allowed keys and CertificateDataFields into one list
            allowedKeys.AddRange(Pkcs12AllowedKeys);
            Logger.LogInformation("Inventorying PKCS12 using the following allowed keys: {Keys}", allowedKeys);
            var pkcs12Inventory = HandlePkcs12Secret(config, allowedKeys);
            Logger.LogDebug("Returned inventory count: {Count}", pkcs12Inventory.Count.ToString());
            return PushInventory(pkcs12Inventory, config.JobHistoryId, submitInventory, true);
        }
        catch (Exception ex)
        {
            Logger.LogError("{Message}", ex.Message);
            Logger.LogTrace("{Message}", ex.ToString());
            //Status: 2=Success, 3=Warning, 4=Error
            Logger.LogInformation("End INVENTORY for K8S Orchestrator Extension for job {JobId} with failure",
                config.JobHistoryId);
            return FailJob(ex.Message, config.JobHistoryId);
        }
    }
    
    private Dictionary<string, List<string>> HandlePkcs12Secret(JobConfiguration config, List<string> allowedKeys)
    {
        var hasPrivateKey = false;
        var pkcs12Store = new Pkcs12CertificateStoreSerializer(config.JobProperties?.ToString());
        var k8sData = KubeClient.GetPkcs12Secret(KubeSecretName, KubeNamespace, "", "", allowedKeys);
        var pkcs12InventoryDict = new Dictionary<string, List<string>>();
        // iterate through the keys in the secret and add them to the pkcs12 store
        foreach (var (keyName, keyBytes) in k8sData.Inventory)
        {
            var keyPassword = GetK8SStorePassword(k8sData.Secret);
            var pStoreDs = pkcs12Store.DeserializeRemoteCertificateStore(keyBytes, keyName, keyPassword);
            // create a list of certificate chains in PEM format
            foreach (var certAlias in pStoreDs.Aliases)
            {
                var certChainList = new List<string>();
                var certChain = pStoreDs.GetCertificateChain(certAlias);
                var certChainPem = new StringBuilder();
                var fullAlias = keyName + "/" + certAlias;
                //check if the alias is a private key
                if (pStoreDs.IsKeyEntry(certAlias)) hasPrivateKey = true;
                var pKey = pStoreDs.GetKey(certAlias);
                if (pKey != null) hasPrivateKey = true;

                // if (certChain == null)
                // {
                //     pkcs12InventoryDict[fullAlias] = string.Join("", certChainList);
                //     continue;
                // }

                if (certChain != null)
                    foreach (var cert in certChain)
                    {
                        certChainPem = new StringBuilder();
                        certChainPem.AppendLine("-----BEGIN CERTIFICATE-----");
                        certChainPem.AppendLine(Convert.ToBase64String(cert.Certificate.GetEncoded()));
                        certChainPem.AppendLine("-----END CERTIFICATE-----");
                        certChainList.Add(certChainPem.ToString());
                    }

                if (certChainList.Count != 0)
                {
                    // pkcs12InventoryDict[fullAlias] = string.Join("", certChainList);
                    pkcs12InventoryDict[fullAlias] = certChainList;
                    continue;
                }

                var leaf = pStoreDs.GetCertificate(certAlias);
                if (leaf != null)
                {
                    certChainPem = new StringBuilder();
                    certChainPem.AppendLine("-----BEGIN CERTIFICATE-----");
                    certChainPem.AppendLine(Convert.ToBase64String(leaf.Certificate.GetEncoded()));
                    certChainPem.AppendLine("-----END CERTIFICATE-----");
                    certChainList.Add(certChainPem.ToString());
                    // var certificate = new X509Certificate2(leaf.Certificate.GetEncoded());
                    // var cn = certificate.GetNameInfo(X509NameType.SimpleName, false);
                    // fullAlias = keyName + "/" + cn;
                }

                // pkcs12InventoryDict[fullAlias] = string.Join("", certChainList);
                pkcs12InventoryDict[fullAlias] = certChainList;
            }
        }

        return pkcs12InventoryDict;
    }
    
    
}