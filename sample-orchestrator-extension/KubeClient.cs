// Copyright 2022 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System;
using k8s;
using k8s.Models;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.PKI.PEM;

namespace Keyfactor.Extensions.Orchestrator.Kube;

public class KubeCertificateManagerClient
{
    public KubeCertificateManagerClient(string credentialsFile, string context)
    {
        Client = GetKubeClient(credentialsFile);
    }

    public IKubernetes Client { get; set; }

    public IKubernetes GetKubeClient(string credentialFileName)
    {
        //Credentials file needs to be in the same location of the executing assembly
        var strExeFilePath = Assembly.GetExecutingAssembly().Location;
        var strWorkPath = Path.GetDirectoryName(strExeFilePath);
        //var strSettingsJsonFilePath = Path.Combine(strWorkPath ?? string.Empty, credentialFileName); //TODO: so this is just where a config must live? /RiderProjects/gcp-certmanager-orchestrator/GcpCertManagerTestConsole/bin/Debug/netcoreapp3.1/  
        //var stream = new FileStream(strSettingsJsonFilePath,
        //   FileMode.Open
        //);
        var config = credentialFileName == ""
            ? KubernetesClientConfiguration.BuildDefaultConfig()
            : KubernetesClientConfiguration.BuildConfigFromConfigFile();

        IKubernetes client = new Kubernetes(config);

        _ = client.CoreV1.ListNamespace();
        Client = client;
        return client;
    }

    public V1Secret GetCertificateSecret(string secretName, string namespaceName)
    {
        return Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
    }

    public V1Secret CreateCertificateStoreSecret(string[] keyPems, string[] certPems, string[] caCertPems, string[] chainPems, int kfid, string secretName,
        string namespaceName, string secretType, bool append = false, bool overwrite = false)
    {
        var certPem = string.Join("\n", certPems);
        var keyPem = string.Join("\n", keyPems);
        var caCertPem = string.Join("\n", caCertPems);
        var chainPem = string.Join("\n\n", chainPems);
        V1Secret k8sSecretData;
        if (secretType == "secret")
        {
            k8sSecretData = new V1Secret
            {
                Metadata = new V1ObjectMeta
                {
                    Name = secretName,
                    NamespaceProperty = namespaceName
                },

                Data = new Dictionary<string, byte[]>
                {
                    { "private_keys", Encoding.UTF8.GetBytes(keyPem) },
                    { "certificates", Encoding.UTF8.GetBytes(certPem) },
                    { "ca_certificates", Encoding.UTF8.GetBytes(caCertPem) },
                    { "chain", Encoding.UTF8.GetBytes(chainPem) },
                    { "kfid", Encoding.UTF8.GetBytes(kfid.ToString()) }
                }
            };
        }
        else
        {
            k8sSecretData = new V1Secret
            {
                Metadata = new V1ObjectMeta
                {
                    Name = secretName,
                    NamespaceProperty = namespaceName

                },

                Type = "kubernetes.io/tls",

                Data = new Dictionary<string, byte[]>
                {
                    { "tls.key", Encoding.UTF8.GetBytes(keyPem) },
                    { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
                }
            };
        }


        try
        {
            var secretResponse = Client.CoreV1.CreateNamespacedSecret(k8sSecretData, namespaceName);
            return secretResponse;
        }
        catch (k8s.Autorest.HttpOperationException e)
        {
            if (e.Message.Contains("Conflict"))
            {
                if (append)
                {
                    var existingSecret = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName, true);
                    if (existingSecret == null)
                    {
                        throw new Exception(
                            $"Create secret {secretName} in Kubernetes namespace {namespaceName} failed. Also unable to read secret, please verify credentials have correct access.");
                    }
                    switch (secretType)
                    {
                        // check if certificate already exists in "certificates" field
                        case "secret":
                        {
                            var existingCerts = Encoding.UTF8.GetString(existingSecret.Data["certificates"]);
                            if (existingCerts.Contains(certPem))
                            {
                                return existingSecret;
                            }
                            var newCerts = existingCerts;
                            if (existingCerts.Length > 0)
                            {
                                newCerts = newCerts + ",";
                            }
                            newCerts = newCerts + certPem;

                            existingSecret.Data["certificates"] = Encoding.UTF8.GetBytes(newCerts);
                            var secretResponse = Client.CoreV1.ReplaceNamespacedSecret(existingSecret, secretName, namespaceName);
                            return secretResponse;
                        }
                        // TODO: Check if overwrite is specified if not then fail.
                        // TODO: Check if multiple certs are trying to be added which is not supported.
                        case "tls_secret" when !overwrite:
                            throw new Exception("Overwrite is not specified, cannot add multiple certificates to a Kubernetes secret type 'tls_secret'.");
                        case "tls_secret":
                        {
                            var secretResponse = Client.CoreV1.ReplaceNamespacedSecret(k8sSecretData, secretName, namespaceName);
                            return secretResponse;
                        }
                    }

                }
                else
                {
                    var secretResponse = Client.CoreV1.ReplaceNamespacedSecret(k8sSecretData, secretName, namespaceName);
                    return secretResponse;
                }
            }
        }
        return null;
    }

    public V1Secret GetCertificateStoreSecret(string secretName, string namespaceName)
    {
        return Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
    }

    public string GetRemoteStore(string secretName, string namespaceName)
    {
        var secretResponse = Client.CoreV1.ReadNamespacedSecret(
            secretName,
            namespaceName,
            true
        );
        return secretResponse.Data.ToString();
    }


    public V1Status DeleteCertificateStoreSecret(string secretName, string namespaceName, string storeType, string alias)
    {
        switch (storeType)
        {
            case "secret":
                // check the current inventory and only remove the cert if it is found else throw not found exception
                var existingSecret = Client.CoreV1.ReadNamespacedSecret(secretName, namespaceName, true);
                if (existingSecret == null)
                {
                    throw new Exception(
                        $"Delete secret {secretName} in Kubernetes namespace {namespaceName} failed. Also unable to read secret, please verify credentials have correct access.");
                }

                // handle cert removal
                var existingCerts = Encoding.UTF8.GetString(existingSecret.Data["certificates"]);
                var existingKeys = Encoding.UTF8.GetString(existingSecret.Data["private_keys"]);
                var certs = existingCerts.Split(",");
                var keys = existingKeys.Split(",");
                var index = 0;
                foreach (var cer in certs)
                {
                    var sCert = new X509Certificate2(Encoding.UTF8.GetBytes(cer));
                    if (sCert.Thumbprint == alias)
                    {
                        existingCerts = existingCerts.Replace(cer, "").Replace(",,", ",");
                        if (existingCerts.StartsWith(","))
                        {
                            existingCerts = existingCerts.Substring(1);
                        }
                        if (existingCerts.EndsWith(","))
                        {
                            existingCerts = existingCerts.Substring(0, existingCerts.Length - 1);
                        }

                        try {
                            existingKeys = existingKeys.Replace(keys[index], "").Replace(",,", ",");
                        }
                        catch (Exception) {
                            // Didn't find existing key for whatever reason so no need to delete.
                            existingKeys = existingKeys;
                        }
                        
                        if (existingKeys.StartsWith(","))
                        {
                            existingKeys = existingKeys.Substring(1);
                        }
                        if (existingKeys.EndsWith(","))
                        {
                            existingKeys = existingKeys.Substring(0, existingKeys.Length - 1);
                        }
                    }
                    index++;
                }
                existingSecret.Data["certificates"] = Encoding.UTF8.GetBytes(existingCerts);
                existingSecret.Data["private_keys"] = Encoding.UTF8.GetBytes(existingKeys);

                // Update Kubernetes secret
                _ = Client.CoreV1.ReplaceNamespacedSecret(existingSecret, secretName, namespaceName);

                return new V1Status("v1", 0, status: "Success");

            case "tls_secret":
                return Client.CoreV1.DeleteNamespacedSecret(
                    secretName,
                    namespaceName,
                    new V1DeleteOptions()
                );
            case "certificate":
                // TODO: See if this is possible
                Client.CertificatesV1.DeleteCertificateSigningRequest(
                    secretName,
                    new V1DeleteOptions()
                );
                throw new NotImplementedException("DeleteCertificateStoreSecret not implemented for 'certificate' type.");
            default:
                throw new NotImplementedException($"DeleteCertificateStoreSecret not implemented for type '{storeType}'.");
        }
        return null;
    }
    public List<string> GetKubeCertInventory()
    {
        var output = new List<string>();
        var csr = Client.CertificatesV1.ListCertificateSigningRequest();
        foreach (var cr in csr)
        {
            var utfCert = cr.Status.Certificate != null ? Encoding.UTF8.GetString(cr.Status.Certificate) : "";
            string utfCsr;
            utfCsr = cr.Spec.Request != null
                ? Encoding.UTF8.GetString(cr.Spec.Request, 0, cr.Spec.Request.Length)
                : "";

            if (utfCsr != "") Console.WriteLine(utfCsr);
            if (utfCert != "")
            {
                var cert = new X509Certificate2(Encoding.UTF8.GetBytes(utfCert));
                var certName = cert.GetNameInfo(X509NameType.SimpleName, false);
                Console.WriteLine(certName);
            }
            else
            {
                output.Add(utfCsr);
            }

            Console.WriteLine("Cert:" + utfCert);
        }

        return output;
    }

    public V1CertificateSigningRequest CreateCertificateSigningRequest(string name, string namespaceName, string csr)
    {
        var request = new V1CertificateSigningRequest
        {
            ApiVersion = "certificates.k8s.io/v1",
            Kind = "CertificateSigningRequest",
            Metadata = new V1ObjectMeta
            {
                Name = name,
                NamespaceProperty = namespaceName
            },
            Spec = new V1CertificateSigningRequestSpec
            {
                Request = Encoding.UTF8.GetBytes(csr),
                Groups = new List<string> { "system:authenticated" },
                Usages = new List<string> { "digital signature", "key encipherment", "server auth", "client auth" },
                SignerName = "kubernetes.io/kube-apiserver-client"
            }
        };
        return Client.CertificatesV1.CreateCertificateSigningRequest(request);
    }

    public CsrObject GenerateCertificateRequest(string name, string[] sans, IPAddress[] ips,
        string keyType = "RSA", int keyBits = 4096)
    {
        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var ip in ips) sanBuilder.AddIpAddress(ip);
        foreach (var san in sans) sanBuilder.AddDnsName(san);

        var distinguishedName = new X500DistinguishedName(name);

        using var rsa = RSA.Create(4096);
        var pkey = rsa.ExportPkcs8PrivateKey();
        var pubkey = rsa.ExportRSAPublicKey();

        var request =
            new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature,
            false));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        request.CertificateExtensions.Add(sanBuilder.Build());
        var csr = request.CreateSigningRequest();
        var csrPem = "-----BEGIN CERTIFICATE REQUEST-----\r\n" +
                     Convert.ToBase64String(csr) +
                     "\r\n-----END CERTIFICATE REQUEST-----";
        var keyPem = "-----BEGIN PRIVATE KEY-----\r\n" +
                     Convert.ToBase64String(pkey) +
                     "\r\n-----END PRIVATE KEY-----";
        var pubKeyPem = "-----BEGIN PUBLIC KEY-----\r\n" +
                        Convert.ToBase64String(pubkey) +
                        "\r\n-----END PUBLIC KEY-----";
        return new CsrObject
        {
            Csr = csrPem,
            PrivateKey = keyPem,
            PublicKey = pubKeyPem
        };
    }

    // public string SignCSR(string csr)
    // {
    //     var kfClient = new Client("https://sbailey-lab.kfdelivery.com/KeyfactorAPI",
    //         "a2ZhZG1pbkBjb21tYW5kOldoNUcyVGM2VkJZalNNcEM=");
    //     var now = DateTime.Now.ToUniversalTime();
    //     var csrReq = new CSREnrollmentRequest
    //     {
    //         CSR = csr,
    //         CertificateAuthority = "CommandCA1",
    //         IncludeChain = true,
    //         Timestamp = now,
    //         Template = "2YearTestWebServer",
    //
    //     };
    //     var enrollResp = kfClient.PostCSREnrollAsync("PEM", csrReq).Result;
    //     return 
    // }

    // private static void Main(string[] args)
    // {
    //     var c = new KubeCertificateManagerClient("", "default");
    //     // var certRequest = c.GenerateCertificateRequest("CN=MEOW",new string[]{"meow.com", "MEOW"}, Array.Empty<IPAddress>(), "RSA", 4096);
    //     // var kubeSigningRequest = c.CreateCertificateSigningRequest("meow", "default", certRequest.CSR);
    //     // Console.WriteLine(certRequest.CSR);
    //     // Console.WriteLine(certRequest.PrivateKey);
    //     // Console.WriteLine(certRequest.PublicKey);
    //     var csrs = c.GetKubeCertInventory();
    //     foreach (var csr in csrs)
    //     {
    //         var signedCert = c.SignCSR(csr);
    //         Console.WriteLine(signedCert);
    //     }
    //     // To prevents the screen from 
    //     // running and closing quickly
    //     // Console.ReadKey();
    // }

    public struct CsrObject
    {
        public string Csr;
        public string PrivateKey;
        public string PublicKey;
    }
}
