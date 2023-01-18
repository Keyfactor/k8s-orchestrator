using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System;
using IdentityModel;

using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

using k8s;
using k8s.Models;


namespace Keyfactor.Extensions.Orchestrator.SOS
{
    public class KubeCertificateManagerClient
    {
        public KubeCertificateManagerClient(string credentialsFile, string context)
        {
            Client = GetKubeClient(credentialsFile);
            Console.Out.WriteLine("Done");
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
            ILogger logger = LogHandler.GetClassLogger(this.GetType());
            var config = credentialFileName == ""
                ? KubernetesClientConfiguration.BuildDefaultConfig()
                : KubernetesClientConfiguration.BuildConfigFromConfigFile();

            IKubernetes client = new Kubernetes(config);
            Console.WriteLine("Starting Request!");
            var csr = client.CertificatesV1.ListCertificateSigningRequest();
            foreach ( var cert in csr )
            {
                Console.WriteLine(cert);
            }
            Client = client;
            return client;
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
                CSR = csrPem,
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
            public string CSR;
            public string PrivateKey;
            public string PublicKey;
        }
    }
}
