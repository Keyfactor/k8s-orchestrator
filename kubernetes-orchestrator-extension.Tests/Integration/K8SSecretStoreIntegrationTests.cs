// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using k8s;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.K8S.Tests.Attributes;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Moq;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration;

/// <summary>
/// Integration tests for K8SSecret store type operations against a real Kubernetes cluster.
/// K8SSecret manages Opaque secrets with PEM-formatted certificates and keys.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// </summary>
[Collection("Integration Tests")]
public class K8SSecretStoreIntegrationTests : IAsyncLifetime
{
    private const string TestNamespace = "keyfactor-k8ssecret-integration-tests";
    private static readonly string KubeconfigPath = (Environment.GetEnvironmentVariable("INTEGRATION_TEST_KUBECONFIG") ?? "~/.kube/config").Replace("~", Environment.GetEnvironmentVariable("HOME") ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
    private static readonly string ClusterContext = Environment.GetEnvironmentVariable("INTEGRATION_TEST_CONTEXT") ?? "kf-integrations";

    private Kubernetes _k8sClient;
    private string _kubeconfigJson;
    private readonly List<string> _createdSecrets = new List<string>();
    private Mock<Keyfactor.Orchestrators.Extensions.Interfaces.IPAMSecretResolver> _mockPamResolver;

    public async Task InitializeAsync()
    {
        var runIntegrationTests = Environment.GetEnvironmentVariable("RUN_INTEGRATION_TESTS");
        if (string.IsNullOrEmpty(runIntegrationTests) ||
            !runIntegrationTests.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var kubeconfigPath = KubeconfigPath.Replace("~", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        if (!File.Exists(kubeconfigPath))
        {
            throw new FileNotFoundException($"Kubeconfig not found at {kubeconfigPath}");
        }

        var kubeconfigContent = await File.ReadAllTextAsync(kubeconfigPath);
        _kubeconfigJson = ConvertKubeconfigToJson(kubeconfigContent);

        var config = KubernetesClientConfiguration.BuildConfigFromConfigFile(kubeconfigPath, currentContext: ClusterContext);
        _k8sClient = new Kubernetes(config);

        _mockPamResolver = new Mock<Keyfactor.Orchestrators.Extensions.Interfaces.IPAMSecretResolver>();
        _mockPamResolver.Setup(x => x.Resolve(It.IsAny<string>())).Returns((string)null);

        await CreateNamespaceIfNotExists();
    }

    public async Task DisposeAsync()
    {
        var runIntegrationTests = Environment.GetEnvironmentVariable("RUN_INTEGRATION_TESTS");
        if (string.IsNullOrEmpty(runIntegrationTests) ||
            !runIntegrationTests.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var skipCleanup = Environment.GetEnvironmentVariable("SKIP_INTEGRATION_TEST_CLEANUP");
        if (!string.IsNullOrEmpty(skipCleanup) &&
            skipCleanup.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        foreach (var secretName in _createdSecrets)
        {
            try
            {
                await _k8sClient.CoreV1.DeleteNamespacedSecretAsync(secretName, TestNamespace);
            }
            catch (Exception)
            {
                // Ignore cleanup errors
            }
        }

        _k8sClient?.Dispose();
    }

    private async Task CreateNamespaceIfNotExists()
    {
        try
        {
            await _k8sClient.CoreV1.ReadNamespaceAsync(TestNamespace);
        }
        catch (k8s.Autorest.HttpOperationException ex) when (ex.Response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            var ns = new V1Namespace
            {
                Metadata = new V1ObjectMeta
                {
                    Name = TestNamespace,
                    Labels = new Dictionary<string, string>
                    {
                        { "purpose", "integration-tests" },
                        { "managed-by", "keyfactor-k8s-orchestrator-tests" }
                    }
                }
            };
            await _k8sClient.CoreV1.CreateNamespaceAsync(ns);
        }
    }

    private string ConvertKubeconfigToJson(string kubeconfigContent)
    {
        var kubeconfigPath = KubeconfigPath.Replace("~", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        var fileContent = File.ReadAllText(kubeconfigPath);

        // Detect if the file is already JSON (starts with '{')
        if (fileContent.TrimStart().StartsWith("{"))
        {
            // File is already JSON, return as-is
            return fileContent;
        }

        // File is YAML, convert using KubernetesClientConfiguration
        var config = KubernetesClientConfiguration.BuildConfigFromConfigFile(
            kubeconfigPath,
            currentContext: ClusterContext);

        var kubeconfigObj = new Dictionary<string, object>
        {
            ["kind"] = "Config",
            ["apiVersion"] = "v1",
            ["current-context"] = ClusterContext,
            ["clusters"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = ClusterContext,
                    ["cluster"] = new Dictionary<string, object>
                    {
                        ["server"] = config.Host,
                        ["certificate-authority-data"] = config.SslCaCerts?.Any() == true ?
                            Convert.ToBase64String(config.SslCaCerts.First().Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert)) : null
                    }
                }
            },
            ["users"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = ClusterContext,
                    ["user"] = new Dictionary<string, object>
                    {
                        ["token"] = config.AccessToken,
                        ["client-certificate-data"] = config.ClientCertificateData,
                        ["client-key-data"] = config.ClientCertificateKeyData
                    }
                }
            },
            ["contexts"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = ClusterContext,
                    ["context"] = new Dictionary<string, object>
                    {
                        ["cluster"] = ClusterContext,
                        ["user"] = ClusterContext,
                        ["namespace"] = TestNamespace
                    }
                }
            }
        };

        return JsonSerializer.Serialize(kubeconfigObj);
    }

    private async Task<V1Secret> CreateTestOpaqueSecret(string name, KeyType keyType = KeyType.Rsa2048, bool includePrivateKey = true, bool includeChain = false)
    {
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Integration Test {name}");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var data = new Dictionary<string, byte[]>
        {
            { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
        };

        if (includePrivateKey)
        {
            var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);
            data["tls.key"] = Encoding.UTF8.GetBytes(keyPem);
        }

        if (includeChain)
        {
            var chain = CertificateTestHelper.GenerateCertificateChain(keyType);
            var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
            var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
            data["ca.crt"] = Encoding.UTF8.GetBytes(intermediatePem + rootPem);
        }

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = name,
                NamespaceProperty = TestNamespace
            },
            Type = "Opaque",
            Data = data
        };

        var created = await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);
        _createdSecrets.Add(name);
        return created;
    }

    #region Inventory Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_OpaqueSecretWithCertificate_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-opaque-cert-{Guid.NewGuid():N}";
        await CreateTestOpaqueSecret(secretName, KeyType.Rsa2048, includePrivateKey: true);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SSecret",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = "{\"KubeSecretType\":\"opaque\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_OpaqueSecretWithChain_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-opaque-chain-{Guid.NewGuid():N}";
        await CreateTestOpaqueSecret(secretName, KeyType.Rsa2048, includePrivateKey: true, includeChain: true);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SSecret",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = "{\"KubeSecretType\":\"opaque\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_CertificateOnlySecret_ReturnsSuccess()
    {
        // Arrange - Some secrets may contain only certificates without private keys
        var secretName = $"test-certonly-{Guid.NewGuid():N}";
        await CreateTestOpaqueSecret(secretName, KeyType.Rsa2048, includePrivateKey: false);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SSecret",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = "{\"KubeSecretType\":\"opaque\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    #endregion

    #region Management Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateToNewSecret_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-add-new-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Management Test Add");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);
        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SSecret",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify secret was created
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("Opaque", secret.Type);
        Assert.True(secret.Data.ContainsKey("tls.crt"));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_RemoveCertificateFromSecret_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-remove-{Guid.NewGuid():N}";
        await CreateTestOpaqueSecret(secretName, KeyType.Rsa2048, includePrivateKey: true);

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SSecret",
            OperationType = CertStoreOperationType.Remove,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert"
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = "{\"KubeSecretType\":\"opaque\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var management = new Management(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithChainBundled_CreatesBundledSecret()
    {
        // Arrange
        var secretName = $"test-add-bundled-chain-{Guid.NewGuid():N}";

        // Generate a certificate chain (root -> intermediate -> leaf)
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKey = chain[0].KeyPair.Private;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SSecret",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12WithChain(
                        leafCert,
                        leafKey,
                        new[] { intermediateCert, rootCert },
                        pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\",\"IncludeCertChain\":true,\"SeparateChain\":false}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify secret was created with bundled chain
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("Opaque", secret.Type);

        // Should have tls.crt and tls.key
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        Assert.True(secret.Data.ContainsKey("tls.key"), "Secret should contain tls.key");

        // Should NOT have ca.crt (chain is bundled into tls.crt)
        Assert.False(secret.Data.ContainsKey("ca.crt"), "Secret should NOT contain ca.crt when SeparateChain=false");

        // Verify tls.crt contains BOTH leaf certificate AND chain certificates (bundled together)
        // When SeparateChain=false and IncludeCertChain=true, the Management job should concatenate
        // the leaf cert and chain certs into a single tls.crt field
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(certCount >= 3, $"Expected leaf + chain (3+ certs total: leaf, intermediate, root) in tls.crt, but found {certCount} certificate(s)");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithChainSeparate_CreatesSeparateChainSecret()
    {
        // Arrange
        var secretName = $"test-add-separate-chain-{Guid.NewGuid():N}";

        // Generate a certificate chain (root -> intermediate -> leaf)
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKey = chain[0].KeyPair.Private;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SSecret",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12WithChain(
                        leafCert,
                        leafKey,
                        new[] { intermediateCert, rootCert },
                        pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\",\"IncludeCertChain\":true,\"SeparateChain\":true}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify secret was created with separate chain
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("Opaque", secret.Type);

        // Should have tls.crt, tls.key, and ca.crt
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        Assert.True(secret.Data.ContainsKey("tls.key"), "Secret should contain tls.key");
        Assert.True(secret.Data.ContainsKey("ca.crt"), "Secret should contain ca.crt when SeparateChain=true");

        // Verify tls.crt contains only the leaf certificate
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var tlsCertCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(tlsCertCount == 1, $"tls.crt should contain only the leaf certificate when SeparateChain=true, but found {tlsCertCount}");

        // Verify ca.crt contains the chain certificates
        var caCrtData = Encoding.UTF8.GetString(secret.Data["ca.crt"]);
        var chainCertCount = System.Text.RegularExpressions.Regex.Matches(caCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(chainCertCount >= 1, $"ca.crt should contain chain certificates, but found {chainCertCount}");
    }

    #endregion

    #region Discovery Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Discovery_FindsOpaqueSecrets_ReturnsSuccess()
    {
        // Arrange - Create multiple Opaque secrets
        var secret1Name = $"test-discover-1-{Guid.NewGuid():N}";
        var secret2Name = $"test-discover-2-{Guid.NewGuid():N}";
        await CreateTestOpaqueSecret(secret1Name, KeyType.Rsa2048);
        await CreateTestOpaqueSecret(secret2Name, KeyType.EcP256);

        var jobConfig = new DiscoveryJobConfiguration
        {
            Capability = "K8SSecret",
            ClientMachine = TestNamespace,
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true,
            JobProperties = new Dictionary<string, object>
            {
                { "dirs", TestNamespace },
                { "ignoreddirs", "" },
                { "patterns", "" }
            }
        };

        var discovery = new Discovery(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => discovery.ProcessJob(jobConfig, (discoveryItems) => true));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    #endregion

    #region Error Handling Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_NonExistentSecret_ReturnsFailure()
    {
        // Arrange
        var nonExistentSecret = $"does-not-exist-{Guid.NewGuid():N}";

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SSecret",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = nonExistentSecret,
                Properties = "{\"KubeSecretType\":\"opaque\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert
        // Non-existent stores return Success with empty inventory and a FailureMessage explaining the issue
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success (lenient behavior for missing stores) but got {result.Result}. FailureMessage: {result.FailureMessage}");
        Assert.NotNull(result.FailureMessage);
        Assert.Contains("not found", result.FailureMessage);
    }

    #endregion

    #region Key Type Coverage Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_Rsa2048Certificate_AddAndInventory_Success()
    {
        var secretName = $"test-rsa2048-secret-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);
        await AddAndInventoryCertificate(secretName, KeyType.Rsa2048);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_Rsa4096Certificate_AddAndInventory_Success()
    {
        var secretName = $"test-rsa4096-secret-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);
        await AddAndInventoryCertificate(secretName, KeyType.Rsa4096);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_EcP256Certificate_AddAndInventory_Success()
    {
        var secretName = $"test-ecp256-secret-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);
        await AddAndInventoryCertificate(secretName, KeyType.EcP256);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_EcP384Certificate_AddAndInventory_Success()
    {
        var secretName = $"test-ecp384-secret-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);
        await AddAndInventoryCertificate(secretName, KeyType.EcP384);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_EcP521Certificate_AddAndInventory_Success()
    {
        var secretName = $"test-ecp521-secret-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);
        await AddAndInventoryCertificate(secretName, KeyType.EcP521);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_Ed25519Certificate_AddAndInventory_Success()
    {
        var secretName = $"test-ed25519-secret-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);
        await AddAndInventoryCertificate(secretName, KeyType.Ed25519);
    }

    private async Task AddAndInventoryCertificate(string secretName, KeyType keyType)
    {
        // Generate certificate with specified key type
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"KeyType Test {keyType}");
        var pfxPassword = "testpassword";

        // Add certificate
        var addJobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SSecret",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(_mockPamResolver.Object);
        var addResult = await Task.Run(() => management.ProcessJob(addJobConfig));

        Assert.True(addResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Add {keyType} certificate expected Success but got {addResult.Result}. FailureMessage: {addResult.FailureMessage}");

        // Verify secret was created
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("Opaque", secret.Type);

        // Inventory the certificate
        var invJobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SSecret",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(_mockPamResolver.Object);
        var invResult = await Task.Run(() => inventory.ProcessJob(invJobConfig, (inventoryItems) => true));

        Assert.True(invResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Inventory {keyType} certificate expected Success but got {invResult.Result}. FailureMessage: {invResult.FailureMessage}");
    }

    #endregion
}
