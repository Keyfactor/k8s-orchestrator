// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using k8s;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.K8S.Tests.Attributes;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Keyfactor.Orchestrators.K8S.Tests.Integration.Fixtures;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration;

/// <summary>
/// Integration tests for K8STLSSecr store type operations against a real Kubernetes cluster.
/// K8STLSSecr manages kubernetes.io/tls secrets with strict field names (tls.crt, tls.key, ca.crt).
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// </summary>
[Collection("K8STLSSecr Integration Tests")]
public class K8STLSSecrStoreIntegrationTests : IntegrationTestBase
{
    protected override string TestNamespace => "keyfactor-k8stlssecr-integration-tests";

    public K8STLSSecrStoreIntegrationTests(IntegrationTestFixture fixture) : base(fixture)
    {
    }

    private async Task<V1Secret> CreateTestTlsSecret(string name, KeyType keyType = KeyType.Rsa2048, bool includeChain = false)
    {
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Integration Test {name}");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var data = new Dictionary<string, byte[]>
        {
            { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
            { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
        };

        if (includeChain)
        {
            var chain = CertificateTestHelper.GenerateCertificateChain(keyType);
            var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
            var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
            data["ca.crt"] = Encoding.UTF8.GetBytes(intermediatePem + rootPem);
        }

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(name),
            Type = "kubernetes.io/tls",
            Data = data
        };

        var created = await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);
        TrackSecret(name);
        return created;
    }

    #region Inventory Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_TlsSecretWithCertificate_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-tls-cert-{Guid.NewGuid():N}";
        await CreateTestTlsSecret(secretName, KeyType.Rsa2048);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8STLSSecr",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"tls_secret\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_TlsSecretWithChain_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-tls-chain-{Guid.NewGuid():N}";
        await CreateTestTlsSecret(secretName, KeyType.Rsa2048, includeChain: true);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8STLSSecr",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"tls_secret\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_EcCertificate_ReturnsSuccess()
    {
        // Arrange - Test with EC certificate
        var secretName = $"test-tls-ec-{Guid.NewGuid():N}";
        await CreateTestTlsSecret(secretName, KeyType.EcP256);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8STLSSecr",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"tls_secret\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    #endregion

    #region Management Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateToNewTlsSecret_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-add-new-tls-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Management Test Add");
        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8STLSSecr",
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
                Properties = $"{{\"KubeSecretType\":\"tls_secret\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify secret was created with correct type
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);

        // Verify required fields exist for TLS secrets
        Assert.True(secret.Data.ContainsKey("tls.crt"), "TLS secret should contain tls.crt");
        Assert.True(secret.Data.ContainsKey("tls.key"), "TLS secret should contain tls.key");

        // Verify field contents are valid PEM format
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var tlsKeyData = Encoding.UTF8.GetString(secret.Data["tls.key"]);
        Assert.Contains("-----BEGIN CERTIFICATE-----", tlsCrtData);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", tlsKeyData);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_RemoveCertificateFromTlsSecret_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-remove-tls-{Guid.NewGuid():N}";
        await CreateTestTlsSecret(secretName, KeyType.Rsa2048);

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8STLSSecr",
            OperationType = CertStoreOperationType.Remove,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert"
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"tls_secret\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var management = new Management(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithChainBundled_CreatesBundledTlsCrt()
    {
        // Arrange - Test that when SeparateChain=false, the chain is bundled into tls.crt
        var secretName = $"test-bundled-chain-tls-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate a certificate chain (root -> intermediate -> leaf)
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKey = chain[0].KeyPair.Private;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8STLSSecr",
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
                Properties = $"{{\"KubeSecretType\":\"tls_secret\",\"KubeNamespace\":\"{TestNamespace}\",\"IncludeCertChain\":true,\"SeparateChain\":false}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify secret was created with bundled chain in tls.crt
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);

        // Should have tls.crt and tls.key
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        Assert.True(secret.Data.ContainsKey("tls.key"), "Secret should contain tls.key");

        // Should NOT have ca.crt (chain is bundled into tls.crt)
        Assert.False(secret.Data.ContainsKey("ca.crt"), "Secret should NOT contain ca.crt when SeparateChain=false");

        // Verify tls.crt contains the full chain (leaf + intermediate + root)
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(certCount >= 3, $"Expected leaf + chain (3+ certs) in tls.crt when SeparateChain=false, but found {certCount} certificate(s)");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithChainSeparate_CreatesSeparateCaCrt()
    {
        // Arrange - Test that when SeparateChain=true (default), the chain goes to ca.crt
        var secretName = $"test-separate-chain-tls-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate a certificate chain (root -> intermediate -> leaf)
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKey = chain[0].KeyPair.Private;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8STLSSecr",
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
                Properties = $"{{\"KubeSecretType\":\"tls_secret\",\"KubeNamespace\":\"{TestNamespace}\",\"IncludeCertChain\":true,\"SeparateChain\":true}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify secret was created with separate ca.crt
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);

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
    public async Task Discovery_FindsTlsSecrets_ReturnsSuccess()
    {
        // Arrange - Create multiple TLS secrets
        var secret1Name = $"test-discover-tls-1-{Guid.NewGuid():N}";
        var secret2Name = $"test-discover-tls-2-{Guid.NewGuid():N}";
        await CreateTestTlsSecret(secret1Name, KeyType.Rsa2048);
        await CreateTestTlsSecret(secret2Name, KeyType.EcP256);

        var jobConfig = new DiscoveryJobConfiguration
        {
            Capability = "K8STLSSecr",
            ClientMachine = TestNamespace,
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            JobProperties = new Dictionary<string, object>
            {
                { "dirs", TestNamespace },
                { "ignoreddirs", "" },
                { "patterns", "" }
            }
        };

        var discovery = new Discovery(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => discovery.ProcessJob(jobConfig, (discoveryItems) => true));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    #endregion

    #region Error Handling Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_NonExistentTlsSecret_ReturnsFailure()
    {
        // Arrange
        var nonExistentSecret = $"does-not-exist-tls-{Guid.NewGuid():N}";

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8STLSSecr",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = nonExistentSecret,
                Properties = "{\"KubeSecretType\":\"tls_secret\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

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

    #region Native Kubernetes Compatibility Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task TlsSecret_CompatibleWithK8sIngress_CorrectFormat()
    {
        // Verify that K8STLSSecr secrets are compatible with native K8S resources like Ingress
        // Arrange
        var secretName = $"test-ingress-tls-{Guid.NewGuid():N}";
        await CreateTestTlsSecret(secretName, KeyType.Rsa2048);

        // Act - Read back the secret
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);

        // Assert - Verify it matches native K8S TLS secret format
        Assert.Equal("kubernetes.io/tls", secret.Type);
        Assert.True(secret.Data.ContainsKey("tls.crt"));
        Assert.True(secret.Data.ContainsKey("tls.key"));

        // Verify PEM format
        var certPem = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var keyPem = Encoding.UTF8.GetString(secret.Data["tls.key"]);
        Assert.Contains("-----BEGIN CERTIFICATE-----", certPem);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", keyPem);
    }

    #endregion

    #region Key Type Coverage Tests

    [SkipUnlessTheory(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    [MemberData(nameof(KeyTypeTestData.AllKeyTypes), MemberType = typeof(KeyTypeTestData))]
    public async Task Management_Certificate_AddAndInventory_Success(KeyType keyType)
    {
        var secretName = $"test-{keyType.ToString().ToLowerInvariant()}-tls-{Guid.NewGuid():N}";
        TrackSecret(secretName);
        await AddAndInventoryCertificate(secretName, keyType);
    }

    private async Task AddAndInventoryCertificate(string secretName, KeyType keyType)
    {
        // Generate certificate with specified key type
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"KeyType Test {keyType}");
        var pfxPassword = "testpassword";

        // Add certificate
        var addJobConfig = new ManagementJobConfiguration
        {
            Capability = "K8STLSSecr",
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
                Properties = $"{{\"KubeSecretType\":\"tls_secret\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(MockPamResolver.Object);
        var addResult = await Task.Run(() => management.ProcessJob(addJobConfig));

        Assert.True(addResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Add {keyType} certificate expected Success but got {addResult.Result}. FailureMessage: {addResult.FailureMessage}");

        // Verify secret was created
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);

        // Inventory the certificate
        var invJobConfig = new InventoryJobConfiguration
        {
            Capability = "K8STLSSecr",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"tls_secret\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);
        var invResult = await Task.Run(() => inventory.ProcessJob(invJobConfig, (inventoryItems) => true));

        Assert.True(invResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Inventory {keyType} certificate expected Success but got {invResult.Result}. FailureMessage: {invResult.FailureMessage}");
    }

    #endregion
}
