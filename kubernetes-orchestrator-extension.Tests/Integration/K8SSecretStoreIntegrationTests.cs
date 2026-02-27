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
using CertificateUtilities = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration;

/// <summary>
/// Integration tests for K8SSecret store type operations against a real Kubernetes cluster.
/// K8SSecret manages Opaque secrets with PEM-formatted certificates and keys.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// </summary>
[Collection("K8SSecret Integration Tests")]
public class K8SSecretStoreIntegrationTests : IntegrationTestBase
{
    protected override string BaseTestNamespace => "keyfactor-k8ssecret-integration-tests";

    public K8SSecretStoreIntegrationTests(IntegrationTestFixture fixture) : base(fixture)
    {
    }

    private async Task<V1Secret> CreateTestOpaqueSecret(string name, KeyType keyType = KeyType.Rsa2048, bool includePrivateKey = true, bool includeChain = false)
    {
        // Use cached certificates for read-only inventory/discovery tests
        var certInfo = CachedCertificateProvider.GetOrCreate(keyType, $"Cached Opaque Secret {keyType}");
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
            var chain = CachedCertificateProvider.GetOrCreateChain(keyType);
            var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
            var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
            data["ca.crt"] = Encoding.UTF8.GetBytes(intermediatePem + rootPem);
        }

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(name),
            Type = "Opaque",
            Data = data
        };

        var created = await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);
        TrackSecret(name);
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
    public async Task Management_AddCertificateToNewSecret_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-add-new-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Management Test Add");
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
        Assert.Equal("Opaque", secret.Type);

        // Verify required fields exist
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        Assert.True(secret.Data.ContainsKey("tls.key"), "Secret should contain tls.key for certificates with private key");

        // Verify field contents are valid PEM
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var tlsKeyData = Encoding.UTF8.GetString(secret.Data["tls.key"]);
        Assert.Contains("-----BEGIN CERTIFICATE-----", tlsCrtData);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", tlsKeyData);
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

        // Verify secret was created with bundled chain
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
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

        // Verify secret was created with separate chain
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithChain_IncludeCertChainFalse_OnlyLeafCertStored()
    {
        // Arrange
        var secretName = $"test-add-no-chain-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate a certificate chain (leaf -> intermediate -> root)
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKey = chain[0].KeyPair.Private;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pfxPassword = "testpassword";

        // Create PKCS12 with full chain
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12WithChain(
            leafCert,
            leafKey,
            new[] { intermediateCert, rootCert },
            pfxPassword);

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SSecret",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(pkcs12Bytes)
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\",\"IncludeCertChain\":false}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert - Job should succeed
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Read the secret directly from Kubernetes
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("Opaque", secret.Type);

        // Verify tls.crt exists
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");

        // Parse tls.crt and verify it contains ONLY the leaf certificate (not intermediate or root)
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.Equal(1, certCount);

        // Verify the single certificate is the leaf cert by checking subject
        using var reader = new System.IO.StringReader(tlsCrtData);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
        var parsedCert = (Org.BouncyCastle.X509.X509Certificate)pemReader.ReadObject();
        Assert.Equal(leafCert.SubjectDN.ToString(), parsedCert.SubjectDN.ToString());

        // Verify no ca.crt field exists (chain was excluded)
        Assert.False(secret.Data.ContainsKey("ca.crt"), "Secret should NOT contain ca.crt when IncludeCertChain=false");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithChain_InvalidConfig_IncludeCertChainFalse_SeparateChainTrue_RespectsIncludeCertChain()
    {
        // Arrange - Test invalid configuration: IncludeCertChain=false, SeparateChain=true
        // The code should log a warning and respect IncludeCertChain=false (only leaf cert deployed)
        var secretName = $"test-invalid-config-opaque-{Guid.NewGuid():N}";
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
            Capability = "K8SSecret",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = secretName,
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
                StorePath = $"{TestNamespace}/{secretName}",
                // Invalid config: SeparateChain=true but IncludeCertChain=false
                // Should warn and respect IncludeCertChain=false
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\",\"IncludeCertChain\":false,\"SeparateChain\":true}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert - Should succeed (with warning logged)
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify secret was created
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("Opaque", secret.Type);

        // Verify IncludeCertChain=false is respected: only leaf certificate, no chain
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(certCount == 1, $"tls.crt should contain only the leaf certificate when IncludeCertChain=false, but found {certCount} certificate(s)");

        // Verify there is NO ca.crt (IncludeCertChain=false takes precedence over SeparateChain=true)
        Assert.False(secret.Data.ContainsKey("ca.crt"), "Secret should NOT contain ca.crt when IncludeCertChain=false (even if SeparateChain=true)");
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
    public async Task Inventory_EmptyOpaqueSecret_ReturnsSuccessWithEmptyInventory()
    {
        // Arrange - Create an empty Opaque secret (exists but has no certificate data)
        var secretName = $"test-empty-opaque-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Array.Empty<byte>() },
                { "tls.key", Array.Empty<byte>() }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SSecret",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert - Empty secrets should return success, not fail
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success for empty secret but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_OpaqueSecretWithNoCertificateFields_ReturnsSuccessWithEmptyInventory()
    {
        // Arrange - Create an Opaque secret with no certificate-related fields
        var secretName = $"test-nocertfields-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "some-other-data", Encoding.UTF8.GetBytes("not a certificate") }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SSecret",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert - Secrets without certificate fields should return success with empty inventory
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success for secret without certificate fields but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

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

    #region Certificate Chain Inventory Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_OpaqueSecretWithMultipleCertsInCaCrt_ReturnsAllCertificates()
    {
        // Arrange - Create an Opaque secret with leaf cert in tls.crt and multiple CA certs in ca.crt
        var secretName = $"test-opaque-chain-multi-ca-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate a certificate chain: Root -> Sub-CA -> Leaf
        // Use cached chain for read-only inventory test
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCertPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var subCaPem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootCaPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var leafKeyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // ca.crt contains both Sub-CA and Root-CA
        var caCrtContent = subCaPem + rootCaPem;

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafCertPem) },
                { "tls.key", Encoding.UTF8.GetBytes(leafKeyPem) },
                { "ca.crt", Encoding.UTF8.GetBytes(caCrtContent) }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SSecret",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);
        var inventoriedCerts = new List<CurrentInventoryItem>();

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (items) =>
        {
            inventoriedCerts.AddRange(items);
            return true;
        }));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Chain certificates are returned as ONE inventory item with multiple certificates in the Certificates array
        Assert.Single(inventoriedCerts);
        // The single inventory item should contain all 3 certificates from the chain
        Assert.Equal(3, inventoriedCerts[0].Certificates.Count());

        // Verify we have all three certificates by checking subjects
        var certSubjects = inventoriedCerts[0].Certificates.Select(certPem =>
        {
            using var reader = new System.IO.StringReader(certPem);
            var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
            var cert = (Org.BouncyCastle.X509.X509Certificate)pemReader.ReadObject();
            return cert.SubjectDN.ToString();
        }).ToList();

        Assert.Contains(certSubjects, s => s.Contains("Leaf"));
        Assert.Contains(certSubjects, s => s.Contains("Intermediate") || s.Contains("Sub"));
        Assert.Contains(certSubjects, s => s.Contains("Root"));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_OpaqueSecretWithChainInTlsCrt_ReturnsAllCertificates()
    {
        // Arrange - Create an Opaque secret with full chain in tls.crt (no separate ca.crt)
        var secretName = $"test-opaque-chain-in-tlscrt-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate a certificate chain
        // Use cached chain for read-only inventory test
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCertPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var subCaPem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootCaPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var leafKeyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // tls.crt contains full chain: Leaf + Sub-CA + Root
        var tlsCrtContent = leafCertPem + subCaPem + rootCaPem;

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(tlsCrtContent) },
                { "tls.key", Encoding.UTF8.GetBytes(leafKeyPem) }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SSecret",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);
        var inventoriedCerts = new List<CurrentInventoryItem>();

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (items) =>
        {
            inventoriedCerts.AddRange(items);
            return true;
        }));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Chain certificates are returned as ONE inventory item with multiple certificates in the Certificates array
        Assert.Single(inventoriedCerts);
        // The single inventory item should contain all 3 certificates from the chain
        Assert.Equal(3, inventoriedCerts[0].Certificates.Count());
    }

    #endregion

    #region Certificate Without Private Key Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithoutPrivateKey_DerFormat_ReturnsSuccess()
    {
        // Arrange - Test adding a certificate in DER format (no private key)
        // Opaque secrets can store certificate-only without requiring a private key
        var secretName = $"test-der-nopk-opaque-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate DER-encoded certificate (no private key)
        var derCertBase64 = CertificateTestHelper.GenerateBase64DerCertificate(KeyType.Rsa2048, "DER No Private Key Test");

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SSecret",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert-nopk",
                PrivateKeyPassword = "", // No password since no private key
                Contents = derCertBase64
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert - Opaque secrets should succeed without private key
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify secret was created with certificate only (no tls.key)
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("Opaque", secret.Type);
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        // Opaque secrets without private key should NOT have tls.key
        Assert.False(secret.Data.ContainsKey("tls.key"), "Secret should NOT contain tls.key when no private key provided");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithoutPrivateKey_PemFormat_ReturnsSuccess()
    {
        // Arrange - Test adding a certificate in PEM format (no private key)
        var secretName = $"test-pem-nopk-opaque-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate PEM-encoded certificate (no private key)
        var pemCert = CertificateTestHelper.GeneratePemCertificateOnly(KeyType.Rsa2048, "PEM No Private Key Test");
        var pemCertBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(pemCert));

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SSecret",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert-pem-nopk",
                PrivateKeyPassword = "", // No password since no private key
                Contents = pemCertBase64
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert - Opaque secrets should succeed without private key
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify secret was created with certificate only
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("Opaque", secret.Type);
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        Assert.False(secret.Data.ContainsKey("tls.key"), "Secret should NOT contain tls.key when no private key provided");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_OpaqueSecretWithCertificateOnly_ReturnsSuccess()
    {
        // Arrange - Create a secret with only a certificate (no private key)
        var secretName = $"test-certonly-inv-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Use cached certificate for read-only inventory test
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert Only Inventory Test");
        var pemCert = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(pemCert) }
                // No tls.key - certificate only
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SSecret",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\"}}"
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
    public async Task Management_UpdateExistingSecretWithCertificateOnly_FailsWhenExistingKeyPresent()
    {
        // Arrange - First create a secret WITH a private key
        var secretName = $"test-update-certonly-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Original Cert");
        var pfxPassword = "testpassword";
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword);

        // Create initial secret with certificate AND private key
        var createJobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SSecret",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(pkcs12Bytes)
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(MockPamResolver.Object);
        var createResult = await Task.Run(() => management.ProcessJob(createJobConfig));
        Assert.True(createResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Failed to create initial secret: {createResult.FailureMessage}");

        // Verify initial secret has tls.key
        var initialSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.True(initialSecret.Data.ContainsKey("tls.key"), "Initial secret should have tls.key");

        // Now try to update with certificate-only (no private key) - using DER format
        var newCertDer = CertificateTestHelper.GenerateBase64DerCertificate(KeyType.Rsa2048, "Updated Cert No Key");

        var updateJobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SSecret",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert-updated",
                PrivateKeyPassword = "", // No password - certificate only
                Contents = newCertDer
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = secretName,
                Properties = $"{{\"KubeSecretType\":\"opaque\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = true // Update existing
        };

        // Act
        var updateResult = await Task.Run(() => management.ProcessJob(updateJobConfig));

        // Assert - Should FAIL because we're trying to update a secret that has a private key
        // with a certificate-only (no private key), which would leave a mismatched key
        Assert.True(updateResult.Result == OrchestratorJobStatusJobResult.Failure,
            $"Expected Failure but got {updateResult.Result}. " +
            "Deploying cert-only to a secret with existing private key should fail to prevent key mismatch.");

        // Verify the failure message explains the issue
        Assert.Contains("private key", updateResult.FailureMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("mismatched", updateResult.FailureMessage, StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region Key Type Coverage Tests

    [SkipUnlessTheory(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    [MemberData(nameof(KeyTypeTestData.AllKeyTypes), MemberType = typeof(KeyTypeTestData))]
    public async Task Management_Certificate_AddAndInventory_Success(KeyType keyType)
    {
        var secretName = $"test-{keyType.ToString().ToLowerInvariant()}-secret-{Guid.NewGuid():N}";
        TrackSecret(secretName);
        await AddAndInventoryCertificate(secretName, keyType);
    }

    private async Task AddAndInventoryCertificate(string secretName, KeyType keyType)
    {
        // Generate certificate with specified key type
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"KeyType Test {keyType}");
        var pfxPassword = "testpassword";

        // Calculate expected thumbprint BEFORE deployment
        var expectedThumbprint = CertificateUtilities.GetThumbprint(certInfo.Certificate);
        var expectedSubject = certInfo.Certificate.SubjectDN.ToString();

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
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(MockPamResolver.Object);
        var addResult = await Task.Run(() => management.ProcessJob(addJobConfig));

        Assert.True(addResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Add {keyType} certificate expected Success but got {addResult.Result}. FailureMessage: {addResult.FailureMessage}");

        // Verify secret was created with correct certificate
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("Opaque", secret.Type);

        // Verify the deployed certificate matches the input certificate
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should have tls.crt field");
        var deployedCertPem = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var parser = new Org.BouncyCastle.X509.X509CertificateParser();
        using var reader = new System.IO.StringReader(deployedCertPem);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
        var deployedCert = (Org.BouncyCastle.X509.X509Certificate)pemReader.ReadObject();

        var deployedThumbprint = CertificateUtilities.GetThumbprint(deployedCert);
        var deployedSubject = deployedCert.SubjectDN.ToString();

        Assert.True(expectedThumbprint == deployedThumbprint,
            $"Deployed certificate thumbprint doesn't match. Expected: {expectedThumbprint}, Got: {deployedThumbprint}");
        Assert.True(expectedSubject == deployedSubject,
            $"Deployed certificate subject doesn't match. Expected: {expectedSubject}, Got: {deployedSubject}");

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
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);
        var inventoriedCerts = new List<CurrentInventoryItem>();
        var invResult = await Task.Run(() => inventory.ProcessJob(invJobConfig, (inventoryItems) =>
        {
            inventoriedCerts.AddRange(inventoryItems);
            return true;
        }));

        Assert.True(invResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Inventory {keyType} certificate expected Success but got {invResult.Result}. FailureMessage: {invResult.FailureMessage}");

        // Verify inventoried certificate matches the input certificate
        Assert.NotEmpty(inventoriedCerts);
        var inventoriedCertPem = inventoriedCerts[0].Certificates.First();
        using var invReader = new System.IO.StringReader(inventoriedCertPem);
        var invPemReader = new Org.BouncyCastle.OpenSsl.PemReader(invReader);
        var inventoriedCert = (Org.BouncyCastle.X509.X509Certificate)invPemReader.ReadObject();
        var inventoriedThumbprint = CertificateUtilities.GetThumbprint(inventoriedCert);

        Assert.True(expectedThumbprint == inventoriedThumbprint,
            $"Inventoried certificate thumbprint doesn't match. Expected: {expectedThumbprint}, Got: {inventoriedThumbprint}");
    }

    #endregion
}
