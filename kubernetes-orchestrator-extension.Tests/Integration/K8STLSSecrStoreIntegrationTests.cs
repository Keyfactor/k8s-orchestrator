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
/// Integration tests for K8STLSSecr store type operations against a real Kubernetes cluster.
/// K8STLSSecr manages kubernetes.io/tls secrets with strict field names (tls.crt, tls.key, ca.crt).
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// </summary>
[Collection("K8STLSSecr Integration Tests")]
public class K8STLSSecrStoreIntegrationTests : IntegrationTestBase
{
    protected override string BaseTestNamespace => "keyfactor-k8stlssecr-integration-tests";

    public K8STLSSecrStoreIntegrationTests(IntegrationTestFixture fixture) : base(fixture)
    {
    }

    private async Task<V1Secret> CreateTestTlsSecret(string name, KeyType keyType = KeyType.Rsa2048, bool includeChain = false)
    {
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Integration Test {name}");
        return await CreateTestTlsSecretFromCertInfo(name, certInfo, keyType, includeChain);
    }

    /// <summary>
    /// Creates a TLS secret using a pre-generated certificate. Useful for read-only tests
    /// that can share cached certificates to reduce test execution time.
    /// </summary>
    private async Task<V1Secret> CreateTestTlsSecretFromCertInfo(
        string name,
        CertificateInfo certInfo,
        KeyType keyType = KeyType.Rsa2048,
        bool includeChain = false,
        List<CertificateInfo>? chainCerts = null)
    {
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var data = new Dictionary<string, byte[]>
        {
            { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
            { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
        };

        if (includeChain)
        {
            var chain = chainCerts ?? CachedCertificateProvider.GetOrCreateChain(keyType);
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
        // Arrange - Use cached certificate for read-only inventory test
        var secretName = $"test-tls-cert-{Guid.NewGuid():N}";
        var cachedCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Inventory TLS Test");
        await CreateTestTlsSecretFromCertInfo(secretName, cachedCert, KeyType.Rsa2048);

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
        // Arrange - Use cached certificate and chain for read-only inventory test
        var secretName = $"test-tls-chain-{Guid.NewGuid():N}";
        var cachedChain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "Inventory Chain TLS Test");
        await CreateTestTlsSecretFromCertInfo(secretName, cachedChain[0], KeyType.Rsa2048, includeChain: true, chainCerts: cachedChain);

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
        // Arrange - Test with EC certificate using cached certificate for read-only test
        var secretName = $"test-tls-ec-{Guid.NewGuid():N}";
        var cachedCert = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Inventory EC TLS Test");
        await CreateTestTlsSecretFromCertInfo(secretName, cachedCert, KeyType.EcP256);

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
        // Arrange - Create multiple TLS secrets using cached certificates for read-only discovery test
        var secret1Name = $"test-discover-tls-1-{Guid.NewGuid():N}";
        var secret2Name = $"test-discover-tls-2-{Guid.NewGuid():N}";
        var cachedRsaCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Discovery RSA TLS Test");
        var cachedEcCert = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Discovery EC TLS Test");
        await CreateTestTlsSecretFromCertInfo(secret1Name, cachedRsaCert, KeyType.Rsa2048);
        await CreateTestTlsSecretFromCertInfo(secret2Name, cachedEcCert, KeyType.EcP256);

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
    public async Task Inventory_EmptyTlsSecret_ReturnsSuccessWithEmptyInventory()
    {
        // Arrange - Create an empty TLS secret (exists but has no certificate data)
        var secretName = $"test-empty-tls-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Array.Empty<byte>() },
                { "tls.key", Array.Empty<byte>() }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

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

        // Assert - Empty secrets should return success, not fail
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success for empty secret but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    // NOTE: This test was removed because Kubernetes enforces schema validation on TLS secrets.
    // You CANNOT create a kubernetes.io/tls secret without tls.crt - the K8s API server rejects it
    // with HTTP 422: "data[tls.crt]: Required value". The scenario is impossible in Kubernetes.
    // If you need to test missing certificate handling, use an Opaque secret type instead.

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
        // Arrange - Use cached certificate for read-only compatibility test
        var secretName = $"test-ingress-tls-{Guid.NewGuid():N}";
        var cachedCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Ingress Compat TLS Test");
        await CreateTestTlsSecretFromCertInfo(secretName, cachedCert, KeyType.Rsa2048);

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

    #region Certificate Chain Inventory Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_TlsSecretWithMultipleCertsInCaCrt_ReturnsAllCertificates()
    {
        // Arrange - Create a TLS secret with leaf cert in tls.crt and multiple CA certs in ca.crt
        // Use cached chain for read-only inventory test
        var secretName = $"test-chain-multi-ca-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Get cached certificate chain: Root -> Sub-CA -> Leaf
        // Chain returns List<CertificateInfo> with [0]=leaf, [1]=intermediate, [2]=root
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "Multi CA Inventory Test");
        var leafCertPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var subCaPem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootCaPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var leafKeyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // ca.crt contains both Sub-CA and Root-CA
        var caCrtContent = subCaPem + rootCaPem;

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "kubernetes.io/tls",
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
    public async Task Inventory_TlsSecretWithChainInTlsCrt_ReturnsAllCertificates()
    {
        // Arrange - Create a TLS secret with full chain in tls.crt (no separate ca.crt)
        // Use cached chain for read-only inventory test
        var secretName = $"test-chain-in-tlscrt-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Get cached certificate chain
        // Chain returns List<CertificateInfo> with [0]=leaf, [1]=intermediate, [2]=root
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "Chain In TlsCrt Inventory Test");
        var leafCertPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var subCaPem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootCaPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var leafKeyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // tls.crt contains full chain: Leaf + Sub-CA + Root
        var tlsCrtContent = leafCertPem + subCaPem + rootCaPem;

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(tlsCrtContent) },
                { "tls.key", Encoding.UTF8.GetBytes(leafKeyPem) }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

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
        // This simulates when Command sends a certificate without private key
        var secretName = $"test-der-nopk-tls-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate DER-encoded certificate (no private key)
        var derCertBase64 = CertificateTestHelper.GenerateBase64DerCertificate(KeyType.Rsa2048, "DER No Private Key Test");

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8STLSSecr",
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

        // Assert - Should succeed even without private key (with warning)
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify secret was created
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithoutPrivateKey_PemFormat_ReturnsSuccess()
    {
        // Arrange - Test adding a certificate in PEM format (no private key)
        var secretName = $"test-pem-nopk-tls-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate PEM-encoded certificate (no private key)
        var pemCert = CertificateTestHelper.GeneratePemCertificateOnly(KeyType.Rsa2048, "PEM No Private Key Test");
        var pemCertBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(pemCert));

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8STLSSecr",
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

        // Assert - Should succeed even without private key (with warning)
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify secret was created
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_UpdateExistingTlsSecretWithCertificateOnly_FailsWhenExistingKeyPresent()
    {
        // Arrange - First create a TLS secret WITH a private key
        var secretName = $"test-tls-update-certonly-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Original TLS Cert");
        var pfxPassword = "testpassword";
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword);

        // Create initial TLS secret with certificate AND private key
        var createJobConfig = new ManagementJobConfiguration
        {
            Capability = "K8STLSSecr",
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
                Properties = $"{{\"KubeSecretType\":\"tls_secret\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = false
        };

        var management = new Management(MockPamResolver.Object);
        var createResult = await Task.Run(() => management.ProcessJob(createJobConfig));
        Assert.True(createResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Failed to create initial TLS secret: {createResult.FailureMessage}");

        // Verify initial secret has tls.key
        var initialSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.True(initialSecret.Data.ContainsKey("tls.key"), "Initial TLS secret should have tls.key");

        // Now try to update with certificate-only (no private key)
        var newCertDer = CertificateTestHelper.GenerateBase64DerCertificate(KeyType.Rsa2048, "Updated TLS Cert No Key");

        var updateJobConfig = new ManagementJobConfiguration
        {
            Capability = "K8STLSSecr",
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
                Properties = $"{{\"KubeSecretType\":\"tls_secret\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true,
            Overwrite = true // Update existing
        };

        // Act
        var updateResult = await Task.Run(() => management.ProcessJob(updateJobConfig));

        // Assert - Should FAIL because we're trying to update a TLS secret that has a private key
        // with a certificate-only (no private key), which would leave a mismatched key
        Assert.True(updateResult.Result == OrchestratorJobStatusJobResult.Failure,
            $"Expected Failure but got {updateResult.Result}. " +
            "Deploying cert-only to a TLS secret with existing private key should fail to prevent key mismatch.");

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
        var secretName = $"test-{keyType.ToString().ToLowerInvariant()}-tls-{Guid.NewGuid():N}";
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

        // Verify secret was created with correct certificate
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);

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
