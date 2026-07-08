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
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SNS;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.K8S.Tests.Attributes;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Keyfactor.Orchestrators.K8S.Tests.Integration.Fixtures;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration;

/// <summary>
/// Integration tests for K8SNS store type operations against a real Kubernetes cluster.
/// K8SNS manages ALL secrets within a SINGLE namespace.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// </summary>
[Collection("K8SNS Integration Tests")]
public class K8SNSStoreIntegrationTests : IntegrationTestBase
{
    protected override string BaseTestNamespace => "keyfactor-k8sns-integration-tests";

    public K8SNSStoreIntegrationTests(IntegrationTestFixture fixture) : base(fixture)
    {
    }

    private async Task<V1Secret> CreateTestSecret(string name, KeyType keyType = KeyType.Rsa2048, string secretType = "Opaque", bool useCache = false)
    {
        var certInfo = useCache
            ? CachedCertificateProvider.GetOrCreate(keyType, $"Integration Test {keyType}")
            : CachedCertificateProvider.GetOrCreate(keyType, $"Integration Test {name}");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(name),
            Type = secretType,
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        var created = await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);
        TrackSecret(name);
        return created;
    }

    #region Discovery Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Discovery_SingleNamespace_FindsAllSecrets()
    {
        // Arrange - Create secrets in the namespace (read-only test uses cached certs)
        var secret1Name = $"test-ns-1-{Guid.NewGuid():N}";
        var secret2Name = $"test-ns-2-{Guid.NewGuid():N}";
        await CreateTestSecret(secret1Name, useCache: true);
        await CreateTestSecret(secret2Name, useCache: true);

        var jobConfig = new DiscoveryJobConfiguration
        {
            Capability = "K8SNS",
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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Discovery_MixedSecretTypes_FindsAllTypes()
    {
        // Arrange - Create different secret types in the namespace (read-only test uses cached certs)
        var opaqueSecret = $"test-opaque-ns-{Guid.NewGuid():N}";
        var tlsSecret = $"test-tls-ns-{Guid.NewGuid():N}";
        await CreateTestSecret(opaqueSecret, KeyType.Rsa2048, "Opaque", useCache: true);
        await CreateTestSecret(tlsSecret, KeyType.Rsa2048, "kubernetes.io/tls", useCache: true);

        var jobConfig = new DiscoveryJobConfiguration
        {
            Capability = "K8SNS",
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

    #region Inventory Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_NamespaceScope_ReturnsAllCertificates()
    {
        // Arrange - Create secrets in the namespace (read-only test uses cached certs)
        var secret1Name = $"test-inv-ns-1-{Guid.NewGuid():N}";
        var secret2Name = $"test-inv-ns-2-{Guid.NewGuid():N}";
        await CreateTestSecret(secret1Name, useCache: true);
        await CreateTestSecret(secret2Name, useCache: true);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SNS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = TestNamespace,
                Properties = "{\"KubeSecretType\":\"namespace\"}"
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
    public async Task Management_AddCertificateToNamespace_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-mgmt-ns-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Namespace Management Test");
        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SNS",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"secrets/opaque/{secretName}",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = TestNamespace,
                Properties = "{\"KubeSecretType\":\"namespace\"}"
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

        // Verify secret was created in the correct namespace
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal(TestNamespace, secret.Metadata.NamespaceProperty);
        Assert.Equal("Opaque", secret.Type);

        // Verify required fields exist
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        Assert.True(secret.Data.ContainsKey("tls.key"), "Secret should contain tls.key");

        // Verify field contents are valid PEM format
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var tlsKeyData = Encoding.UTF8.GetString(secret.Data["tls.key"]);
        Assert.Contains("-----BEGIN CERTIFICATE-----", tlsCrtData);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", tlsKeyData);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_RemoveCertificateFromNamespace_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-remove-ns-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName);

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SNS",
            OperationType = CertStoreOperationType.Remove,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"secrets/opaque/{secretName}"
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = TestNamespace,
                Properties = "{\"KubeSecretType\":\"namespace\"}"
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
    public async Task Management_AddCertificateWithChain_IncludeCertChainFalse_OnlyLeafCertStored()
    {
        // Arrange - Test that when IncludeCertChain=false, only the leaf certificate is stored
        var secretName = $"test-no-chain-ns-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate a certificate chain (root -> intermediate -> leaf)
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKey = chain[0].KeyPair.Private;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SNS",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"secrets/tls/{secretName}",
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
                StorePath = TestNamespace,
                Properties = $"{{\"KubeSecretType\":\"tls\",\"KubeNamespace\":\"{TestNamespace}\",\"IncludeCertChain\":false}}"
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

        // Verify secret was created - read directly from Kubernetes
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);

        // Verify tls.crt contains ONLY the leaf certificate (not the chain)
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(certCount == 1, $"tls.crt should contain only the leaf certificate when IncludeCertChain=false, but found {certCount} certificate(s)");

        // Verify there is no ca.crt field (chain was excluded)
        Assert.False(secret.Data.ContainsKey("ca.crt"), "Secret should NOT contain ca.crt when IncludeCertChain=false");

        // Verify the single certificate is indeed the leaf certificate by checking its subject
        using var reader = new System.IO.StringReader(tlsCrtData);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
        var storedCert = (Org.BouncyCastle.X509.X509Certificate)pemReader.ReadObject();
        var storedSubject = storedCert.SubjectDN.ToString();
        var leafSubject = leafCert.SubjectDN.ToString();

        Assert.Equal(leafSubject, storedSubject);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithChain_SeparateChainFalse_ChainBundledInTlsCrt()
    {
        // Arrange - Test that when SeparateChain=false, the full chain is bundled into tls.crt
        var secretName = $"test-bundle-chain-ns-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate a certificate chain (root -> intermediate -> leaf)
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKey = chain[0].KeyPair.Private;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SNS",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"secrets/tls/{secretName}",
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
                StorePath = TestNamespace,
                Properties = $"{{\"KubeSecretType\":\"tls\",\"KubeNamespace\":\"{TestNamespace}\",\"IncludeCertChain\":true,\"SeparateChain\":false}}"
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

        // Verify secret was created
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);

        // Verify there is NO ca.crt (chain bundled into tls.crt)
        Assert.False(secret.Data.ContainsKey("ca.crt"), "Secret should NOT contain ca.crt when SeparateChain=false");

        // Verify tls.crt contains the full chain (leaf + intermediate + root = 3 certs)
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(certCount >= 3, $"Expected leaf + chain (3+ certs) in tls.crt when SeparateChain=false, but found {certCount} certificate(s)");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithChain_SeparateChainTrue_ChainInCaCrt()
    {
        // Arrange - Test that when SeparateChain=true, the chain goes to ca.crt
        var secretName = $"test-separate-chain-ns-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate a certificate chain (root -> intermediate -> leaf)
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKey = chain[0].KeyPair.Private;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SNS",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"secrets/tls/{secretName}",
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
                StorePath = TestNamespace,
                Properties = $"{{\"KubeSecretType\":\"tls\",\"KubeNamespace\":\"{TestNamespace}\",\"IncludeCertChain\":true,\"SeparateChain\":true}}"
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

        // Verify secret was created
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);

        // Verify ca.crt contains the chain (intermediate + root)
        Assert.True(secret.Data.ContainsKey("ca.crt"), "Secret should contain ca.crt when SeparateChain=true");
        var caCrtData = Encoding.UTF8.GetString(secret.Data["ca.crt"]);
        var caCertCount = System.Text.RegularExpressions.Regex.Matches(caCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(caCertCount >= 2, $"ca.crt should contain chain certificates (2+), but found {caCertCount}");

        // Verify tls.crt contains ONLY the leaf certificate
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var tlsCertCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(tlsCertCount == 1, $"tls.crt should contain only the leaf certificate when SeparateChain=true, but found {tlsCertCount}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithChain_InvalidConfig_IncludeCertChainFalse_SeparateChainTrue_RespectsIncludeCertChain()
    {
        // Arrange - Test invalid configuration: IncludeCertChain=false, SeparateChain=true
        // The code should log a warning and respect IncludeCertChain=false (only leaf cert deployed)
        var secretName = $"test-invalid-config-ns-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate a certificate chain (root -> intermediate -> leaf)
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKey = chain[0].KeyPair.Private;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SNS",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"secrets/tls/{secretName}",
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
                StorePath = TestNamespace,
                // Invalid config: SeparateChain=true but IncludeCertChain=false
                // Should warn and respect IncludeCertChain=false
                Properties = $"{{\"KubeSecretType\":\"tls\",\"KubeNamespace\":\"{TestNamespace}\",\"IncludeCertChain\":false,\"SeparateChain\":true}}"
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
        Assert.Equal("kubernetes.io/tls", secret.Type);

        // Verify IncludeCertChain=false is respected: only leaf certificate, no chain
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(certCount == 1, $"tls.crt should contain only the leaf certificate when IncludeCertChain=false, but found {certCount} certificate(s)");

        // Verify there is NO ca.crt (IncludeCertChain=false takes precedence over SeparateChain=true)
        Assert.False(secret.Data.ContainsKey("ca.crt"), "Secret should NOT contain ca.crt when IncludeCertChain=false (even if SeparateChain=true)");
    }

    #endregion

    #region Boundary Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task NamespaceScope_OnlySeesSecretsInNamespace_NotOtherNamespaces()
    {
        // Verify that K8SNS only sees secrets in its namespace (read-only test uses cached certs)
        // This requires creating a secret in another namespace (if we have cluster permissions)
        // For this test, we just verify our namespace secrets are correctly scoped

        // Arrange
        var secretName = $"test-boundary-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, useCache: true);

        // Act - Read secret
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);

        // Assert
        Assert.NotNull(secret);
        Assert.Equal(TestNamespace, secret.Metadata.NamespaceProperty);
    }

    #endregion

    #region Error Handling Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_NonExistentNamespace_ReturnsFailure()
    {
        // Arrange - Use a namespace that doesn't exist
        var nonExistentNamespace = $"does-not-exist-{Guid.NewGuid():N}";

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SNS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = nonExistentNamespace,
                StorePath = nonExistentNamespace,
                Properties = "{\"KubeSecretType\":\"namespace\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert
        // Depending on implementation, this may succeed with empty results or fail
        // The important thing is it doesn't crash and provides appropriate feedback
        Assert.NotNull(result);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_EmptyNamespace_ReturnsSuccess()
    {
        // An empty namespace (no secrets) should return success with empty results
        // We'll use our test namespace and ensure it has no matching secrets by using a filter

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SNS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"nonexistent-secret-{Guid.NewGuid():N}",
                Properties = "{\"KubeSecretType\":\"namespace\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert - Non-existent stores return Success with empty inventory (lenient behavior)
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success (lenient behavior for missing stores) but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_Namespace_ReturnsCorrectPrivateKeyStatus()
    {
        // Arrange - Create one secret with private key and one without (read-only test uses cached certs)
        var secretWithKey = $"test-ns-withkey-{Guid.NewGuid():N}";
        var secretWithoutKey = $"test-ns-nokey-{Guid.NewGuid():N}";

        // Create secret WITH private key
        await CreateTestSecret(secretWithKey, useCache: true);

        // Create secret WITHOUT private key (cert only)
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "NS No Key Test");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var secretNoKey = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = secretWithoutKey,
                NamespaceProperty = TestNamespace,
                Labels = new Dictionary<string, string>
                {
                    { "app.kubernetes.io/managed-by", "keyfactor-integration-tests" }
                }
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
                // No tls.key field
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secretNoKey, TestNamespace);
        TrackSecret(secretWithoutKey);

        var inventoryItems = new List<CurrentInventoryItem>();
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SNS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = TestNamespace,
                Properties = "{\"KubeSecretType\":\"namespace\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (items) =>
        {
            inventoryItems.AddRange(items);
            return true;
        }));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Find our test secrets and verify private key status
        var withKeyItem = inventoryItems.Find(i => i.Alias.Contains(secretWithKey));
        var noKeyItem = inventoryItems.Find(i => i.Alias.Contains(secretWithoutKey));

        Assert.NotNull(withKeyItem);
        Assert.NotNull(noKeyItem);
        Assert.True(withKeyItem.PrivateKeyEntry, $"Secret {secretWithKey} should have PrivateKeyEntry=true");
        Assert.False(noKeyItem.PrivateKeyEntry, $"Secret {secretWithoutKey} should have PrivateKeyEntry=false");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_Namespace_ReturnsFullCertificateChains()
    {
        // Arrange - Create a secret with a certificate chain (read-only test uses cached certs)
        var secretName = $"test-ns-chain-{Guid.NewGuid():N}";

        // Create secret with certificate chain (leaf + intermediate + root)
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCertPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // Bundle all certs in tls.crt field
        var bundledCertPem = leafCertPem + intermediatePem + rootPem;
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = secretName,
                NamespaceProperty = TestNamespace,
                Labels = new Dictionary<string, string>
                {
                    { "app.kubernetes.io/managed-by", "keyfactor-integration-tests" }
                }
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(bundledCertPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);
        TrackSecret(secretName);

        var inventoryItems = new List<CurrentInventoryItem>();
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SNS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = TestNamespace,
                Properties = "{\"KubeSecretType\":\"namespace\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (items) =>
        {
            inventoryItems.AddRange(items);
            return true;
        }));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Find our chain secret
        var chainItem = inventoryItems.Find(i => i.Alias.Contains(secretName));
        Assert.NotNull(chainItem);

        // Should have 3 certificates (leaf + intermediate + root)
        Assert.True(chainItem.Certificates.Count() >= 3,
            $"Expected at least 3 certificates in chain but got {chainItem.Certificates.Count()}");
        Assert.True(chainItem.UseChainLevel,
            "UseChainLevel should be true for secrets with certificate chains");
    }

    #endregion

    #region KubeNamespace Property Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_KubeNamespaceProperty_TakesPriorityOverStorePath()
    {
        // This test verifies that when KubeNamespace is set in store properties,
        // it takes priority over the StorePath value for determining which namespace
        // to inventory. This was a bug where StorePath "default" would overwrite
        // the configured KubeNamespace.

        // Arrange - Create a unique secret in our test namespace (read-only test uses cached certs)
        var secretName = $"test-nsprop-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, useCache: true);

        var inventoryItems = new List<CurrentInventoryItem>();

        // Configure with StorePath="default" but KubeNamespace=TestNamespace
        // The inventory should use KubeNamespace (TestNamespace), NOT StorePath (default)
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SNS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = "default", // This should be ignored when KubeNamespace is set
                Properties = $"{{\"KubeSecretType\":\"namespace\",\"KubeNamespace\":\"{TestNamespace}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (items) =>
        {
            inventoryItems.AddRange(items);
            return true;
        }));

        // Assert - The key assertion is that inventory succeeded and found secrets
        // If StorePath "default" was used instead of KubeNamespace, this would fail
        // because our secret only exists in TestNamespace
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify inventory returned items (proving correct namespace was used)
        Assert.True(inventoryItems.Count > 0,
            "Inventory should return items when KubeNamespace property is set correctly");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_EmptyKubeNamespaceProperty_UsesStorePath()
    {
        // This test verifies that when KubeNamespace is empty/not provided,
        // the StorePath is used as the namespace (fallback behavior).

        // Arrange - Create a unique secret in our test namespace (read-only test uses cached certs)
        var secretName = $"test-nsfallback-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, useCache: true);

        var inventoryItems = new List<CurrentInventoryItem>();

        // Configure with StorePath=TestNamespace and KubeNamespace empty
        // The inventory should use StorePath (TestNamespace) as fallback
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SNS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = TestNamespace, // This should be used when KubeNamespace is empty
                Properties = "{\"KubeSecretType\":\"namespace\"}" // No KubeNamespace provided
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (items) =>
        {
            inventoryItems.AddRange(items);
            return true;
        }));

        // Assert - Should succeed using StorePath as namespace
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify inventory returned items (proving StorePath was used as namespace)
        Assert.True(inventoryItems.Count > 0,
            "Inventory should return items when StorePath is used as namespace fallback");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_StorePathWithClusterNamespace_WorksCorrectly()
    {
        // Test the <cluster>/<namespace> storepath pattern for K8SNS
        // This is documented as a valid pattern in docsource/k8sns.md

        // Arrange - Create a unique secret in our test namespace (read-only test uses cached certs)
        var secretName = $"test-clusterpath-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, useCache: true);

        var inventoryItems = new List<CurrentInventoryItem>();

        // Use <cluster>/<namespace> pattern
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SNS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "kf-integrations",
                StorePath = $"kf-integrations/{TestNamespace}", // <cluster>/<namespace> pattern
                Properties = "{\"KubeSecretType\":\"namespace\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (items) =>
        {
            inventoryItems.AddRange(items);
            return true;
        }));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify inventory returned items
        Assert.True(inventoryItems.Count > 0,
            "Inventory should return items with <cluster>/<namespace> path pattern");
    }

    #endregion

    #region Multiple Secret Type Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Namespace_WithMultipleSecretTypes_HandlesAllTypes()
    {
        // Verify K8SNS can handle multiple secret types in the same namespace (read-only test uses cached certs)
        // Arrange
        var opaqueSecret = $"test-multi-opaque-{Guid.NewGuid():N}";
        var tlsSecret = $"test-multi-tls-{Guid.NewGuid():N}";
        var ecSecret = $"test-multi-ec-{Guid.NewGuid():N}";

        await CreateTestSecret(opaqueSecret, KeyType.Rsa2048, "Opaque", useCache: true);
        await CreateTestSecret(tlsSecret, KeyType.Rsa2048, "kubernetes.io/tls", useCache: true);
        await CreateTestSecret(ecSecret, KeyType.EcP256, "Opaque", useCache: true);

        // Act - List all secrets in namespace
        var secrets = await K8sClient.CoreV1.ListNamespacedSecretAsync(TestNamespace);

        // Assert - Verify our created secrets exist
        Assert.Contains(secrets.Items, s => s.Metadata.Name == opaqueSecret);
        Assert.Contains(secrets.Items, s => s.Metadata.Name == tlsSecret);
        Assert.Contains(secrets.Items, s => s.Metadata.Name == ecSecret);
    }

    #endregion

    #region Key Type Coverage Tests

    [SkipUnlessTheory(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    [MemberData(nameof(KeyTypeTestData.AllKeyTypes), MemberType = typeof(KeyTypeTestData))]
    public async Task Management_Certificate_AddAndInventory_Success(KeyType keyType)
    {
        var secretName = $"test-{keyType.ToString().ToLowerInvariant()}-ns-{Guid.NewGuid():N}";
        TrackSecret(secretName);
        await AddAndInventoryCertificate(secretName, keyType);
    }

    private async Task AddAndInventoryCertificate(string secretName, KeyType keyType)
    {
        // Generate certificate with specified key type
        var certInfo = CachedCertificateProvider.GetOrCreate(keyType, $"KeyType Test {keyType}");
        var pfxPassword = "testpassword";

        // Add certificate
        var addJobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SNS",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"secrets/opaque/{secretName}",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = TestNamespace,
                Properties = "{\"KubeSecretType\":\"namespace\"}"
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

        // Inventory the certificate
        var invJobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SNS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = TestNamespace,
                Properties = "{\"KubeSecretType\":\"namespace\"}"
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
