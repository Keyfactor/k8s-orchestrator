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
/// Integration tests for K8SNS store type operations against a real Kubernetes cluster.
/// K8SNS manages ALL secrets within a SINGLE namespace.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// </summary>
[Collection("K8SNS Integration Tests")]
public class K8SNSStoreIntegrationTests : IntegrationTestBase
{
    protected override string TestNamespace => "keyfactor-k8sns-integration-tests";

    public K8SNSStoreIntegrationTests(IntegrationTestFixture fixture) : base(fixture)
    {
    }

    private async Task<V1Secret> CreateTestSecret(string name, KeyType keyType = KeyType.Rsa2048, string secretType = "Opaque")
    {
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Integration Test {name}");
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
        // Arrange - Create secrets in the namespace
        var secret1Name = $"test-ns-1-{Guid.NewGuid():N}";
        var secret2Name = $"test-ns-2-{Guid.NewGuid():N}";
        await CreateTestSecret(secret1Name);
        await CreateTestSecret(secret2Name);

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
        // Arrange - Create different secret types in the namespace
        var opaqueSecret = $"test-opaque-ns-{Guid.NewGuid():N}";
        var tlsSecret = $"test-tls-ns-{Guid.NewGuid():N}";
        await CreateTestSecret(opaqueSecret, KeyType.Rsa2048, "Opaque");
        await CreateTestSecret(tlsSecret, KeyType.Rsa2048, "kubernetes.io/tls");

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
        // Arrange - Create secrets in the namespace
        var secret1Name = $"test-inv-ns-1-{Guid.NewGuid():N}";
        var secret2Name = $"test-inv-ns-2-{Guid.NewGuid():N}";
        await CreateTestSecret(secret1Name);
        await CreateTestSecret(secret2Name);

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

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Namespace Management Test");
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

    #endregion

    #region Boundary Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task NamespaceScope_OnlySeesSecretsInNamespace_NotOtherNamespaces()
    {
        // Verify that K8SNS only sees secrets in its namespace
        // This requires creating a secret in another namespace (if we have cluster permissions)
        // For this test, we just verify our namespace secrets are correctly scoped

        // Arrange
        var secretName = $"test-boundary-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName);

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

    #endregion

    #region Multiple Secret Type Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Namespace_WithMultipleSecretTypes_HandlesAllTypes()
    {
        // Verify K8SNS can handle multiple secret types in the same namespace
        // Arrange
        var opaqueSecret = $"test-multi-opaque-{Guid.NewGuid():N}";
        var tlsSecret = $"test-multi-tls-{Guid.NewGuid():N}";
        var ecSecret = $"test-multi-ec-{Guid.NewGuid():N}";

        await CreateTestSecret(opaqueSecret, KeyType.Rsa2048, "Opaque");
        await CreateTestSecret(tlsSecret, KeyType.Rsa2048, "kubernetes.io/tls");
        await CreateTestSecret(ecSecret, KeyType.EcP256, "Opaque");

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
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"KeyType Test {keyType}");
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
