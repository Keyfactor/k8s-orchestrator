// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using k8s;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.Orchestrators.K8S.Tests.Attributes;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Keyfactor.Orchestrators.K8S.Tests.Integration.Fixtures;
using Moq;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration;

/// <summary>
/// Integration tests for K8SCluster store type operations against a real Kubernetes cluster.
/// K8SCluster manages ALL secrets across ALL namespaces cluster-wide.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// Note: This test class uses two namespaces for cross-namespace testing.
/// </summary>
[Collection("K8SCluster Integration Tests")]
public class K8SClusterStoreIntegrationTests : IAsyncLifetime
{
    private const string TestNamespace1 = "keyfactor-k8scluster-test-ns1";
    private const string TestNamespace2 = "keyfactor-k8scluster-test-ns2";

    private readonly IntegrationTestFixture _fixture;
    private Kubernetes _k8sClient = null!;
    private string _kubeconfigJson = string.Empty;
    private readonly List<(string secretName, string ns)> _createdSecrets = new();
    private Mock<IPAMSecretResolver> _mockPamResolver = null!;

    public K8SClusterStoreIntegrationTests(IntegrationTestFixture fixture)
    {
        _fixture = fixture;
    }

    public async Task InitializeAsync()
    {
        if (!_fixture.IsEnabled)
        {
            return;
        }

        _kubeconfigJson = _fixture.KubeconfigJson;
        _k8sClient = _fixture.CreateK8sClient();
        _mockPamResolver = _fixture.CreateMockPamResolver();

        await CreateNamespaceIfNotExists(TestNamespace1);
        await CreateNamespaceIfNotExists(TestNamespace2);
    }

    public async Task DisposeAsync()
    {
        if (!_fixture.IsEnabled)
        {
            return;
        }

        if (!_fixture.SkipCleanup)
        {
            foreach (var (secretName, ns) in _createdSecrets)
            {
                try
                {
                    await _k8sClient.CoreV1.DeleteNamespacedSecretAsync(secretName, ns);
                }
                catch (Exception)
                {
                    // Ignore cleanup errors
                }
            }
        }

        _k8sClient?.Dispose();
    }

    private async Task CreateNamespaceIfNotExists(string namespaceName)
    {
        try
        {
            await _k8sClient.CoreV1.ReadNamespaceAsync(namespaceName);
        }
        catch (k8s.Autorest.HttpOperationException ex) when (ex.Response.StatusCode == HttpStatusCode.NotFound)
        {
            var ns = new V1Namespace
            {
                Metadata = new V1ObjectMeta
                {
                    Name = namespaceName,
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

    /// <summary>
    /// Standard label used to identify secrets created by integration tests.
    /// </summary>
    private const string TestManagedByLabel = "keyfactor-integration-tests";
    private const string ManagedByLabelKey = "app.kubernetes.io/managed-by";
    private const string TestRunIdLabelKey = "keyfactor.com/test-run-id";
    private readonly string _testRunId = Guid.NewGuid().ToString("N")[..8];

    private Dictionary<string, string> GetTestSecretLabels()
    {
        return new Dictionary<string, string>
        {
            { ManagedByLabelKey, TestManagedByLabel },
            { TestRunIdLabelKey, _testRunId }
        };
    }

    private async Task<V1Secret> CreateTestSecret(string name, string namespaceName, KeyType keyType = KeyType.Rsa2048, string secretType = "Opaque")
    {
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Integration Test {name}");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = name,
                NamespaceProperty = namespaceName,
                Labels = GetTestSecretLabels()
            },
            Type = secretType,
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        var created = await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, namespaceName);
        _createdSecrets.Add((name, namespaceName));
        return created;
    }

    private async Task<V1Secret> CreateTestSecretWithChain(string name, string namespaceName, KeyType keyType = KeyType.Rsa2048, string secretType = "Opaque", bool separateChain = true)
    {
        var chain = CertificateTestHelper.GenerateCertificateChain(keyType);
        var leafCertPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        var data = new Dictionary<string, byte[]>
        {
            { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
        };

        if (separateChain)
        {
            data["tls.crt"] = Encoding.UTF8.GetBytes(leafCertPem);
            data["ca.crt"] = Encoding.UTF8.GetBytes(intermediatePem + rootPem);
        }
        else
        {
            data["tls.crt"] = Encoding.UTF8.GetBytes(leafCertPem + intermediatePem + rootPem);
        }

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = name,
                NamespaceProperty = namespaceName,
                Labels = GetTestSecretLabels()
            },
            Type = secretType,
            Data = data
        };

        var created = await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, namespaceName);
        _createdSecrets.Add((name, namespaceName));
        return created;
    }

    private async Task<V1Secret> CreateTestSecretCertOnly(string name, string namespaceName, KeyType keyType = KeyType.Rsa2048)
    {
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Integration Test {name}");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = name,
                NamespaceProperty = namespaceName,
                Labels = GetTestSecretLabels()
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
            }
        };

        var created = await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, namespaceName);
        _createdSecrets.Add((name, namespaceName));
        return created;
    }

    /// <summary>
    /// Runs a cluster-wide inventory job with retry logic to handle race conditions
    /// from parallel test execution. Cluster-wide scans may encounter secrets from
    /// other tests being created/deleted, causing transient NotFound errors.
    /// </summary>
    private async Task<JobResult> RunClusterInventoryWithRetry(InventoryJobConfiguration jobConfig, int maxRetries = 3)
    {
        var inventory = new Inventory(_mockPamResolver.Object);
        JobResult? result = null;

        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

            // Success - return immediately
            if (result.Result == OrchestratorJobStatusJobResult.Success)
            {
                return result;
            }

            // Check if it's a transient NotFound error from parallel test interference
            if (result.FailureMessage != null &&
                result.FailureMessage.Contains("NotFound") &&
                attempt < maxRetries)
            {
                // Wait briefly before retry to let parallel tests settle
                await Task.Delay(500 * attempt);
                continue;
            }

            // Non-transient error or max retries reached
            break;
        }

        return result!;
    }

    #region Discovery Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Discovery_MultipleNamespaces_FindsAllSecrets()
    {
        // Arrange - Create secrets in multiple namespaces
        var secret1Name = $"test-cluster-ns1-{Guid.NewGuid():N}";
        var secret2Name = $"test-cluster-ns2-{Guid.NewGuid():N}";
        await CreateTestSecret(secret1Name, TestNamespace1);
        await CreateTestSecret(secret2Name, TestNamespace2);

        var jobConfig = new DiscoveryJobConfiguration
        {
            Capability = "K8SCluster",
            ClientMachine = "cluster",
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true,
            JobProperties = new Dictionary<string, object>
            {
                { "dirs", "cluster" },
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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Discovery_MixedSecretTypes_FindsAllTypes()
    {
        // Arrange - Create different secret types in different namespaces
        var opaqueSecret = $"test-opaque-{Guid.NewGuid():N}";
        var tlsSecret = $"test-tls-{Guid.NewGuid():N}";
        await CreateTestSecret(opaqueSecret, TestNamespace1, KeyType.Rsa2048, "Opaque");
        await CreateTestSecret(tlsSecret, TestNamespace2, KeyType.Rsa2048, "kubernetes.io/tls");

        var jobConfig = new DiscoveryJobConfiguration
        {
            Capability = "K8SCluster",
            ClientMachine = "cluster",
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true,
            JobProperties = new Dictionary<string, object>
            {
                { "dirs", "cluster" },
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

    #region Inventory Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_ClusterWide_ReturnsAllCertificates()
    {
        // Arrange - Create secrets across multiple namespaces
        var secret1Name = $"test-inv-cluster-1-{Guid.NewGuid():N}";
        var secret2Name = $"test-inv-cluster-2-{Guid.NewGuid():N}";
        await CreateTestSecret(secret1Name, TestNamespace1);
        await CreateTestSecret(secret2Name, TestNamespace2);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCluster",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        // Act - Use retry logic to handle race conditions from parallel test execution
        var result = await RunClusterInventoryWithRetry(jobConfig);

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_ClusterWide_ReturnsCorrectPrivateKeyStatus()
    {
        // Arrange - Create one secret with private key and one without
        var secretWithKey = $"test-cluster-withkey-{Guid.NewGuid():N}";
        var secretWithoutKey = $"test-cluster-nokey-{Guid.NewGuid():N}";

        // Create secret WITH private key
        await CreateTestSecret(secretWithKey, TestNamespace1);

        // Create secret WITHOUT private key (cert only)
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Cluster No Key Test");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var secretNoKey = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = secretWithoutKey,
                NamespaceProperty = TestNamespace2,
                Labels = GetTestSecretLabels()
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
                // No tls.key field
            }
        };
        await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secretNoKey, TestNamespace2);
        _createdSecrets.Add((secretWithoutKey, TestNamespace2));

        var inventoryItems = new List<CurrentInventoryItem>();
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCluster",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(_mockPamResolver.Object);

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
    public async Task Inventory_ClusterWide_ReturnsFullCertificateChains()
    {
        // Arrange - Create a secret with a certificate chain
        var secretName = $"test-cluster-chain-{Guid.NewGuid():N}";

        // Create secret with certificate chain (leaf + intermediate + root)
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
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
                NamespaceProperty = TestNamespace1,
                Labels = GetTestSecretLabels()
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(bundledCertPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };
        await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace1);
        _createdSecrets.Add((secretName, TestNamespace1));

        var inventoryItems = new List<CurrentInventoryItem>();
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCluster",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(_mockPamResolver.Object);

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

    #region Management Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateToSpecificNamespace_ReturnsSuccess()
    {
        // K8SCluster management should be able to target specific namespace
        // Arrange
        var secretName = $"test-mgmt-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Cluster Management Test");
        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/opaque/{secretName}",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace1,
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
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

        // Verify secret was created in the correct namespace
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        Assert.NotNull(secret);
        Assert.Equal(TestNamespace1, secret.Metadata.NamespaceProperty);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_RemoveCertificateFromNamespace_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-remove-cluster-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, TestNamespace1);

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Remove,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/opaque/{secretName}"
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace1,
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
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

    #endregion

    #region Cross-Namespace Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task CrossNamespace_SecretsInDifferentNamespaces_AreIndependent()
    {
        // Verify that secrets with the same name in different namespaces are independent
        // Arrange
        var secretName = $"test-same-name-{Guid.NewGuid():N}";
        var secret1 = await CreateTestSecret(secretName, TestNamespace1, KeyType.Rsa2048);
        var secret2 = await CreateTestSecret(secretName, TestNamespace2, KeyType.EcP256);

        // Assert - Same name, different namespaces
        Assert.Equal(secretName, secret1.Metadata.Name);
        Assert.Equal(secretName, secret2.Metadata.Name);
        Assert.NotEqual(secret1.Metadata.NamespaceProperty, secret2.Metadata.NamespaceProperty);

        // Verify both can be read independently
        var readSecret1 = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        var readSecret2 = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace2);

        Assert.NotNull(readSecret1);
        Assert.NotNull(readSecret2);
        Assert.Equal(TestNamespace1, readSecret1.Metadata.NamespaceProperty);
        Assert.Equal(TestNamespace2, readSecret2.Metadata.NamespaceProperty);
    }

    #endregion

    #region Error Handling Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_InvalidClusterCredentials_ReturnsFailure()
    {
        // Arrange - Create invalid kubeconfig
        var invalidKubeconfig = "{\"invalid\": \"json\"}";

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCluster",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = invalidKubeconfig,
            UseSSL = true
        };

        // Act - Use retry logic to handle race conditions from parallel test execution
        var result = await RunClusterInventoryWithRetry(jobConfig);

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Failure,
            $"Expected Failure but got {result.Result}. FailureMessage: {result.FailureMessage}");
        Assert.NotNull(result.FailureMessage);
    }

    #endregion

    #region TLS Secret Operations via Cluster

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_TlsSecretInCluster_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-tls-cluster-inv-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, TestNamespace1, KeyType.Rsa2048, "kubernetes.io/tls");

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCluster",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        // Act - Use retry logic to handle race conditions from parallel test execution
        var result = await RunClusterInventoryWithRetry(jobConfig);

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddTlsSecretToCluster_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-add-tls-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Cluster TLS Add Test");
        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/tls/{secretName}",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace1,
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
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

        // Verify secret was created with TLS type
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);
    }

    #endregion

    #region Opaque Secret Operations via Cluster

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_OpaqueSecretInCluster_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-opaque-cluster-inv-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, TestNamespace1, KeyType.Rsa2048, "Opaque");

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCluster",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        // Act - Use retry logic to handle race conditions from parallel test execution
        var result = await RunClusterInventoryWithRetry(jobConfig);

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_OpaqueSecretWithChain_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-opaque-chain-cluster-{Guid.NewGuid():N}";
        await CreateTestSecretWithChain(secretName, TestNamespace1, KeyType.Rsa2048, "Opaque", separateChain: true);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCluster",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        // Act - Use retry logic to handle race conditions from parallel test execution
        var result = await RunClusterInventoryWithRetry(jobConfig);

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_OpaqueSecretCertOnly_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-opaque-certonly-{Guid.NewGuid():N}";
        await CreateTestSecretCertOnly(secretName, TestNamespace1);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCluster",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        // Act - Use retry logic to handle race conditions from parallel test execution
        var result = await RunClusterInventoryWithRetry(jobConfig);

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddOpaqueSecretToCluster_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-add-opaque-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Cluster Opaque Add Test");
        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/opaque/{secretName}",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace1,
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
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

        // Verify secret was created with Opaque type
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        Assert.NotNull(secret);
        Assert.Equal("Opaque", secret.Type);
    }

    #endregion

    #region Key Type Coverage via Cluster

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddRsaCertificateViaCluster_AllKeySizes()
    {
        // Test RSA 2048 via cluster
        var secretName = $"test-rsa2048-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "RSA 2048 Test");
        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/tls/{secretName}",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace1,
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
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
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddEcCertificateViaCluster_AllCurves()
    {
        // Test EC P-256 via cluster
        var secretName = $"test-ecp256-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "EC P-256 Test");
        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/tls/{secretName}",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace1,
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
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
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddEd25519CertificateViaCluster_Success()
    {
        // Test Ed25519 via cluster
        var secretName = $"test-ed25519-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Ed25519, "Ed25519 Test");
        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/tls/{secretName}",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace1,
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
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
    }

    #endregion

    #region TLS Chain Tests via K8SCluster

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddTlsSecretWithChainBundled_CreatesCorrectFields()
    {
        // Arrange - Test that when SeparateChain=false, the chain is bundled into tls.crt
        var secretName = $"test-tls-bundled-chain-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

        // Generate a certificate chain (root -> intermediate -> leaf)
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKey = chain[0].KeyPair.Private;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/tls/{secretName}",
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
                ClientMachine = TestNamespace1,
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\",\"IncludeCertChain\":true,\"SeparateChain\":false}"
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

        // Verify secret was created with bundled chain in tls.crt
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);

        // Verify required fields exist
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Secret should contain tls.crt");
        Assert.True(secret.Data.ContainsKey("tls.key"), "Secret should contain tls.key");

        // Should NOT have ca.crt (chain is bundled into tls.crt)
        Assert.False(secret.Data.ContainsKey("ca.crt"), "Secret should NOT contain ca.crt when SeparateChain=false");

        // Verify tls.crt contains the full chain (leaf + intermediate + root)
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(certCount >= 3, $"Expected leaf + chain (3+ certs) in tls.crt when SeparateChain=false, but found {certCount} certificate(s)");

        // Verify tls.key contains a private key
        var tlsKeyData = Encoding.UTF8.GetString(secret.Data["tls.key"]);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", tlsKeyData);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddTlsSecretWithChainSeparate_CreatesCorrectFields()
    {
        // Arrange - Test that when SeparateChain=true (default), the chain goes to ca.crt
        var secretName = $"test-tls-separate-chain-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

        // Generate a certificate chain (root -> intermediate -> leaf)
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKey = chain[0].KeyPair.Private;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/tls/{secretName}",
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
                ClientMachine = TestNamespace1,
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\",\"IncludeCertChain\":true,\"SeparateChain\":true}"
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

        // Verify secret was created with separate ca.crt
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        Assert.NotNull(secret);
        Assert.Equal("kubernetes.io/tls", secret.Type);

        // Verify all required fields exist
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

        // Verify tls.key contains a private key
        var tlsKeyData = Encoding.UTF8.GetString(secret.Data["tls.key"]);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", tlsKeyData);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_TlsSecretWithChainBundled_ReturnsSuccess()
    {
        // Arrange - Create TLS secret with chain bundled in tls.crt
        var secretName = $"test-inv-tls-bundled-{Guid.NewGuid():N}";
        await CreateTestSecretWithChain(secretName, TestNamespace1, KeyType.Rsa2048, "kubernetes.io/tls", separateChain: false);

        // Verify the created secret has the chain bundled
        var createdSecret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        Assert.Equal("kubernetes.io/tls", createdSecret.Type);
        Assert.False(createdSecret.Data.ContainsKey("ca.crt"), "Bundled chain should not have ca.crt");

        var tlsCrtData = Encoding.UTF8.GetString(createdSecret.Data["tls.crt"]);
        var certCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(certCount >= 3, $"tls.crt should contain bundled chain, but found {certCount} cert(s)");

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCluster",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        // Act - Use retry logic to handle race conditions from parallel test execution
        var result = await RunClusterInventoryWithRetry(jobConfig);

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_TlsSecretWithChainSeparate_ReturnsSuccess()
    {
        // Arrange - Create TLS secret with chain in separate ca.crt
        var secretName = $"test-inv-tls-separate-{Guid.NewGuid():N}";
        await CreateTestSecretWithChain(secretName, TestNamespace1, KeyType.Rsa2048, "kubernetes.io/tls", separateChain: true);

        // Verify the created secret has the chain separated
        var createdSecret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        Assert.Equal("kubernetes.io/tls", createdSecret.Type);
        Assert.True(createdSecret.Data.ContainsKey("ca.crt"), "Separate chain should have ca.crt");
        Assert.True(createdSecret.Data.ContainsKey("tls.crt"), "Should have tls.crt");
        Assert.True(createdSecret.Data.ContainsKey("tls.key"), "Should have tls.key");

        var tlsCrtData = Encoding.UTF8.GetString(createdSecret.Data["tls.crt"]);
        var tlsCertCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.True(tlsCertCount == 1, $"tls.crt should contain only leaf cert, but found {tlsCertCount}");

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCluster",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{\"KubeSecretType\":\"cluster\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        // Act - Use retry logic to handle race conditions from parallel test execution
        var result = await RunClusterInventoryWithRetry(jobConfig);

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    #endregion
}
