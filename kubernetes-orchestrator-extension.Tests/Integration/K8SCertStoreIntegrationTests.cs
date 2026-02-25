// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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
/// Integration tests for K8SCert store type operations against a real Kubernetes cluster.
/// K8SCert is READ-ONLY - only Inventory and Discovery operations are tested.
///
/// K8SCert supports two inventory modes:
/// - Single CSR mode: When KubeSecretName is set, inventories that specific CSR
/// - Cluster-wide mode: When KubeSecretName is empty or "*", inventories ALL issued CSRs
///
/// No Management operations are supported for CSRs.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// </summary>
[Collection("K8SCert Integration Tests")]
public class K8SCertStoreIntegrationTests : IAsyncLifetime
{
    private const string TestNamespace = "keyfactor-k8scert-integration-tests";

    private readonly IntegrationTestFixture _fixture;
    private Kubernetes _k8sClient = null!;
    private string _kubeconfigJson = string.Empty;
    private readonly List<string> _createdCsrs = new();
    private Mock<IPAMSecretResolver> _mockPamResolver = null!;

    public K8SCertStoreIntegrationTests(IntegrationTestFixture fixture)
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

        await CreateNamespaceIfNotExists();
    }

    public async Task DisposeAsync()
    {
        if (!_fixture.IsEnabled)
        {
            return;
        }

        if (!_fixture.SkipCleanup)
        {
            foreach (var csrName in _createdCsrs)
            {
                try
                {
                    await _k8sClient.CertificatesV1.DeleteCertificateSigningRequestAsync(csrName);
                }
                catch (Exception)
                {
                    // Ignore cleanup errors
                }
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
        catch (k8s.Autorest.HttpOperationException ex) when (ex.Response.StatusCode == HttpStatusCode.NotFound)
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

    private async Task<V1CertificateSigningRequest> CreateTestCsr(string name, bool approve = false)
    {
        // Generate a proper PKCS#10 Certificate Signing Request
        var csrPem = CertificateTestHelper.GenerateCertificateRequest(KeyType.Rsa2048, $"CSR {name}");

        // Create CSR object for Kubernetes
        var csr = new V1CertificateSigningRequest
        {
            Metadata = new V1ObjectMeta
            {
                Name = name
            },
            Spec = new V1CertificateSigningRequestSpec
            {
                Request = System.Text.Encoding.UTF8.GetBytes(csrPem),
                SignerName = "kubernetes.io/kube-apiserver-client",
                Usages = new List<string> { "client auth" }
            }
        };

        var created = await _k8sClient.CertificatesV1.CreateCertificateSigningRequestAsync(csr);
        _createdCsrs.Add(name);

        if (approve)
        {
            // Approve the CSR
            created.Status = new V1CertificateSigningRequestStatus
            {
                Conditions = new List<V1CertificateSigningRequestCondition>
                {
                    new V1CertificateSigningRequestCondition
                    {
                        Type = "Approved",
                        Status = "True",
                        Reason = "TestApproval",
                        Message = "Approved by integration test",
                        LastUpdateTime = DateTime.UtcNow
                    }
                }
            };
            created = await _k8sClient.CertificatesV1.ReplaceCertificateSigningRequestApprovalAsync(created, name);
        }

        return created;
    }

    #region Single CSR Mode Tests (Legacy Behavior)

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_SingleMode_ApprovedCSR_ReturnsSuccess()
    {
        // Arrange
        var csrName = $"test-single-approved-{Guid.NewGuid():N}";
        await CreateTestCsr(csrName, approve: true);
        await Task.Delay(2000); // Wait for certificate to be issued

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCert",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = csrName,
                Properties = $"{{\"KubeSecretName\":\"{csrName}\"}}"
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
    public async Task Inventory_SingleMode_PendingCSR_ReturnsSuccessWithEmptyInventory()
    {
        // Arrange - CSR not approved, so no certificate issued
        var csrName = $"test-single-pending-{Guid.NewGuid():N}";
        await CreateTestCsr(csrName, approve: false);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCert",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = csrName,
                Properties = $"{{\"KubeSecretName\":\"{csrName}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert - Should succeed but with empty inventory (CSR has no certificate)
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_SingleMode_NonExistentCSR_ReturnsSuccessWithMessage()
    {
        // Arrange
        var nonExistentCsr = $"does-not-exist-{Guid.NewGuid():N}";

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCert",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = nonExistentCsr,
                Properties = $"{{\"KubeSecretName\":\"{nonExistentCsr}\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert - Returns success with message about CSR not found
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
        Assert.NotNull(result.FailureMessage);
        Assert.Contains("not found", result.FailureMessage);
    }

    #endregion

    #region Cluster-Wide Mode Tests (New Behavior)

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_ClusterWideMode_EmptyName_ReturnsAllIssuedCSRs()
    {
        // Arrange - Create multiple CSRs
        var approvedCsr1 = $"test-cw-approved-1-{Guid.NewGuid():N}";
        var approvedCsr2 = $"test-cw-approved-2-{Guid.NewGuid():N}";
        var pendingCsr = $"test-cw-pending-{Guid.NewGuid():N}";

        await CreateTestCsr(approvedCsr1, approve: true);
        await CreateTestCsr(approvedCsr2, approve: true);
        await CreateTestCsr(pendingCsr, approve: false);
        await Task.Delay(2000); // Wait for certificates to be issued

        var inventoryItems = new List<CurrentInventoryItem>();
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCert",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{\"KubeSecretName\":\"\"}" // Empty = cluster-wide mode
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

        // Should find at least our 2 approved CSRs
        Assert.True(inventoryItems.Count >= 2,
            $"Expected at least 2 inventory items but got {inventoryItems.Count}");

        var aliases = inventoryItems.Select(i => i.Alias).ToList();
        Assert.Contains(approvedCsr1, aliases);
        Assert.Contains(approvedCsr2, aliases);
        Assert.DoesNotContain(pendingCsr, aliases); // Pending CSR should not be included
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_ClusterWideMode_Wildcard_ReturnsAllIssuedCSRs()
    {
        // Arrange
        var approvedCsr = $"test-wc-approved-{Guid.NewGuid():N}";
        await CreateTestCsr(approvedCsr, approve: true);
        await Task.Delay(2000);

        var inventoryItems = new List<CurrentInventoryItem>();
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCert",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{\"KubeSecretName\":\"*\"}" // Wildcard = cluster-wide mode
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

        var aliases = inventoryItems.Select(i => i.Alias).ToList();
        Assert.Contains(approvedCsr, aliases);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_ClusterWideMode_CSRsHaveNoPrivateKey()
    {
        // Arrange
        var csrName = $"test-no-pk-cw-{Guid.NewGuid():N}";
        await CreateTestCsr(csrName, approve: true);
        await Task.Delay(2000);

        var inventoryItems = new List<CurrentInventoryItem>();
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCert",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = "cluster",
                Properties = "{}"
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

        // All CSR inventory items should have PrivateKeyEntry = false
        foreach (var item in inventoryItems)
        {
            Assert.False(item.PrivateKeyEntry, $"CSR {item.Alias} should not have private key");
        }
    }

    #endregion

    #region Discovery Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Discovery_FindsMultipleCSRs_ReturnsSuccess()
    {
        // Arrange - Create multiple CSRs
        var csr1Name = $"test-discover-1-{Guid.NewGuid():N}";
        var csr2Name = $"test-discover-2-{Guid.NewGuid():N}";
        await CreateTestCsr(csr1Name, approve: true);
        await CreateTestCsr(csr2Name, approve: false);

        var jobConfig = new DiscoveryJobConfiguration
        {
            Capability = "K8SCert",
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
}
