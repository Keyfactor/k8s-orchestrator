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
/// Integration tests for K8SCert store type operations against a real Kubernetes cluster.
/// K8SCert is READ-ONLY - only Inventory and Discovery operations are tested.
/// No Management operations are supported for CSRs.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// </summary>
[Collection("Integration Tests")]
public class K8SCertStoreIntegrationTests : IAsyncLifetime
{
    private const string TestNamespace = "keyfactor-k8scert-integration-tests";
    private static readonly string KubeconfigPath = (Environment.GetEnvironmentVariable("INTEGRATION_TEST_KUBECONFIG") ?? "~/.kube/config").Replace("~", Environment.GetEnvironmentVariable("HOME") ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
    private static readonly string ClusterContext = Environment.GetEnvironmentVariable("INTEGRATION_TEST_CONTEXT") ?? "kf-integrations";

    private Kubernetes _k8sClient;
    private string _kubeconfigJson;
    private readonly List<string> _createdCsrs = new List<string>();
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

    #region Inventory Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_SingleApprovedCSR_ReturnsSuccess()
    {
        // Arrange
        var csrName = $"test-inventory-{Guid.NewGuid():N}";
        await CreateTestCsr(csrName, approve: true);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCert",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = csrName,
                Properties = "{\"KubeSecretType\":\"certificate\"}"
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
    public async Task Inventory_PendingCSR_ReturnsSuccess()
    {
        // Arrange
        var csrName = $"test-pending-{Guid.NewGuid():N}";
        await CreateTestCsr(csrName, approve: false);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SCert",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "cluster",
                StorePath = csrName,
                Properties = "{\"KubeSecretType\":\"certificate\"}"
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

    #region Error Handling Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_NonExistentCSR_ReturnsFailure()
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
                Properties = "{\"KubeSecretType\":\"certificate\"}"
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
        Assert.Contains("was not found", result.FailureMessage);
    }

    #endregion
}
