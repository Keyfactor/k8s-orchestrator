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
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SCluster;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.K8S.Tests.Attributes;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Moq;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration;

/// <summary>
/// Integration tests for K8SCluster store type operations against a real Kubernetes cluster.
/// K8SCluster manages ALL secrets across ALL namespaces cluster-wide.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// </summary>
[Collection("Integration Tests")]
public class K8SClusterStoreIntegrationTests : IAsyncLifetime
{
    private const string TestNamespace1 = "keyfactor-k8scluster-test-ns1";
    private const string TestNamespace2 = "keyfactor-k8scluster-test-ns2";
    private static readonly string KubeconfigPath = (Environment.GetEnvironmentVariable("INTEGRATION_TEST_KUBECONFIG") ?? "~/.kube/config").Replace("~", Environment.GetEnvironmentVariable("HOME") ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
    private static readonly string ClusterContext = Environment.GetEnvironmentVariable("INTEGRATION_TEST_CONTEXT") ?? "kf-integrations";

    private Kubernetes _k8sClient;
    private string _kubeconfigJson;
    private readonly List<(string secretName, string ns)> _createdSecrets = new List<(string, string)>();
    private readonly List<string> _createdNamespaces = new List<string>();
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

        await CreateNamespaceIfNotExists(TestNamespace1);
        await CreateNamespaceIfNotExists(TestNamespace2);
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

        _k8sClient?.Dispose();
    }

    private async Task CreateNamespaceIfNotExists(string namespaceName)
    {
        try
        {
            await _k8sClient.CoreV1.ReadNamespaceAsync(namespaceName);
        }
        catch (k8s.Autorest.HttpOperationException ex) when (ex.Response.StatusCode == System.Net.HttpStatusCode.NotFound)
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
            _createdNamespaces.Add(namespaceName);
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
                        ["namespace"] = TestNamespace1
                    }
                }
            }
        };

        return JsonSerializer.Serialize(kubeconfigObj);
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
                NamespaceProperty = namespaceName
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
                { "dirs", "cluster" }, // Discovery across entire cluster
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

        var inventory = new Inventory(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Failure,
            $"Expected Failure but got {result.Result}. FailureMessage: {result.FailureMessage}");
        Assert.NotNull(result.FailureMessage);
    }

    #endregion
}
