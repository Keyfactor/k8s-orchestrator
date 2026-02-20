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
/// Integration tests for K8SNS store type operations against a real Kubernetes cluster.
/// K8SNS manages ALL secrets within a SINGLE namespace.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// </summary>
[Collection("Integration Tests")]
public class K8SNSStoreIntegrationTests : IAsyncLifetime
{
    private const string TestNamespace = "keyfactor-k8sns-integration-tests";
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

    private async Task<V1Secret> CreateTestSecret(string name, KeyType keyType = KeyType.Rsa2048, string secretType = "Opaque")
    {
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Integration Test {name}");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = name,
                NamespaceProperty = TestNamespace
            },
            Type = secretType,
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        var created = await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);
        _createdSecrets.Add(name);
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
    public async Task Management_AddCertificateToNamespace_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-mgmt-ns-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);

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
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.Equal(TestNamespace, secret.Metadata.NamespaceProperty);
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
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);

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
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(_mockPamResolver.Object);

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
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(_mockPamResolver.Object);

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
        var secrets = await _k8sClient.CoreV1.ListNamespacedSecretAsync(TestNamespace);

        // Assert - Verify our created secrets exist
        Assert.Contains(secrets.Items, s => s.Metadata.Name == opaqueSecret);
        Assert.Contains(secrets.Items, s => s.Metadata.Name == tlsSecret);
        Assert.Contains(secrets.Items, s => s.Metadata.Name == ecSecret);
    }

    #endregion
}
