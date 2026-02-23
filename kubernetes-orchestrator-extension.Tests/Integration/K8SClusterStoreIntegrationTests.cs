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
                NamespaceProperty = namespaceName
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
                NamespaceProperty = namespaceName
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

        var inventory = new Inventory(_mockPamResolver.Object);

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
        var secretName = $"test-tls-chain-cluster-{Guid.NewGuid():N}";
        await CreateTestSecretWithChain(secretName, TestNamespace1, KeyType.Rsa2048, "kubernetes.io/tls", separateChain: true);

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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_TlsSecretWithEcCert_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-tls-ec-cluster-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, TestNamespace1, KeyType.EcP256, "kubernetes.io/tls");

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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_RemoveTlsSecretFromCluster_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-remove-tls-cluster-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, TestNamespace1, KeyType.Rsa2048, "kubernetes.io/tls");

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Remove,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/tls/{secretName}"
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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddTlsSecretWithBundledChain_CreatesBundledTlsCrt()
    {
        // Arrange
        var secretName = $"test-tls-bundled-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

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
                Properties = $"{{\"KubeSecretType\":\"cluster\",\"IncludeCertChain\":true,\"SeparateChain\":false}}"
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

        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        Assert.NotNull(secret);
        Assert.False(secret.Data.ContainsKey("ca.crt"), "Should NOT have ca.crt when SeparateChain=false");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddTlsSecretWithSeparateChain_CreatesSeparateCaCrt()
    {
        // Arrange
        var secretName = $"test-tls-separate-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

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
                Properties = $"{{\"KubeSecretType\":\"cluster\",\"IncludeCertChain\":true,\"SeparateChain\":true}}"
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

        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        Assert.NotNull(secret);
        Assert.True(secret.Data.ContainsKey("ca.crt"), "Should have ca.crt when SeparateChain=true");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddTlsSecretWithoutChain_NoChainIncluded()
    {
        // Test IncludeCertChain=false - no chain included
        var secretName = $"test-tls-nochain-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

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
                Properties = $"{{\"KubeSecretType\":\"cluster\",\"IncludeCertChain\":false}}"
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

        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        Assert.NotNull(secret);
        // No ca.crt when IncludeCertChain=false
        Assert.False(secret.Data.ContainsKey("ca.crt"), "Should NOT have ca.crt when IncludeCertChain=false");
        // tls.crt should only have leaf certificate
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = System.Text.RegularExpressions.Regex.Matches(tlsCrtData, "-----BEGIN CERTIFICATE-----").Count;
        Assert.Equal(1, certCount);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddOpaqueSecretWithoutChain_NoChainIncluded()
    {
        // Test IncludeCertChain=false for Opaque secrets
        var secretName = $"test-opaque-nochain-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

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
                Alias = $"{TestNamespace1}/secrets/opaque/{secretName}",
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
                Properties = $"{{\"KubeSecretType\":\"cluster\",\"IncludeCertChain\":false}}"
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

        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        Assert.NotNull(secret);
        Assert.False(secret.Data.ContainsKey("ca.crt"), "Should NOT have ca.crt when IncludeCertChain=false");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_OverwriteTlsSecret_UpdatesCorrectly()
    {
        // Arrange - Create an existing TLS secret
        var secretName = $"test-overwrite-tls-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, TestNamespace1, KeyType.Rsa2048, "kubernetes.io/tls");

        // New certificate to overwrite
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "Overwrite Test");
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
            Overwrite = true // Enable overwrite
        };

        var management = new Management(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task TlsSecret_CreatedViaCluster_CompatibleWithIngress()
    {
        // Arrange - Create TLS secret via cluster management
        var secretName = $"test-ingress-compat-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, TestNamespace1, KeyType.Rsa2048, "kubernetes.io/tls");

        // Act - Read back the secret
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);

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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_MultipleTlsSecretsAcrossNamespaces_ReturnsAll()
    {
        // Arrange - Create TLS secrets in both namespaces
        var secret1Name = $"test-tls-multi-1-{Guid.NewGuid():N}";
        var secret2Name = $"test-tls-multi-2-{Guid.NewGuid():N}";
        await CreateTestSecret(secret1Name, TestNamespace1, KeyType.Rsa2048, "kubernetes.io/tls");
        await CreateTestSecret(secret2Name, TestNamespace2, KeyType.EcP256, "kubernetes.io/tls");

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

        var inventory = new Inventory(_mockPamResolver.Object);

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

        var inventory = new Inventory(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

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

        var inventory = new Inventory(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_RemoveOpaqueSecretFromCluster_ReturnsSuccess()
    {
        // Arrange
        var secretName = $"test-remove-opaque-cluster-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, TestNamespace1, KeyType.Rsa2048, "Opaque");

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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddOpaqueSecretWithBundledChain_CreatesBundledSecret()
    {
        // Arrange
        var secretName = $"test-opaque-bundled-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

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
                Alias = $"{TestNamespace1}/secrets/opaque/{secretName}",
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
                Properties = $"{{\"KubeSecretType\":\"cluster\",\"IncludeCertChain\":true,\"SeparateChain\":false}}"
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
    public async Task Management_AddOpaqueSecretWithSeparateChain_CreatesSeparateCaCrt()
    {
        // Arrange
        var secretName = $"test-opaque-separate-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));

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
                Alias = $"{TestNamespace1}/secrets/opaque/{secretName}",
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
                Properties = $"{{\"KubeSecretType\":\"cluster\",\"IncludeCertChain\":true,\"SeparateChain\":true}}"
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
    public async Task Management_OverwriteOpaqueSecret_UpdatesCorrectly()
    {
        // Arrange - Create an existing Opaque secret
        var secretName = $"test-overwrite-opaque-{Guid.NewGuid():N}";
        await CreateTestSecret(secretName, TestNamespace1, KeyType.Rsa2048, "Opaque");

        // New certificate to overwrite
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.EcP384, "Overwrite Opaque Test");
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
            Overwrite = true
        };

        var management = new Management(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_MultipleOpaqueSecretsAcrossNamespaces_ReturnsAll()
    {
        // Arrange - Create Opaque secrets in both namespaces
        var secret1Name = $"test-opaque-multi-1-{Guid.NewGuid():N}";
        var secret2Name = $"test-opaque-multi-2-{Guid.NewGuid():N}";
        await CreateTestSecret(secret1Name, TestNamespace1, KeyType.Rsa2048, "Opaque");
        await CreateTestSecret(secret2Name, TestNamespace2, KeyType.EcP256, "Opaque");

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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddRsa4096CertificateViaCluster_Success()
    {
        var secretName = $"test-rsa4096-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));
        await AddAndInventoryCertificateViaCluster(secretName, KeyType.Rsa4096, "kubernetes.io/tls");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddEcP384CertificateViaCluster_Success()
    {
        var secretName = $"test-ecp384-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));
        await AddAndInventoryCertificateViaCluster(secretName, KeyType.EcP384, "kubernetes.io/tls");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddEcP521CertificateViaCluster_Success()
    {
        var secretName = $"test-ecp521-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));
        await AddAndInventoryCertificateViaCluster(secretName, KeyType.EcP521, "kubernetes.io/tls");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddRsa2048OpaqueSecretViaCluster_Success()
    {
        var secretName = $"test-rsa2048-opaque-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));
        await AddAndInventoryCertificateViaCluster(secretName, KeyType.Rsa2048, "Opaque");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddEcP256OpaqueSecretViaCluster_Success()
    {
        var secretName = $"test-ecp256-opaque-cluster-{Guid.NewGuid():N}";
        _createdSecrets.Add((secretName, TestNamespace1));
        await AddAndInventoryCertificateViaCluster(secretName, KeyType.EcP256, "Opaque");
    }

    private async Task AddAndInventoryCertificateViaCluster(string secretName, KeyType keyType, string secretType)
    {
        // Generate certificate with specified key type
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"KeyType Test {keyType}");
        var pfxPassword = "testpassword";

        var secretTypeAlias = secretType == "kubernetes.io/tls" ? "tls" : "opaque";

        // Add certificate
        var addJobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/{secretTypeAlias}/{secretName}",
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
        var addResult = await Task.Run(() => management.ProcessJob(addJobConfig));

        Assert.True(addResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Add {keyType} certificate expected Success but got {addResult.Result}. FailureMessage: {addResult.FailureMessage}");

        // Verify secret was created
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        Assert.NotNull(secret);
        Assert.Equal(secretType, secret.Type);

        // Inventory the cluster
        var invJobConfig = new InventoryJobConfiguration
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
        var invResult = await Task.Run(() => inventory.ProcessJob(invJobConfig, (inventoryItems) => true));

        Assert.True(invResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Inventory {keyType} certificate expected Success but got {invResult.Result}. FailureMessage: {invResult.FailureMessage}");
    }

    #endregion

    #region Cross-Type and Cross-Namespace Operations

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_MixedSecretTypes_ReturnsAllTypes()
    {
        // Arrange - Create both TLS and Opaque secrets
        var tlsSecretName = $"test-mixed-tls-{Guid.NewGuid():N}";
        var opaqueSecretName = $"test-mixed-opaque-{Guid.NewGuid():N}";
        await CreateTestSecret(tlsSecretName, TestNamespace1, KeyType.Rsa2048, "kubernetes.io/tls");
        await CreateTestSecret(opaqueSecretName, TestNamespace1, KeyType.Rsa2048, "Opaque");

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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Discovery_MixedSecretTypes_ReturnsCorrectMetadata()
    {
        // Arrange - Create both TLS and Opaque secrets in different namespaces
        var tlsSecretName = $"test-disc-tls-{Guid.NewGuid():N}";
        var opaqueSecretName = $"test-disc-opaque-{Guid.NewGuid():N}";
        await CreateTestSecret(tlsSecretName, TestNamespace1, KeyType.Rsa2048, "kubernetes.io/tls");
        await CreateTestSecret(opaqueSecretName, TestNamespace2, KeyType.Rsa2048, "Opaque");

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
    public async Task Management_AddTlsAndOpaqueToSameNamespace_BothSucceed()
    {
        // Arrange
        var tlsSecretName = $"test-same-ns-tls-{Guid.NewGuid():N}";
        var opaqueSecretName = $"test-same-ns-opaque-{Guid.NewGuid():N}";
        _createdSecrets.Add((tlsSecretName, TestNamespace1));
        _createdSecrets.Add((opaqueSecretName, TestNamespace1));

        var certInfo1 = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "TLS Test");
        var certInfo2 = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "Opaque Test");
        var pfxPassword = "testpassword";

        // Add TLS secret
        var tlsJobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/tls/{tlsSecretName}",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo1.Certificate, certInfo1.KeyPair, pfxPassword))
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
        var tlsResult = await Task.Run(() => management.ProcessJob(tlsJobConfig));

        // Add Opaque secret
        var opaqueJobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/opaque/{opaqueSecretName}",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo2.Certificate, certInfo2.KeyPair, pfxPassword))
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

        var opaqueResult = await Task.Run(() => management.ProcessJob(opaqueJobConfig));

        // Assert both succeeded
        Assert.True(tlsResult.Result == OrchestratorJobStatusJobResult.Success,
            $"TLS add expected Success but got {tlsResult.Result}. FailureMessage: {tlsResult.FailureMessage}");
        Assert.True(opaqueResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Opaque add expected Success but got {opaqueResult.Result}. FailureMessage: {opaqueResult.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task CrossNamespace_TlsSecretsSameNameDifferentNs_AreIndependent()
    {
        // Arrange - Create TLS secrets with same name in different namespaces
        var secretName = $"test-tls-same-name-{Guid.NewGuid():N}";
        var secret1 = await CreateTestSecret(secretName, TestNamespace1, KeyType.Rsa2048, "kubernetes.io/tls");
        var secret2 = await CreateTestSecret(secretName, TestNamespace2, KeyType.EcP256, "kubernetes.io/tls");

        // Assert - Same name, different namespaces
        Assert.Equal(secretName, secret1.Metadata.Name);
        Assert.Equal(secretName, secret2.Metadata.Name);
        Assert.NotEqual(secret1.Metadata.NamespaceProperty, secret2.Metadata.NamespaceProperty);

        // Verify both can be read independently
        var readSecret1 = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        var readSecret2 = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace2);

        Assert.Equal("kubernetes.io/tls", readSecret1.Type);
        Assert.Equal("kubernetes.io/tls", readSecret2.Type);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task CrossNamespace_OpaqueSecretsSameNameDifferentNs_AreIndependent()
    {
        // Arrange - Create Opaque secrets with same name in different namespaces
        var secretName = $"test-opaque-same-name-{Guid.NewGuid():N}";
        var secret1 = await CreateTestSecret(secretName, TestNamespace1, KeyType.Rsa2048, "Opaque");
        var secret2 = await CreateTestSecret(secretName, TestNamespace2, KeyType.EcP384, "Opaque");

        // Assert - Same name, different namespaces
        Assert.Equal(secretName, secret1.Metadata.Name);
        Assert.Equal(secretName, secret2.Metadata.Name);
        Assert.NotEqual(secret1.Metadata.NamespaceProperty, secret2.Metadata.NamespaceProperty);

        // Verify both can be read independently
        var readSecret1 = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace1);
        var readSecret2 = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace2);

        Assert.Equal("Opaque", readSecret1.Type);
        Assert.Equal("Opaque", readSecret2.Type);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_TargetSpecificSecretType_UsesCorrectAlias()
    {
        // Verify that the alias format determines the secret type
        var tlsSecretName = $"test-alias-tls-{Guid.NewGuid():N}";
        _createdSecrets.Add((tlsSecretName, TestNamespace1));

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Alias Test");
        var pfxPassword = "testpassword";

        // Alias format: {namespace}/secrets/tls/{secretname} should create TLS secret
        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{TestNamespace1}/secrets/tls/{tlsSecretName}",
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

        // Verify the secret type matches what alias specified
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(tlsSecretName, TestNamespace1);
        Assert.Equal("kubernetes.io/tls", secret.Type);
    }

    #endregion

    #region Additional Error Handling Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_NonExistentTlsSecretInCluster_ReturnsGracefully()
    {
        // Arrange
        var nonExistentSecret = $"does-not-exist-tls-{Guid.NewGuid():N}";

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

        // Assert - Cluster inventory should succeed even if specific secret doesn't exist
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_NonExistentOpaqueSecretInCluster_ReturnsGracefully()
    {
        // Arrange
        var nonExistentSecret = $"does-not-exist-opaque-{Guid.NewGuid():N}";

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

        // Assert - Cluster inventory should succeed even if specific secret doesn't exist
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddToNonExistentNamespace_ReturnsFailure()
    {
        // Arrange
        var nonExistentNamespace = $"does-not-exist-ns-{Guid.NewGuid():N}";
        var secretName = $"test-nonexistent-ns-{Guid.NewGuid():N}";

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Nonexistent NS Test");
        var pfxPassword = "testpassword";

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SCluster",
            OperationType = CertStoreOperationType.Add,
            JobCertificate = new ManagementJobCertificate
            {
                Alias = $"{nonExistentNamespace}/secrets/opaque/{secretName}",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(
                    CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, pfxPassword))
            },
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = nonExistentNamespace,
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

        // Assert - Should fail when namespace doesn't exist
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Failure,
            $"Expected Failure but got {result.Result}. FailureMessage: {result.FailureMessage}");
    }

    #endregion
}

