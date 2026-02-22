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
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers.Serializers;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.K8S.Tests.Attributes;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Moq;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration;

/// <summary>
/// Integration tests for K8SJKS store type operations against a real Kubernetes cluster.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// Uses ~/.kube/config with kf-integrations context.
/// All resources are cleaned up after tests.
/// </summary>
[Collection("Integration Tests")]
public class K8SJKSStoreIntegrationTests : IAsyncLifetime
{
    private const string TestNamespace = "keyfactor-k8sjks-integration-tests";
    private static readonly string KubeconfigPath = (Environment.GetEnvironmentVariable("INTEGRATION_TEST_KUBECONFIG") ?? "~/.kube/config").Replace("~", Environment.GetEnvironmentVariable("HOME") ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
    private static readonly string ClusterContext = Environment.GetEnvironmentVariable("INTEGRATION_TEST_CONTEXT") ?? "kf-integrations";

    private Kubernetes _k8sClient;
    private KubeCertificateManagerClient _kubeClientWrapper;
    private string _kubeconfigJson;
    private readonly List<string> _createdSecrets = new List<string>();
    private Mock<Keyfactor.Orchestrators.Extensions.Interfaces.IPAMSecretResolver> _mockPamResolver;

    public async Task InitializeAsync()
    {
        // Skip initialization if not running integration tests
        var runIntegrationTests = Environment.GetEnvironmentVariable("RUN_INTEGRATION_TESTS");
        if (string.IsNullOrEmpty(runIntegrationTests) ||
            !runIntegrationTests.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Load kubeconfig from standard location
        var kubeconfigPath = KubeconfigPath.Replace("~", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        if (!File.Exists(kubeconfigPath))
        {
            throw new FileNotFoundException($"Kubeconfig not found at {kubeconfigPath}");
        }

        var kubeconfigContent = await File.ReadAllTextAsync(kubeconfigPath);
        _kubeconfigJson = ConvertKubeconfigToJson(kubeconfigContent);

        // Initialize Kubernetes client
        var config = KubernetesClientConfiguration.BuildConfigFromConfigFile(kubeconfigPath, currentContext: ClusterContext);
        _k8sClient = new Kubernetes(config);

        // Initialize wrapper client
        _kubeClientWrapper = new KubeCertificateManagerClient(_kubeconfigJson);

        // Initialize mock PAM resolver (returns null for all password lookups, meaning use provided passwords)
        _mockPamResolver = new Mock<Keyfactor.Orchestrators.Extensions.Interfaces.IPAMSecretResolver>();
        _mockPamResolver.Setup(x => x.Resolve(It.IsAny<string>())).Returns((string)null);

        // Create test namespace if it doesn't exist
        await CreateNamespaceIfNotExists();
    }

    public async Task DisposeAsync()
    {
        // Skip cleanup if not running integration tests
        var runIntegrationTests = Environment.GetEnvironmentVariable("RUN_INTEGRATION_TESTS");
        if (string.IsNullOrEmpty(runIntegrationTests) ||
            !runIntegrationTests.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Skip cleanup if user wants to manually inspect secrets
        var skipCleanup = Environment.GetEnvironmentVariable("SKIP_INTEGRATION_TEST_CLEANUP");
        if (!string.IsNullOrEmpty(skipCleanup) &&
            skipCleanup.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Clean up all created secrets
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

        // Optionally delete the test namespace (commented out to preserve for inspection)
        // await _k8sClient.CoreV1.DeleteNamespaceAsync(TestNamespace);

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

        // Build a minimal kubeconfig JSON structure using Dictionary to support hyphenated property names
        var kubeconfigObj = new Dictionary<string, object>
        {
            ["kind"] = "Config",
            ["apiVersion"] = "v1",
            ["current-context"] = ClusterContext,  // FIXED: Use hyphenated property name
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

    #region Inventory Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_EmptyJksSecret_ReturnsEmptyList()
    {
        // Arrange
        var secretName = $"test-empty-jks-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Integration Test Cert");
        var jksBytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "testpassword", "testcert");

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = secretName,
                NamespaceProperty = TestNamespace
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", jksBytes }
            }
        };

        await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Create Inventory job config
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SJKS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "testpassword",
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"testpassword\",\"StoreFileName\":\"keystore.jks\"}"
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
        Assert.NotNull(result.JobHistoryId);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_JksSecretWithMultipleCerts_ReturnsAllCertificates()
    {
        // Arrange
        var secretName = $"test-multi-jks-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);

        var cert1 = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Cert 1");
        var cert2 = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "Cert 2");
        var cert3 = CertificateTestHelper.GenerateCertificate(KeyType.Rsa4096, "Cert 3");

        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "alias1", (cert1.Certificate, cert1.KeyPair) },
            { "alias2", (cert2.Certificate, cert2.KeyPair) },
            { "alias3", (cert3.Certificate, cert3.KeyPair) }
        };

        var jksBytes = CertificateTestHelper.GenerateJksWithMultipleEntries(entries, "testpassword");

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = secretName,
                NamespaceProperty = TestNamespace
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", jksBytes }
            }
        };

        await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Create Inventory job config
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SJKS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "testpassword",
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"testpassword\",\"StoreFileName\":\"keystore.jks\"}"
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
        Assert.NotNull(result.JobHistoryId);
        // Verify we got back 3 certificates
        // Note: The actual certificate data would be in result.JobHistoryId serialized data
    }

    #endregion

    #region Management Add Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateToNewSecret_CreatesSecretWithCertificate()
    {
        // Arrange
        var secretName = $"test-add-new-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "New Cert");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "certpassword", "newcert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

        // Create Management Add job config
        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SJKS",
            OperationType = CertStoreOperationType.Add,
            Overwrite = false,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"keystore.jks\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "newcert",
                PrivateKeyPassword = "certpassword",
                Contents = pfxBase64
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

        // Verify secret was created
        var secret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.True(secret.Data.ContainsKey("keystore.jks"));
        Assert.NotEmpty(secret.Data["keystore.jks"]);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateToExistingSecret_UpdatesSecret()
    {
        // Arrange
        var secretName = $"test-add-existing-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);

        // Create existing secret with one certificate
        var existingCert = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Existing Cert");
        var existingJks = CertificateTestHelper.GenerateJks(existingCert.Certificate, existingCert.KeyPair, "storepassword", "existing");

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = secretName,
                NamespaceProperty = TestNamespace
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", existingJks }
            }
        };

        await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Prepare new certificate to add
        var newCert = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "New Cert");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(newCert.Certificate, newCert.KeyPair, "certpassword", "newcert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

        // Create Management Add job config
        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SJKS",
            OperationType = CertStoreOperationType.Add,
            Overwrite = false,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"keystore.jks\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "newcert",
                PrivateKeyPassword = "certpassword",
                Contents = pfxBase64
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

        // Verify secret was updated
        var updatedSecret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(updatedSecret);
        Assert.True(updatedSecret.Data.ContainsKey("keystore.jks"));

        // Verify both certificates are in the store
        var serializer = new JksCertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["keystore.jks"], "/test", "storepassword");
        var aliases = store.Aliases.ToList();
        Assert.Equal(2, aliases.Count);
        Assert.Contains("existing", aliases);
        Assert.Contains("newcert", aliases);
    }

    #endregion

    #region Management Remove Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_RemoveCertificateFromSecret_RemovesCertificate()
    {
        // Arrange
        var secretName = $"test-remove-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);

        // Create secret with two certificates
        var cert1 = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Cert 1");
        var cert2 = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "Cert 2");

        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "cert1", (cert1.Certificate, cert1.KeyPair) },
            { "cert2", (cert2.Certificate, cert2.KeyPair) }
        };

        var jksBytes = CertificateTestHelper.GenerateJksWithMultipleEntries(entries, "storepassword");

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = secretName,
                NamespaceProperty = TestNamespace
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", jksBytes }
            }
        };

        await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Create Management Remove job config
        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SJKS",
            OperationType = CertStoreOperationType.Remove,
            Overwrite = false,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"keystore.jks\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "cert1"
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

        // Verify cert1 was removed and cert2 remains
        var updatedSecret = await _k8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        var serializer = new JksCertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["keystore.jks"], "/test", "storepassword");
        var aliases = store.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("cert2", aliases);
        Assert.DoesNotContain("cert1", aliases);
    }

    #endregion

    #region Discovery Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Discovery_FindsJksSecretsInNamespace()
    {
        // Arrange - Create multiple JKS secrets
        var secret1Name = $"test-discover-1-{Guid.NewGuid():N}";
        var secret2Name = $"test-discover-2-{Guid.NewGuid():N}";
        _createdSecrets.Add(secret1Name);
        _createdSecrets.Add(secret2Name);

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Discovery Test");
        var jksBytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "testpassword");

        foreach (var secretName in new[] { secret1Name, secret2Name })
        {
            var secret = new V1Secret
            {
                Metadata = new V1ObjectMeta
                {
                    Name = secretName,
                    NamespaceProperty = TestNamespace,
                    Labels = new Dictionary<string, string>
                    {
                        { "keyfactor.com/store-type", "K8SJKS" }
                    }
                },
                Type = "Opaque",
                Data = new Dictionary<string, byte[]>
                {
                    { "keystore.jks", jksBytes }
                }
            };

            await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);
        }

        // Create Discovery job config
        var jobConfig = new DiscoveryJobConfiguration
        {
            Capability = "K8SJKS",
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
        // Note: Discovery returns store paths in the result
    }

    #endregion

    #region Error Handling Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddWithWrongPassword_ReturnsFailure()
    {
        // Arrange
        var secretName = $"test-wrong-password-{Guid.NewGuid():N}";
        _createdSecrets.Add(secretName);

        // Create existing secret with one password
        var existingCert = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Existing");
        var existingJks = CertificateTestHelper.GenerateJks(existingCert.Certificate, existingCert.KeyPair, "correctpassword");

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = secretName,
                NamespaceProperty = TestNamespace
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", existingJks }
            }
        };

        await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Try to add with wrong password
        var newCert = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "New");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(newCert.Certificate, newCert.KeyPair, "certpassword");

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SJKS",
            OperationType = CertStoreOperationType.Add,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "wrongpassword", // Wrong password!
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"wrongpassword\",\"StoreFileName\":\"keystore.jks\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "newcert",
                PrivateKeyPassword = "certpassword",
                Contents = Convert.ToBase64String(pfxBytes)
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
            UseSSL = true
        };

        var management = new Management(_mockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Failure,
            $"Expected Failure but got {result.Result}. FailureMessage: {result.FailureMessage}");
        Assert.NotNull(result.FailureMessage);
        Assert.Contains("password", result.FailureMessage.ToLower());
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_NonExistentSecret_ReturnsFailure()
    {
        // Arrange
        var nonExistentSecretName = $"does-not-exist-{Guid.NewGuid():N}";

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SJKS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{nonExistentSecretName}",
                StorePassword = "password",
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"password\",\"StoreFileName\":\"keystore.jks\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = _kubeconfigJson,
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
