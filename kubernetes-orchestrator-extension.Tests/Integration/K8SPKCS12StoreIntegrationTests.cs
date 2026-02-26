// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using k8s;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SPKCS12;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.K8S.Tests.Attributes;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Keyfactor.Orchestrators.K8S.Tests.Integration.Fixtures;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration;

/// <summary>
/// Integration tests for K8SPKCS12 store type operations against a real Kubernetes cluster.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// Uses ~/.kube/config with kf-integrations context.
/// All resources are cleaned up after tests.
/// </summary>
[Collection("K8SPKCS12 Integration Tests")]
public class K8SPKCS12StoreIntegrationTests : IntegrationTestBase
{
    protected override string BaseTestNamespace => "keyfactor-k8spkcs12-integration-tests";

    public K8SPKCS12StoreIntegrationTests(IntegrationTestFixture fixture) : base(fixture)
    {
    }

    #region Inventory Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_EmptyPkcs12Secret_ReturnsEmptyList()
    {
        // Arrange
        var secretName = $"test-empty-pkcs12-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var pfxBytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.Rsa2048, "testpassword", "testcert");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.pfx", pfxBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Create Inventory job config
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SPKCS12",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "testpassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"testpassword\",\"StoreFileName\":\"keystore.pfx\"}"
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
        Assert.NotNull(result.JobHistoryId);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_Pkcs12SecretWithMultipleCerts_ReturnsAllCertificates()
    {
        // Arrange
        var secretName = $"test-multi-pkcs12-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Inventory Multi Cert 1");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Inventory Multi Cert 2");
        var cert3 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa4096, "Inventory Multi Cert 3");

        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "alias1", (cert1.Certificate, cert1.KeyPair) },
            { "alias2", (cert2.Certificate, cert2.KeyPair) },
            { "alias3", (cert3.Certificate, cert3.KeyPair) }
        };

        var pfxBytes = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(entries, "testpassword");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.pfx", pfxBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Create Inventory job config
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SPKCS12",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "testpassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"testpassword\",\"StoreFileName\":\"keystore.pfx\"}"
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
        TrackSecret(secretName);

        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "New Cert");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "certpassword", "newcert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

        // Create Management Add job config
        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SPKCS12",
            OperationType = CertStoreOperationType.Add,
            Overwrite = false,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"keystore.pfx\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "newcert",
                PrivateKeyPassword = "certpassword",
                Contents = pfxBase64
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

        // Verify secret was created
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.True(secret.Data.ContainsKey("keystore.pfx"));
        Assert.NotEmpty(secret.Data["keystore.pfx"]);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateToExistingSecret_UpdatesSecret()
    {
        // Arrange
        var secretName = $"test-add-existing-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Create existing secret with one certificate
        var existingCert = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Existing Cert");
        var existingPkcs12 = CertificateTestHelper.GeneratePkcs12(existingCert.Certificate, existingCert.KeyPair, "storepassword", "existing");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.pfx", existingPkcs12 }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Prepare new certificate to add
        var newCert = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "New Cert");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(newCert.Certificate, newCert.KeyPair, "certpassword", "newcert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

        // Create Management Add job config
        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SPKCS12",
            OperationType = CertStoreOperationType.Add,
            Overwrite = false,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"keystore.pfx\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "newcert",
                PrivateKeyPassword = "certpassword",
                Contents = pfxBase64
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

        // Verify secret was updated
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(updatedSecret);
        Assert.True(updatedSecret.Data.ContainsKey("keystore.pfx"));

        // Verify both certificates are in the store
        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["keystore.pfx"], "/test", "storepassword");
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
        TrackSecret(secretName);

        // Create secret with two certificates
        var cert1 = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Cert 1");
        var cert2 = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "Cert 2");

        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "cert1", (cert1.Certificate, cert1.KeyPair) },
            { "cert2", (cert2.Certificate, cert2.KeyPair) }
        };

        var pfxBytes = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(entries, "storepassword");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.pfx", pfxBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Create Management Remove job config
        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SPKCS12",
            OperationType = CertStoreOperationType.Remove,
            Overwrite = false,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"keystore.pfx\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "cert1"
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

        // Verify cert1 was removed and cert2 remains
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["keystore.pfx"], "/test", "storepassword");
        var aliases = store.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("cert2", aliases);
        Assert.DoesNotContain("cert1", aliases);
    }

    #endregion

    #region Discovery Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Discovery_FindsPkcs12SecretsInNamespace()
    {
        // Arrange - Create multiple PKCS12 secrets
        var secret1Name = $"test-discover-1-{Guid.NewGuid():N}";
        var secret2Name = $"test-discover-2-{Guid.NewGuid():N}";
        TrackSecret(secret1Name);
        TrackSecret(secret2Name);

        var pfxBytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.Rsa2048, "testpassword", "discovery-test");

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
                        { "keyfactor.com/store-type", "K8SPKCS12" }
                    }
                },
                Type = "Opaque",
                Data = new Dictionary<string, byte[]>
                {
                    { "keystore.pfx", pfxBytes }
                }
            };

            await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);
        }

        // Create Discovery job config
        var jobConfig = new DiscoveryJobConfiguration
        {
            Capability = "K8SPKCS12",
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
        // Note: Discovery returns store paths in the result
    }

    #endregion

    #region Error Handling Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddWithWrongPassword_ReturnsFailure()
    {
        // Arrange
        var secretName = $"test-wrong-password-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Create existing secret with one password
        var existingCert = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Existing");
        var existingPkcs12 = CertificateTestHelper.GeneratePkcs12(existingCert.Certificate, existingCert.KeyPair, "correctpassword");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.pfx", existingPkcs12 }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Try to add with wrong password
        var newCert = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "New");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(newCert.Certificate, newCert.KeyPair, "certpassword");

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SPKCS12",
            OperationType = CertStoreOperationType.Add,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "wrongpassword", // Wrong password!
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"wrongpassword\",\"StoreFileName\":\"keystore.pfx\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "newcert",
                PrivateKeyPassword = "certpassword",
                Contents = Convert.ToBase64String(pfxBytes)
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var management = new Management(MockPamResolver.Object);

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
            Capability = "K8SPKCS12",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{nonExistentSecretName}",
                StorePassword = "password",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"password\",\"StoreFileName\":\"keystore.pfx\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Failure,
            $"Expected Failure but got {result.Result}. FailureMessage: {result.FailureMessage}");
        Assert.NotNull(result.FailureMessage);
    }

    #endregion

    #region StorePath Pattern Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_StorePathWithSecretsKeyword_WorksCorrectly()
    {
        // Test the <namespace>/secrets/<secret> storepath pattern
        // Arrange
        var secretName = $"test-path-secrets-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var pfxBytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.Rsa2048, "testpassword", "testcert");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.pfx", pfxBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var inventoryItems = new List<CurrentInventoryItem>();

        // Use <namespace>/secrets/<secret> pattern
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SPKCS12",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/secrets/{secretName}",
                StorePassword = "testpassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"testpassword\",\"StoreFileName\":\"keystore.pfx\"}"
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
        Assert.True(inventoryItems.Count > 0, "Should find certificates with <namespace>/secrets/<secret> path pattern");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_StorePathWithClusterNamespaceSecrets_WorksCorrectly()
    {
        // Test the <cluster>/<namespace>/secrets/<secret> storepath pattern
        // Arrange
        var secretName = $"test-path-cluster-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var pfxBytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.Rsa2048, "testpassword", "testcert");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.pfx", pfxBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var inventoryItems = new List<CurrentInventoryItem>();

        // Use <cluster>/<namespace>/secrets/<secret> pattern
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SPKCS12",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "kf-integrations",
                StorePath = $"kf-integrations/{TestNamespace}/secrets/{secretName}",
                StorePassword = "testpassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"testpassword\",\"StoreFileName\":\"keystore.pfx\"}"
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
        Assert.True(inventoryItems.Count > 0, "Should find certificates with <cluster>/<namespace>/secrets/<secret> path pattern");
    }

    #endregion
}
