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
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SJKS;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.K8S.Tests.Attributes;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Keyfactor.Orchestrators.K8S.Tests.Integration.Fixtures;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration;

/// <summary>
/// Integration tests for K8SJKS store type operations against a real Kubernetes cluster.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// Uses ~/.kube/config with kf-integrations context.
/// All resources are cleaned up after tests.
/// </summary>
[Collection("K8SJKS Integration Tests")]
public class K8SJKSStoreIntegrationTests : IntegrationTestBase
{
    protected override string BaseTestNamespace => "keyfactor-k8sjks-integration-tests";

    public K8SJKSStoreIntegrationTests(IntegrationTestFixture fixture) : base(fixture)
    {
    }

    #region Inventory Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_EmptyJksSecret_ReturnsEmptyList()
    {
        // Arrange
        var secretName = $"test-empty-jks-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Integration Test Cert");
        var jksBytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "testpassword", "testcert");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", jksBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

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
    public async Task Inventory_JksSecretWithMultipleCerts_ReturnsAllCertificates()
    {
        // Arrange
        var secretName = $"test-multi-jks-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert 1");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Cert 2");
        var cert3 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa4096, "Cert 3");

        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "alias1", (cert1.Certificate, cert1.KeyPair) },
            { "alias2", (cert2.Certificate, cert2.KeyPair) },
            { "alias3", (cert3.Certificate, cert3.KeyPair) }
        };

        var jksBytes = CertificateTestHelper.GenerateJksWithMultipleEntries(entries, "testpassword");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", jksBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

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
        Assert.True(secret.Data.ContainsKey("keystore.jks"));
        Assert.NotEmpty(secret.Data["keystore.jks"]);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithChain_IncludeCertChainFalse_OnlyLeafCertInKeystore()
    {
        // Arrange
        var secretName = $"test-include-chain-false-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate a certificate chain (leaf -> intermediate -> root)
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048,
            leafCN: "Leaf Cert",
            intermediateCN: "Intermediate CA",
            rootCN: "Root CA");

        var leafCert = chain[0];
        var intermediateCert = chain[1];
        var rootCert = chain[2];

        // Create PKCS12 with the full chain (leaf + intermediate + root)
        var chainCerts = new[] { intermediateCert.Certificate, rootCert.Certificate };
        var pfxBytes = CertificateTestHelper.GeneratePkcs12WithChain(
            leafCert.Certificate,
            leafCert.KeyPair.Private,
            chainCerts,
            password: "certpassword",
            alias: "leafcert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

        // Create Management Add job config with IncludeCertChain=false
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
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"keystore.jks\",\"IncludeCertChain\":\"false\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "leafcert",
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

        // Assert - Job should succeed
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify secret was created
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.True(secret.Data.ContainsKey("keystore.jks"), "Secret should contain keystore.jks");

        // Load the JKS and verify the chain length
        var jksStore = new Org.BouncyCastle.Security.JksStore();
        using (var ms = new System.IO.MemoryStream(secret.Data["keystore.jks"]))
        {
            jksStore.Load(ms, "storepassword".ToCharArray());
        }

        // Verify the alias exists
        Assert.True(jksStore.ContainsAlias("leafcert"), "JKS should contain the 'leafcert' alias");

        // Get the certificate chain for the alias
        var certChain = jksStore.GetCertificateChain("leafcert");

        // With IncludeCertChain=false, only the leaf certificate should be in the chain
        Assert.NotNull(certChain);
        Assert.Single(certChain); // Should have exactly 1 certificate (only the leaf)

        // Verify the certificate is the leaf certificate
        var storedCert = certChain[0];
        Assert.Equal(leafCert.Certificate.SubjectDN.ToString(), storedCert.SubjectDN.ToString());
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateToExistingSecret_UpdatesSecret()
    {
        // Arrange
        var secretName = $"test-add-existing-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Create existing secret with one certificate
        var existingCert = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Existing Cert");
        var existingJks = CertificateTestHelper.GenerateJks(existingCert.Certificate, existingCert.KeyPair, "storepassword", "existing");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", existingJks }
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
        Assert.True(updatedSecret.Data.ContainsKey("keystore.jks"));

        // Verify both certificates are in the store
        var serializer = new JksCertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["keystore.jks"], "/test", "storepassword");
        var aliases = store.Aliases.ToList();
        Assert.Equal(2, aliases.Count);
        Assert.Contains("existing", aliases);
        Assert.Contains("newcert", aliases);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_CreateStoreIfMissing_NoCertificateData_CreatesEmptyJksStore()
    {
        // Arrange - "Create store if missing" scenario: no certificate data provided
        var secretName = $"test-create-store-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Create Management Add job config with no certificate contents (simulates "create store if missing")
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
                // No alias, no contents - simulates "create store if missing"
                Alias = null,
                PrivateKeyPassword = null,
                Contents = null
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

        // Verify secret was created with an empty but valid JKS keystore
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.True(secret.Data.ContainsKey("keystore.jks"), "Expected 'keystore.jks' key in secret data");
        Assert.NotEmpty(secret.Data["keystore.jks"]);

        // Verify the JKS store is valid and empty (no aliases)
        var serializer = new JksCertificateStoreSerializer(null);
        var jksStore = serializer.DeserializeRemoteCertificateStore(secret.Data["keystore.jks"], "/test", "storepassword");
        var aliases = jksStore.Aliases.ToList();
        Assert.Empty(aliases);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_CreateStoreIfMissing_SecretAlreadyExists_ReturnsExistingSecret()
    {
        // Arrange - Secret already exists, "create store if missing" should return the existing secret
        var secretName = $"test-existing-store-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Create existing secret with one certificate
        var existingCert = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Existing Cert");
        var existingJks = CertificateTestHelper.GenerateJks(existingCert.Certificate, existingCert.KeyPair, "storepassword", "existing");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", existingJks }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Create Management Add job config with no certificate contents
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
                Alias = null,
                PrivateKeyPassword = null,
                Contents = null
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var management = new Management(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert - Should succeed without modifying the existing store
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify the existing certificate is still present
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        var serializer = new JksCertificateStoreSerializer(null);
        var jksStore = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["keystore.jks"], "/test", "storepassword");
        var aliases = jksStore.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("existing", aliases);
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

        var jksBytes = CertificateTestHelper.GenerateJksWithMultipleEntries(entries, "storepassword");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", jksBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

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
        TrackSecret(secret1Name);
        TrackSecret(secret2Name);

        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Discovery Test");
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

            await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);
        }

        // Create Discovery job config
        var jobConfig = new DiscoveryJobConfiguration
        {
            Capability = "K8SJKS",
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
        var existingJks = CertificateTestHelper.GenerateJks(existingCert.Certificate, existingCert.KeyPair, "correctpassword");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", existingJks }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

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
    public async Task Inventory_NonExistentSecret_ReturnsSuccessWithEmptyInventory()
    {
        // Arrange - Test that non-existent secrets return success with empty inventory
        // This behavior supports the "create store if missing" feature
        var nonExistentSecretName = $"does-not-exist-{Guid.NewGuid():N}";
        var inventoryItems = new List<CurrentInventoryItem>();

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

        // Assert - Should return Success with warning message and empty inventory
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
        Assert.Contains("not found", result.FailureMessage ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Empty(inventoryItems);
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

        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Path Pattern Test");
        var jksBytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "testpassword", "testcert");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", jksBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var inventoryItems = new List<CurrentInventoryItem>();

        // Use <namespace>/secrets/<secret> pattern
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SJKS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/secrets/{secretName}",
                StorePassword = "testpassword",
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"testpassword\",\"StoreFileName\":\"keystore.jks\"}"
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

        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cluster Path Test");
        var jksBytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "testpassword", "testcert");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", jksBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var inventoryItems = new List<CurrentInventoryItem>();

        // Use <cluster>/<namespace>/secrets/<secret> pattern
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SJKS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "kf-integrations",
                StorePath = $"kf-integrations/{TestNamespace}/secrets/{secretName}",
                StorePassword = "testpassword",
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"testpassword\",\"StoreFileName\":\"keystore.jks\"}"
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

    #region Mixed Entry Types Tests (Private Keys + Trusted Certs)

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_JksWithMixedEntries_ReturnsCorrectPrivateKeyFlags()
    {
        // Arrange - Create JKS with 2 private key entries + 2 trusted cert entries
        var secretName = $"test-mixed-jks-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate certificates for private key entries (with keys)
        var serverCert1 = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Server Cert 1");
        var serverCert2 = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "Server Cert 2");

        // Generate certificates for trusted cert entries (no keys)
        var trustedRootCa = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Trusted Root CA");
        var trustedIntermediateCa = CertificateTestHelper.GenerateCertificate(KeyType.Rsa4096, "Trusted Intermediate CA");

        var privateKeyEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "server1", (serverCert1.Certificate, serverCert1.KeyPair) },
            { "server2", (serverCert2.Certificate, serverCert2.KeyPair) }
        };

        var trustedCertEntries = new Dictionary<string, Org.BouncyCastle.X509.X509Certificate>
        {
            { "root-ca", trustedRootCa.Certificate },
            { "intermediate-ca", trustedIntermediateCa.Certificate }
        };

        var jksBytes = CertificateTestHelper.GenerateJksWithMixedEntries(privateKeyEntries, trustedCertEntries, "testpassword");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", jksBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var inventoryItems = new List<CurrentInventoryItem>();

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

        // NOTE: JKS inventory only returns entries with private keys (PrivateKeyEntry).
        // Trusted certificate entries (certificate-only, no private key) are NOT returned.
        // This is because GetCertificateChain() returns null for certificate-only entries,
        // which causes them to be marked as "skip" in the JKS inventory handler.
        // Should have 2 inventory items (only the private key entries)
        Assert.Equal(2, inventoryItems.Count);

        // Verify private key entries are returned
        // Note: JKS inventory uses full alias format: <secretDataKey>/<entryAlias>
        var server1Item = inventoryItems.FirstOrDefault(i => i.Alias == "keystore.jks/server1");
        var server2Item = inventoryItems.FirstOrDefault(i => i.Alias == "keystore.jks/server2");

        Assert.NotNull(server1Item);
        Assert.NotNull(server2Item);

        // Private key entries should have PrivateKeyEntry = true
        Assert.True(server1Item.PrivateKeyEntry, "server1 should have PrivateKeyEntry = true");
        Assert.True(server2Item.PrivateKeyEntry, "server2 should have PrivateKeyEntry = true");

        // Verify trusted cert entries are NOT returned (expected behavior for JKS)
        var rootCaItem = inventoryItems.FirstOrDefault(i => i.Alias == "keystore.jks/root-ca");
        var intermediateCaItem = inventoryItems.FirstOrDefault(i => i.Alias == "keystore.jks/intermediate-ca");
        Assert.Null(rootCaItem); // Trusted certs are not included in JKS inventory
        Assert.Null(intermediateCaItem); // Trusted certs are not included in JKS inventory
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddTrustedCert_ToExistingJks_Success()
    {
        // Arrange - Create existing JKS with a private key entry
        var secretName = $"test-add-trusted-jks-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var serverCert = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Server Cert");
        var existingJks = CertificateTestHelper.GenerateJks(serverCert.Certificate, serverCert.KeyPair, "storepassword", "server");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", existingJks }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Generate a trusted certificate (certificate only, no private key)
        var trustedCa = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Trusted CA");

        // For adding a certificate-only entry, we send the DER-encoded certificate
        // The management job should detect this and add it as a trusted cert entry
        var certOnlyBase64 = Convert.ToBase64String(trustedCa.Certificate.GetEncoded());

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
                Alias = "trusted-ca",
                PrivateKeyPassword = null, // No private key password for certificate-only entry
                Contents = certOnlyBase64
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

        // Verify the JKS was updated with both entries
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(updatedSecret);

        // Load the JKS and verify both entries exist
        var jksStore = new Org.BouncyCastle.Security.JksStore();
        using (var ms = new System.IO.MemoryStream(updatedSecret.Data["keystore.jks"]))
        {
            jksStore.Load(ms, "storepassword".ToCharArray());
        }

        var aliases = jksStore.Aliases.ToList();
        Assert.Equal(2, aliases.Count);
        Assert.Contains("server", aliases);
        Assert.Contains("trusted-ca", aliases);

        // Verify entry types
        Assert.True(jksStore.IsKeyEntry("server"), "server should be a key entry");
        Assert.False(jksStore.IsKeyEntry("trusted-ca"), "trusted-ca should be a certificate-only entry");
    }

    #endregion

    #region PKCS12 Format Detection Tests

    /// <summary>
    /// Tests that the JKS store type correctly fails when encountering PKCS12 format data.
    /// Note: BouncyCastle's JksStore reports PKCS12 data as "password incorrect or store tampered with"
    /// because the file format doesn't match the JKS magic bytes. The intended auto-delegation
    /// via JkSisPkcs12Exception does not work because IOException is thrown instead.
    /// Users should use the K8SPKCS12 store type for PKCS12 files.
    /// </summary>
    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_Pkcs12FileInJksSecret_ReturnsFailureWithPasswordError()
    {
        // Arrange - Create a K8s secret with PKCS12 data but configure as JKS store
        // This tests that PKCS12 files cannot be processed by the JKS store type
        var secretName = $"test-pkcs12-in-jks-inv-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate PKCS12 data (NOT JKS)
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 in JKS Test");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "testpassword", "testcert");

        // Create secret with PKCS12 data but named as a keystore file
        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", pkcs12Bytes }  // PKCS12 data in a .jks filename
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var inventoryItems = new List<CurrentInventoryItem>();

        // Create Inventory job config as K8SJKS store type
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
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act - The inventory job will fail because JKS parser cannot read PKCS12 format
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (items) =>
        {
            inventoryItems.AddRange(items);
            return true;
        }));

        // Assert - Should fail with password/format error
        // The JKS parser interprets PKCS12 format as "password incorrect or store tampered with"
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Failure,
            $"Expected Failure but got {result.Result}. FailureMessage: {result.FailureMessage}");
        Assert.NotNull(result.FailureMessage);
        Assert.Contains("password", result.FailureMessage.ToLower());
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddToJksStore_ExistingSecretIsPkcs12_ReturnsFailure()
    {
        // Arrange - Create a secret with PKCS12 data but configure as JKS store
        // Then try to add a certificate to it - should fail because JKS cannot read PKCS12
        var secretName = $"test-add-pkcs12-jks-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Create existing secret with PKCS12 data
        var existingCertInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Existing PKCS12");
        var existingPkcs12Bytes = CertificateTestHelper.GeneratePkcs12(
            existingCertInfo.Certificate,
            existingCertInfo.KeyPair,
            "storepassword",
            "existing");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", existingPkcs12Bytes }  // PKCS12 data
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Prepare new certificate to add
        var newCert = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "New Cert for PKCS12");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(newCert.Certificate, newCert.KeyPair, "certpassword", "newcert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

        // Create Management Add job config as K8SJKS
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
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var management = new Management(MockPamResolver.Object);

        // Act - Should fail because JKS parser cannot read PKCS12
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert - Should fail with password/format error
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Failure,
            $"Expected Failure but got {result.Result}. FailureMessage: {result.FailureMessage}");
        Assert.NotNull(result.FailureMessage);
        Assert.Contains("password", result.FailureMessage.ToLower());
    }

    /// <summary>
    /// Verifies that actual JKS files work correctly with the JKS store type.
    /// This is a sanity check alongside the PKCS12 failure tests.
    /// </summary>
    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_ActualJksFile_SucceedsCorrectly()
    {
        // Arrange
        var secretName = $"test-actual-jks-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate actual JKS data
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Actual JKS Test");
        var jksBytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "testpassword", "testcert");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", jksBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var inventoryItems = new List<CurrentInventoryItem>();

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

        // Assert - Should succeed with actual JKS data
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
        Assert.True(inventoryItems.Count > 0, "Should find certificates in actual JKS store");
    }

    #endregion

    #region Multiple JKS Files in Single Secret Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_SecretWithMultipleJksFiles_ReturnsAllCertificatesFromAllFiles()
    {
        // Arrange - Create a K8s secret with multiple JKS files (app.jks, ca.jks, truststore.jks)
        var secretName = $"test-multi-jks-files-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate different certificates for each JKS file
        var appCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "App Server Cert");
        var caCert = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "CA Certificate");
        var trustCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa4096, "Truststore Cert");

        // Generate separate JKS files with unique aliases
        var appJksBytes = CertificateTestHelper.GenerateJks(appCert.Certificate, appCert.KeyPair, "testpassword", "app-server");
        var caJksBytes = CertificateTestHelper.GenerateJks(caCert.Certificate, caCert.KeyPair, "testpassword", "ca-cert");
        var trustJksBytes = CertificateTestHelper.GenerateJks(trustCert.Certificate, trustCert.KeyPair, "testpassword", "trust-cert");

        // Create secret with multiple JKS files
        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "app.jks", appJksBytes },
                { "ca.jks", caJksBytes },
                { "truststore.jks", trustJksBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var inventoryItems = new List<CurrentInventoryItem>();

        // Create Inventory job config - Note: without StoreFileName, it should process ALL JKS files
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SJKS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "testpassword",
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"testpassword\"}"
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

        // Should find all 3 certificates from all 3 JKS files
        Assert.True(inventoryItems.Count >= 3,
            $"Expected at least 3 certificates but found {inventoryItems.Count}");

        // Verify aliases from each file are present (format: <filename>/<alias>)
        var aliasStrings = inventoryItems.Select(i => i.Alias).ToList();
        Assert.Contains(aliasStrings, a => a.Contains("app-server") || a.Contains("app.jks"));
        Assert.Contains(aliasStrings, a => a.Contains("ca-cert") || a.Contains("ca.jks"));
        Assert.Contains(aliasStrings, a => a.Contains("trust-cert") || a.Contains("truststore.jks"));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_SecretWithMultipleJksFiles_EachFileHasMultipleEntries_ReturnsAll()
    {
        // Arrange - Create a K8s secret with 2 JKS files, each containing 2 certificates
        var secretName = $"test-multi-jks-multi-entries-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate certificates for app.jks (2 entries)
        var appCert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "App Cert 1");
        var appCert2 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "App Cert 2");

        // Generate certificates for backend.jks (2 entries)
        var backendCert1 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Backend Cert 1");
        var backendCert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Backend Cert 2");

        var appEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "app-cert-1", (appCert1.Certificate, appCert1.KeyPair) },
            { "app-cert-2", (appCert2.Certificate, appCert2.KeyPair) }
        };

        var backendEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "backend-cert-1", (backendCert1.Certificate, backendCert1.KeyPair) },
            { "backend-cert-2", (backendCert2.Certificate, backendCert2.KeyPair) }
        };

        var appJksBytes = CertificateTestHelper.GenerateJksWithMultipleEntries(appEntries, "testpassword");
        var backendJksBytes = CertificateTestHelper.GenerateJksWithMultipleEntries(backendEntries, "testpassword");

        // Create secret with multiple JKS files
        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "app.jks", appJksBytes },
                { "backend.jks", backendJksBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var inventoryItems = new List<CurrentInventoryItem>();

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SJKS",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "testpassword",
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"testpassword\"}"
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

        // Should find all 4 certificates (2 from each JKS file)
        Assert.True(inventoryItems.Count >= 4,
            $"Expected at least 4 certificates but found {inventoryItems.Count}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificate_ToSpecificJksFile_UpdatesCorrectFile()
    {
        // Arrange - Create a K8s secret with multiple JKS files
        var secretName = $"test-add-specific-jks-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate existing JKS files
        var appCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Existing App Cert");
        var backendCert = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Existing Backend Cert");

        var appJksBytes = CertificateTestHelper.GenerateJks(appCert.Certificate, appCert.KeyPair, "storepassword", "existing-app");
        var backendJksBytes = CertificateTestHelper.GenerateJks(backendCert.Certificate, backendCert.KeyPair, "storepassword", "existing-backend");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "app.jks", appJksBytes },
                { "backend.jks", backendJksBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Prepare new certificate to add to app.jks specifically
        var newCert = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "New App Cert");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(newCert.Certificate, newCert.KeyPair, "certpassword", "new-app-cert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

        // Create Management Add job config targeting app.jks specifically
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
                // Use StoreFileName to target a specific JKS file
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"app.jks\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "new-app-cert",
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

        // Verify the secret was updated
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(updatedSecret);
        Assert.True(updatedSecret.Data.ContainsKey("app.jks"), "app.jks should still exist");
        Assert.True(updatedSecret.Data.ContainsKey("backend.jks"), "backend.jks should still exist");

        // Verify app.jks was updated with the new cert
        var serializer = new JksCertificateStoreSerializer(null);
        var appStore = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["app.jks"], "/test", "storepassword");
        var appAliases = appStore.Aliases.ToList();
        Assert.Equal(2, appAliases.Count);
        Assert.Contains("existing-app", appAliases);
        Assert.Contains("new-app-cert", appAliases);

        // Verify backend.jks was NOT modified (should still have only 1 cert)
        var backendStore = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["backend.jks"], "/test", "storepassword");
        var backendAliases = backendStore.Aliases.ToList();
        Assert.Single(backendAliases);
        Assert.Contains("existing-backend", backendAliases);
        Assert.DoesNotContain("new-app-cert", backendAliases);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_RemoveCertificate_FromSpecificJksFile_UpdatesCorrectFile()
    {
        // Arrange - Create a K8s secret with multiple JKS files, each with multiple certs
        var secretName = $"test-remove-specific-jks-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Create app.jks with 2 certs
        var appCert1 = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "App Cert 1");
        var appCert2 = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "App Cert 2");
        var appEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "app-cert-1", (appCert1.Certificate, appCert1.KeyPair) },
            { "app-cert-2", (appCert2.Certificate, appCert2.KeyPair) }
        };
        var appJksBytes = CertificateTestHelper.GenerateJksWithMultipleEntries(appEntries, "storepassword");

        // Create backend.jks with 2 certs
        var backendCert1 = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "Backend Cert 1");
        var backendCert2 = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "Backend Cert 2");
        var backendEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "backend-cert-1", (backendCert1.Certificate, backendCert1.KeyPair) },
            { "backend-cert-2", (backendCert2.Certificate, backendCert2.KeyPair) }
        };
        var backendJksBytes = CertificateTestHelper.GenerateJksWithMultipleEntries(backendEntries, "storepassword");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "app.jks", appJksBytes },
                { "backend.jks", backendJksBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Remove app-cert-1 from app.jks specifically
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
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"app.jks\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "app-cert-1"
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

        // Verify the correct file was updated
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        var serializer = new JksCertificateStoreSerializer(null);

        // app.jks should now have only 1 cert (app-cert-2)
        var appStore = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["app.jks"], "/test", "storepassword");
        var appAliases = appStore.Aliases.ToList();
        Assert.Single(appAliases);
        Assert.Contains("app-cert-2", appAliases);
        Assert.DoesNotContain("app-cert-1", appAliases);

        // backend.jks should be unchanged (still have 2 certs)
        var backendStore = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["backend.jks"], "/test", "storepassword");
        var backendAliases = backendStore.Aliases.ToList();
        Assert.Equal(2, backendAliases.Count);
        Assert.Contains("backend-cert-1", backendAliases);
        Assert.Contains("backend-cert-2", backendAliases);
    }

    #endregion

    #region Native JKS Format Preservation Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertToNativeJks_PreservesJksFormat()
    {
        // Arrange - Create a native JKS secret
        var secretName = $"test-jks-format-add-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var existingCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Existing JKS Cert");
        var existingJks = CertificateTestHelper.GenerateJks(existingCert.Certificate, existingCert.KeyPair, "storepassword", "existing");

        // Verify initial JKS is in native JKS format
        Assert.True(CertificateTestHelper.IsNativeJksFormat(existingJks), "Initial JKS should be in native JKS format");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", existingJks }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Prepare new certificate to add
        var newCert = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "New Cert JKS Format");
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
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var management = new Management(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify the updated secret is still in native JKS format (not PKCS12)
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(updatedSecret);
        Assert.True(updatedSecret.Data.ContainsKey("keystore.jks"));

        var updatedJksBytes = updatedSecret.Data["keystore.jks"];

        // Verify JKS format is preserved (magic bytes 0xFEEDFEED)
        Assert.True(CertificateTestHelper.IsNativeJksFormat(updatedJksBytes),
            $"Updated keystore should remain in native JKS format but got magic bytes: 0x{updatedJksBytes[0]:X2}{updatedJksBytes[1]:X2}{updatedJksBytes[2]:X2}{updatedJksBytes[3]:X2}");
        Assert.False(CertificateTestHelper.IsPkcs12Format(updatedJksBytes),
            "Updated keystore should NOT be in PKCS12 format");

        // Verify both certificates are in the store
        var jksStore = new Org.BouncyCastle.Security.JksStore();
        using (var ms = new System.IO.MemoryStream(updatedJksBytes))
        {
            jksStore.Load(ms, "storepassword".ToCharArray());
        }

        var aliases = jksStore.Aliases.ToList();
        Assert.Equal(2, aliases.Count);
        Assert.Contains("existing", aliases);
        Assert.Contains("newcert", aliases);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_UpdateCertInNativeJks_PreservesJksFormat()
    {
        // Arrange - Create a native JKS secret with a certificate
        var secretName = $"test-jks-format-update-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var existingCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Existing Cert Update");
        var existingJks = CertificateTestHelper.GenerateJks(existingCert.Certificate, existingCert.KeyPair, "storepassword", "testcert");

        // Verify initial JKS is in native JKS format
        Assert.True(CertificateTestHelper.IsNativeJksFormat(existingJks), "Initial JKS should be in native JKS format");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", existingJks }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Prepare replacement certificate (same alias, different cert)
        var replacementCert = CertificateTestHelper.GenerateCertificate(KeyType.EcP384, "Replacement Cert");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(replacementCert.Certificate, replacementCert.KeyPair, "certpassword", "testcert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

        // Create Management Add job config with Overwrite=true
        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SJKS",
            OperationType = CertStoreOperationType.Add,
            Overwrite = true, // Overwrite existing certificate
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"jks\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"keystore.jks\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert",
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

        // Verify the updated secret is still in native JKS format
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        var updatedJksBytes = updatedSecret.Data["keystore.jks"];

        Assert.True(CertificateTestHelper.IsNativeJksFormat(updatedJksBytes),
            "Updated keystore should remain in native JKS format after certificate update");
        Assert.False(CertificateTestHelper.IsPkcs12Format(updatedJksBytes),
            "Updated keystore should NOT be in PKCS12 format");

        // Verify the certificate was updated (still only 1 certificate with same alias)
        var jksStore = new Org.BouncyCastle.Security.JksStore();
        using (var ms = new System.IO.MemoryStream(updatedJksBytes))
        {
            jksStore.Load(ms, "storepassword".ToCharArray());
        }

        var aliases = jksStore.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("testcert", aliases);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_RemoveCertFromNativeJks_PreservesJksFormat()
    {
        // Arrange - Create a native JKS secret with multiple certificates
        var secretName = $"test-jks-format-remove-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert 1 Remove Format");
        var cert2 = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "Cert 2 Remove Format");

        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "cert1", (cert1.Certificate, cert1.KeyPair) },
            { "cert2", (cert2.Certificate, cert2.KeyPair) }
        };

        var existingJks = CertificateTestHelper.GenerateJksWithMultipleEntries(entries, "storepassword");

        // Verify initial JKS is in native JKS format
        Assert.True(CertificateTestHelper.IsNativeJksFormat(existingJks), "Initial JKS should be in native JKS format");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", existingJks }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Create Management Remove job config
        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SJKS",
            OperationType = CertStoreOperationType.Remove,
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
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var management = new Management(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // Verify the updated secret is still in native JKS format
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        var updatedJksBytes = updatedSecret.Data["keystore.jks"];

        Assert.True(CertificateTestHelper.IsNativeJksFormat(updatedJksBytes),
            $"Updated keystore should remain in native JKS format after certificate removal but got magic bytes: 0x{updatedJksBytes[0]:X2}{updatedJksBytes[1]:X2}{updatedJksBytes[2]:X2}{updatedJksBytes[3]:X2}");
        Assert.False(CertificateTestHelper.IsPkcs12Format(updatedJksBytes),
            "Updated keystore should NOT be in PKCS12 format");

        // Verify cert1 was removed and cert2 remains
        var jksStore = new Org.BouncyCastle.Security.JksStore();
        using (var ms = new System.IO.MemoryStream(updatedJksBytes))
        {
            jksStore.Load(ms, "storepassword".ToCharArray());
        }

        var aliases = jksStore.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("cert2", aliases);
        Assert.DoesNotContain("cert1", aliases);
    }

    #endregion
}
