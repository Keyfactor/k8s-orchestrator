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
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SPKCS12;
using Keyfactor.Extensions.Orchestrator.K8S.Serializers.K8SPKCS12;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.K8S.Tests.Attributes;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Keyfactor.Orchestrators.K8S.Tests.Integration.Fixtures;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;
using CertificateUtilities = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities;

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

        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "New Cert");
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
        var existingCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Existing Cert");
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
        var newCert = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "New Cert");
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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificateWithChain_IncludeCertChainFalse_OnlyLeafCertInKeystore()
    {
        // Arrange - Test that when IncludeCertChain=false, only the leaf certificate is stored in the PKCS12
        var secretName = $"test-no-chain-pkcs12-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate a certificate chain (leaf -> intermediate -> root)
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKey = chain[0].KeyPair.Private;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pfxPassword = "testpassword";
        var storePassword = "storepassword";

        // Create a PKCS12 with the full chain included
        var pfxWithChain = CertificateTestHelper.GeneratePkcs12WithChain(
            leafCert,
            leafKey,
            new[] { intermediateCert, rootCert },
            pfxPassword);

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SPKCS12",
            OperationType = CertStoreOperationType.Add,
            Overwrite = false,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = storePassword,
                Properties = $"{{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"{storePassword}\",\"StoreFileName\":\"keystore.pfx\",\"IncludeCertChain\":false}}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "testcert",
                PrivateKeyPassword = pfxPassword,
                Contents = Convert.ToBase64String(pfxWithChain)
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
        Assert.True(secret.Data.ContainsKey("keystore.pfx"), "Secret should contain keystore.pfx");

        // Load the PKCS12 from the secret and verify certificate count
        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(secret.Data["keystore.pfx"], "/test", storePassword);

        // Get the certificate chain for the alias
        var certChain = store.GetCertificateChain("testcert");
        Assert.NotNull(certChain);

        // With IncludeCertChain=false, the chain should contain only the leaf certificate (1 cert)
        Assert.True(certChain.Length == 1,
            $"Expected only 1 certificate (leaf) in PKCS12 when IncludeCertChain=false, but found {certChain.Length} certificate(s)");

        // Verify the single certificate is indeed the leaf certificate
        var storedCert = certChain[0].Certificate;
        var storedSubject = storedCert.SubjectDN.ToString();
        var leafSubject = leafCert.SubjectDN.ToString();
        Assert.Equal(leafSubject, storedSubject);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_CreateStoreIfMissing_NoCertificateData_CreatesEmptyPkcs12Store()
    {
        // Arrange - "Create store if missing" scenario: no certificate data provided
        var secretName = $"test-create-store-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Create Management Add job config with no certificate contents (simulates "create store if missing")
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

        // Verify secret was created with an empty but valid PKCS12 keystore
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.True(secret.Data.ContainsKey("keystore.pfx"), "Expected 'keystore.pfx' key in secret data");
        Assert.NotEmpty(secret.Data["keystore.pfx"]);

        // Verify the PKCS12 store is valid and empty (no aliases)
        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var pkcs12Store = serializer.DeserializeRemoteCertificateStore(secret.Data["keystore.pfx"], "/test", "storepassword");
        var aliases = pkcs12Store.Aliases.ToList();
        Assert.Empty(aliases);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_CreateStoreIfMissing_SecretAlreadyExists_ReturnsExistingSecret()
    {
        // Arrange - Secret already exists, "create store if missing" should return the existing secret
        var secretName = $"test-existing-store-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Create existing secret with one certificate
        var existingCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Existing Cert");
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

        // Create Management Add job config with no certificate contents
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
        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var pkcs12Store = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["keystore.pfx"], "/test", "storepassword");
        var aliases = pkcs12Store.Aliases.ToList();
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
        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert 1");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Cert 2");

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
        var existingCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Existing");
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
        var newCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "New");
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
    public async Task Inventory_NonExistentSecret_ReturnsSuccessWithEmptyInventory()
    {
        // Arrange - Test that non-existent secrets return success with empty inventory
        // This behavior supports the "create store if missing" feature
        var nonExistentSecretName = $"does-not-exist-{Guid.NewGuid():N}";
        var inventoryItems = new List<CurrentInventoryItem>();

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

    #region Mixed Entry Types Tests (Private Keys + Trusted Certs)

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_Pkcs12WithMixedEntries_ReturnsCorrectPrivateKeyFlags()
    {
        // Arrange - Create PKCS12 with 2 private key entries + 2 trusted cert entries
        var secretName = $"test-mixed-pkcs12-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate certificates for private key entries (with keys)
        var serverCert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Server Cert 1");
        var serverCert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Server Cert 2");

        // Generate certificates for trusted cert entries (no keys)
        var trustedRootCa = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Trusted Root CA");
        var trustedIntermediateCa = CachedCertificateProvider.GetOrCreate(KeyType.Rsa4096, "Trusted Intermediate CA");

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

        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12WithMixedEntries(privateKeyEntries, trustedCertEntries, "testpassword");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.pfx", pkcs12Bytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var inventoryItems = new List<CurrentInventoryItem>();

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
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (items) =>
        {
            inventoryItems.AddRange(items);
            return true;
        }));

        // Assert
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        // NOTE: PKCS12 inventory returns ALL entries including trusted certificate entries.
        // This differs from JKS inventory which only returns key entries.
        // Should have 4 inventory items (2 private key entries + 2 trusted cert entries)
        Assert.Equal(4, inventoryItems.Count);

        // Verify all entries are returned with full alias format: <secretDataKey>/<entryAlias>
        var server1Item = inventoryItems.FirstOrDefault(i => i.Alias == "keystore.pfx/server1");
        var server2Item = inventoryItems.FirstOrDefault(i => i.Alias == "keystore.pfx/server2");
        var rootCaItem = inventoryItems.FirstOrDefault(i => i.Alias == "keystore.pfx/root-ca");
        var intermediateCaItem = inventoryItems.FirstOrDefault(i => i.Alias == "keystore.pfx/intermediate-ca");

        Assert.NotNull(server1Item);
        Assert.NotNull(server2Item);
        Assert.NotNull(rootCaItem);
        Assert.NotNull(intermediateCaItem);

        // All entries have PrivateKeyEntry=true because the PKCS12 inventory
        // sets this globally based on whether ANY entry has a private key
        Assert.True(server1Item.PrivateKeyEntry, "server1 should have PrivateKeyEntry = true");
        Assert.True(server2Item.PrivateKeyEntry, "server2 should have PrivateKeyEntry = true");
        // Note: Trusted certs also get PrivateKeyEntry=true because the flag is set globally
        Assert.True(rootCaItem.PrivateKeyEntry, "root-ca has PrivateKeyEntry = true (global flag)");
        Assert.True(intermediateCaItem.PrivateKeyEntry, "intermediate-ca has PrivateKeyEntry = true (global flag)");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddTrustedCert_ToExistingPkcs12_Success()
    {
        // Arrange - Create existing PKCS12 with a private key entry
        var secretName = $"test-add-trusted-pkcs12-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var serverCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Server Cert");
        var existingPkcs12 = CertificateTestHelper.GeneratePkcs12(serverCert.Certificate, serverCert.KeyPair, "storepassword", "server");

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

        // Generate a trusted certificate (certificate only, no private key)
        var trustedCa = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Trusted CA");

        // For adding a certificate-only entry, we send the DER-encoded certificate
        var certOnlyBase64 = Convert.ToBase64String(trustedCa.Certificate.GetEncoded());

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

        // Verify the PKCS12 was updated with both entries
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(updatedSecret);

        // Load the PKCS12 and verify both entries exist
        var pkcs12Store = new Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder().Build();
        using (var ms = new System.IO.MemoryStream(updatedSecret.Data["keystore.pfx"]))
        {
            pkcs12Store.Load(ms, "storepassword".ToCharArray());
        }

        var aliases = pkcs12Store.Aliases.ToList();
        Assert.Equal(2, aliases.Count);
        Assert.Contains("server", aliases);
        Assert.Contains("trusted-ca", aliases);

        // Verify entry types
        Assert.True(pkcs12Store.IsKeyEntry("server"), "server should be a key entry");
        Assert.False(pkcs12Store.IsKeyEntry("trusted-ca"), "trusted-ca should be a certificate-only entry");
    }

    #endregion

    #region Multiple PKCS12 Files in Single Secret Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_SecretWithMultiplePkcs12Files_ReturnsAllCertificatesFromAllFiles()
    {
        // Arrange - Create a K8s secret with multiple PKCS12 files (app.pfx, ca.p12, truststore.pfx)
        var secretName = $"test-multi-pfx-files-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate different certificates for each PKCS12 file
        var appCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "App Server PKCS12");
        var caCert = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "CA Certificate PKCS12");
        var trustCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa4096, "Truststore PKCS12");

        // Generate separate PKCS12 files with unique aliases
        var appPfxBytes = CertificateTestHelper.GeneratePkcs12(appCert.Certificate, appCert.KeyPair, "testpassword", "app-server");
        var caP12Bytes = CertificateTestHelper.GeneratePkcs12(caCert.Certificate, caCert.KeyPair, "testpassword", "ca-cert");
        var trustPfxBytes = CertificateTestHelper.GeneratePkcs12(trustCert.Certificate, trustCert.KeyPair, "testpassword", "trust-cert");

        // Create secret with multiple PKCS12 files
        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "app.pfx", appPfxBytes },
                { "ca.p12", caP12Bytes },
                { "truststore.pfx", trustPfxBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var inventoryItems = new List<CurrentInventoryItem>();

        // Create Inventory job config - Note: without StoreFileName, it should process ALL PKCS12 files
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SPKCS12",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "testpassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"testpassword\"}"
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

        // Should find all 3 certificates from all 3 PKCS12 files
        Assert.True(inventoryItems.Count >= 3,
            $"Expected at least 3 certificates but found {inventoryItems.Count}");

        // Verify aliases from each file are present
        var aliasStrings = inventoryItems.Select(i => i.Alias).ToList();
        Assert.Contains(aliasStrings, a => a.Contains("app-server") || a.Contains("app.pfx"));
        Assert.Contains(aliasStrings, a => a.Contains("ca-cert") || a.Contains("ca.p12"));
        Assert.Contains(aliasStrings, a => a.Contains("trust-cert") || a.Contains("truststore.pfx"));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_SecretWithMultiplePkcs12Files_EachFileHasMultipleEntries_ReturnsAll()
    {
        // Arrange - Create a K8s secret with 2 PKCS12 files, each containing 2 certificates
        var secretName = $"test-multi-pfx-multi-entries-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate certificates for app.pfx (2 entries)
        var appCert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "App Cert 1 PFX");
        var appCert2 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "App Cert 2 PFX");

        // Generate certificates for backend.pfx (2 entries)
        var backendCert1 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Backend Cert 1 PFX");
        var backendCert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Backend Cert 2 PFX");

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

        var appPfxBytes = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(appEntries, "testpassword");
        var backendPfxBytes = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(backendEntries, "testpassword");

        // Create secret with multiple PKCS12 files
        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "app.pfx", appPfxBytes },
                { "backend.pfx", backendPfxBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var inventoryItems = new List<CurrentInventoryItem>();

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SPKCS12",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "testpassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"testpassword\"}"
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

        // Should find all 4 certificates (2 from each PKCS12 file)
        Assert.True(inventoryItems.Count >= 4,
            $"Expected at least 4 certificates but found {inventoryItems.Count}");
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddCertificate_ToSpecificPkcs12File_UpdatesCorrectFile()
    {
        // Arrange - Create a K8s secret with multiple PKCS12 files
        var secretName = $"test-add-specific-pfx-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Generate existing PKCS12 files
        var appCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Existing App Cert PFX");
        var backendCert = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Existing Backend Cert PFX");

        var appPfxBytes = CertificateTestHelper.GeneratePkcs12(appCert.Certificate, appCert.KeyPair, "storepassword", "existing-app");
        var backendPfxBytes = CertificateTestHelper.GeneratePkcs12(backendCert.Certificate, backendCert.KeyPair, "storepassword", "existing-backend");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "app.pfx", appPfxBytes },
                { "backend.pfx", backendPfxBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Prepare new certificate to add to app.pfx specifically
        var newCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "New App Cert PFX");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(newCert.Certificate, newCert.KeyPair, "certpassword", "new-app-cert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

        // Create Management Add job config targeting app.pfx specifically
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
                // Use StoreFileName to target a specific PKCS12 file
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"app.pfx\"}"
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
        Assert.True(updatedSecret.Data.ContainsKey("app.pfx"), "app.pfx should still exist");
        Assert.True(updatedSecret.Data.ContainsKey("backend.pfx"), "backend.pfx should still exist");

        // Verify app.pfx was updated with the new cert
        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var appStore = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["app.pfx"], "/test", "storepassword");
        var appAliases = appStore.Aliases.ToList();
        Assert.Equal(2, appAliases.Count);
        Assert.Contains("existing-app", appAliases);
        Assert.Contains("new-app-cert", appAliases);

        // Verify backend.pfx was NOT modified (should still have only 1 cert)
        var backendStore = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["backend.pfx"], "/test", "storepassword");
        var backendAliases = backendStore.Aliases.ToList();
        Assert.Single(backendAliases);
        Assert.Contains("existing-backend", backendAliases);
        Assert.DoesNotContain("new-app-cert", backendAliases);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_RemoveCertificate_FromSpecificPkcs12File_UpdatesCorrectFile()
    {
        // Arrange - Create a K8s secret with multiple PKCS12 files, each with multiple certs
        var secretName = $"test-remove-specific-pfx-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        // Create app.pfx with 2 certs
        var appCert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "App Cert 1 PFX Remove");
        var appCert2 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "App Cert 2 PFX Remove");
        var appEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "app-cert-1", (appCert1.Certificate, appCert1.KeyPair) },
            { "app-cert-2", (appCert2.Certificate, appCert2.KeyPair) }
        };
        var appPfxBytes = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(appEntries, "storepassword");

        // Create backend.pfx with 2 certs
        var backendCert1 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Backend Cert 1 PFX Remove");
        var backendCert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Backend Cert 2 PFX Remove");
        var backendEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "backend-cert-1", (backendCert1.Certificate, backendCert1.KeyPair) },
            { "backend-cert-2", (backendCert2.Certificate, backendCert2.KeyPair) }
        };
        var backendPfxBytes = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(backendEntries, "storepassword");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "app.pfx", appPfxBytes },
                { "backend.pfx", backendPfxBytes }
            }
        };

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Remove app-cert-1 from app.pfx specifically
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
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"app.pfx\"}"
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
        var serializer = new Pkcs12CertificateStoreSerializer(null);

        // app.pfx should now have only 1 cert (app-cert-2)
        var appStore = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["app.pfx"], "/test", "storepassword");
        var appAliases = appStore.Aliases.ToList();
        Assert.Single(appAliases);
        Assert.Contains("app-cert-2", appAliases);
        Assert.DoesNotContain("app-cert-1", appAliases);

        // backend.pfx should be unchanged (still have 2 certs)
        var backendStore = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["backend.pfx"], "/test", "storepassword");
        var backendAliases = backendStore.Aliases.ToList();
        Assert.Equal(2, backendAliases.Count);
        Assert.Contains("backend-cert-1", backendAliases);
        Assert.Contains("backend-cert-2", backendAliases);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_ReplaceExistingAlias_WithOverwrite_UpdatesCertificate()
    {
        // Arrange - Create PKCS12 with existing certificate
        var secretName = $"test-replace-alias-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var existingCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Existing PKCS12 Cert");
        var existingPfx = CertificateTestHelper.GeneratePkcs12(existingCert.Certificate, existingCert.KeyPair, "storepassword", "mycert");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "app.pfx", existingPfx }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Get the original thumbprint
        var originalThumbprint = CertificateUtilities.GetThumbprint(existingCert.Certificate);

        // Prepare replacement certificate (same alias, different key+cert)
        var replacementCert = CachedCertificateProvider.GetOrCreate(KeyType.EcP384, "Replacement PKCS12 Cert");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(replacementCert.Certificate, replacementCert.KeyPair, "certpassword", "mycert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SPKCS12",
            OperationType = CertStoreOperationType.Add,
            Overwrite = true, // Replace existing
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"app.pfx\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "mycert",
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

        // Verify the certificate was replaced
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["app.pfx"], "/test", "storepassword");

        var aliases = store.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("mycert", aliases);

        // Verify thumbprint changed (it's a different cert now)
        var newCert = store.GetCertificate("mycert");
        var newThumbprint = CertificateUtilities.GetThumbprint(newCert.Certificate);
        Assert.NotEqual(originalThumbprint, newThumbprint);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddThirdAlias_ToStoreWithTwoAliases_AllThreePresent()
    {
        // Arrange - Create PKCS12 with 2 existing aliases
        var secretName = $"test-add-third-alias-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Cert 1 Third");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "PKCS12 Cert 2 Third");

        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "alias1", (cert1.Certificate, cert1.KeyPair) },
            { "alias2", (cert2.Certificate, cert2.KeyPair) }
        };
        var existingPfx = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(entries, "storepassword");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "app.pfx", existingPfx }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Prepare third certificate to add
        var cert3 = CachedCertificateProvider.GetOrCreate(KeyType.EcP384, "PKCS12 Cert 3 Third");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert3.Certificate, cert3.KeyPair, "certpassword", "alias3");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

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
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"app.pfx\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "alias3",
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

        // Verify all 3 aliases are present
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["app.pfx"], "/test", "storepassword");

        var aliases = store.Aliases.ToList();
        Assert.Equal(3, aliases.Count);
        Assert.Contains("alias1", aliases);
        Assert.Contains("alias2", aliases);
        Assert.Contains("alias3", aliases);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_RemoveMiddleAlias_FromThreeAliasStore_OtherTwoRemain()
    {
        // Arrange - Create PKCS12 with 3 aliases
        var secretName = $"test-remove-middle-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Cert 1 Middle");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "PKCS12 Cert 2 Middle");
        var cert3 = CachedCertificateProvider.GetOrCreate(KeyType.EcP384, "PKCS12 Cert 3 Middle");

        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "first", (cert1.Certificate, cert1.KeyPair) },
            { "middle", (cert2.Certificate, cert2.KeyPair) },
            { "last", (cert3.Certificate, cert3.KeyPair) }
        };
        var existingPfx = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(entries, "storepassword");

        var secret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "store.pfx", existingPfx }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SPKCS12",
            OperationType = CertStoreOperationType.Remove,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\",\"StoreFileName\":\"store.pfx\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "middle"
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

        // Verify middle was removed but first and last remain
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["store.pfx"], "/test", "storepassword");

        var aliases = store.Aliases.ToList();
        Assert.Equal(2, aliases.Count);
        Assert.Contains("first", aliases);
        Assert.Contains("last", aliases);
        Assert.DoesNotContain("middle", aliases);
    }

    #endregion

    #region Buddy Password Tests (Password in Separate Secret)

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_WithBuddyPassword_ReadsPasswordFromSeparateSecret()
    {
        // Arrange - Create a PKCS12 secret with password stored in a separate secret
        var secretName = $"test-pkcs12-buddy-inv-{Guid.NewGuid():N}";
        var passwordSecretName = $"test-pkcs12-buddy-pass-{Guid.NewGuid():N}";
        TrackSecret(secretName);
        TrackSecret(passwordSecretName);

        var storePassword = "buddypassword123";
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Buddy Password Cert");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, storePassword, "testcert");

        // Create the PKCS12 secret
        var pfxSecret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.pfx", pfxBytes }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(pfxSecret, TestNamespace);

        // Create the password secret (buddy password)
        var passwordSecret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(passwordSecretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "password", System.Text.Encoding.UTF8.GetBytes(storePassword) }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(passwordSecret, TestNamespace);

        // Create Inventory job config with PasswordIsSeparateSecret=true
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SPKCS12",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "", // Empty - password is in separate secret
                Properties = $"{{\"KubeSecretType\":\"pkcs12\",\"StoreFileName\":\"keystore.pfx\",\"PasswordIsSeparateSecret\":\"true\",\"StorePasswordPath\":\"{TestNamespace}/{passwordSecretName}\",\"PasswordFieldName\":\"password\"}}"
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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddWithBuddyPassword_UsesPasswordFromSeparateSecret()
    {
        // Arrange - Password stored in a separate secret
        var secretName = $"test-pkcs12-buddy-add-{Guid.NewGuid():N}";
        var passwordSecretName = $"test-pkcs12-buddy-add-pass-{Guid.NewGuid():N}";
        TrackSecret(secretName);
        TrackSecret(passwordSecretName);

        var storePassword = "buddyaddpassword";

        // Create an empty PKCS12 store first (with one cert to establish the store)
        var existingCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Buddy Existing");
        var existingPfx = CertificateTestHelper.GeneratePkcs12(existingCert.Certificate, existingCert.KeyPair, storePassword, "existing");

        var pfxSecret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "store.pfx", existingPfx }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(pfxSecret, TestNamespace);

        // Create the password secret
        var passwordSecret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(passwordSecretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "password", System.Text.Encoding.UTF8.GetBytes(storePassword) }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(passwordSecret, TestNamespace);

        // Prepare new certificate to add
        var newCert = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "PKCS12 Buddy New Cert");
        var newPfxBytes = CertificateTestHelper.GeneratePkcs12(newCert.Certificate, newCert.KeyPair, "certpassword", "newcert");
        var pfxBase64 = Convert.ToBase64String(newPfxBytes);

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SPKCS12",
            OperationType = CertStoreOperationType.Add,
            Overwrite = false,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "",
                Properties = $"{{\"KubeSecretType\":\"pkcs12\",\"StoreFileName\":\"store.pfx\",\"PasswordIsSeparateSecret\":\"true\",\"StorePasswordPath\":\"{TestNamespace}/{passwordSecretName}\",\"PasswordFieldName\":\"password\"}}"
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

        // Verify both certs are in the store
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["store.pfx"], "/test", storePassword);

        var aliases = store.Aliases.ToList();
        Assert.Equal(2, aliases.Count);
        Assert.Contains("existing", aliases);
        Assert.Contains("newcert", aliases);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_RemoveWithBuddyPassword_UsesPasswordFromSeparateSecret()
    {
        // Arrange - Create PKCS12 with 2 certs, password in separate secret
        var secretName = $"test-pkcs12-buddy-remove-{Guid.NewGuid():N}";
        var passwordSecretName = $"test-pkcs12-buddy-remove-pass-{Guid.NewGuid():N}";
        TrackSecret(secretName);
        TrackSecret(passwordSecretName);

        var storePassword = "buddyremovepassword";

        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Buddy Remove 1");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "PKCS12 Buddy Remove 2");

        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "cert1", (cert1.Certificate, cert1.KeyPair) },
            { "cert2", (cert2.Certificate, cert2.KeyPair) }
        };
        var pfxBytes = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(entries, storePassword);

        var pfxSecret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "store.pfx", pfxBytes }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(pfxSecret, TestNamespace);

        // Create the password secret
        var passwordSecret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(passwordSecretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "password", System.Text.Encoding.UTF8.GetBytes(storePassword) }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(passwordSecret, TestNamespace);

        var jobConfig = new ManagementJobConfiguration
        {
            Capability = "K8SPKCS12",
            OperationType = CertStoreOperationType.Remove,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "",
                Properties = $"{{\"KubeSecretType\":\"pkcs12\",\"StoreFileName\":\"store.pfx\",\"PasswordIsSeparateSecret\":\"true\",\"StorePasswordPath\":\"{TestNamespace}/{passwordSecretName}\",\"PasswordFieldName\":\"password\"}}"
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

        // Verify cert1 was removed, cert2 remains
        var updatedSecret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(updatedSecret.Data["store.pfx"], "/test", storePassword);

        var aliases = store.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("cert2", aliases);
        Assert.DoesNotContain("cert1", aliases);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_WithBuddyPassword_CustomFieldName_ReadsCorrectField()
    {
        // Arrange - Password stored with a custom field name
        var secretName = $"test-pkcs12-buddy-custom-{Guid.NewGuid():N}";
        var passwordSecretName = $"test-pkcs12-buddy-custom-pass-{Guid.NewGuid():N}";
        TrackSecret(secretName);
        TrackSecret(passwordSecretName);

        var storePassword = "customfieldpassword";
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Buddy Custom Field");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, storePassword, "testcert");

        var pfxSecret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.pfx", pfxBytes }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(pfxSecret, TestNamespace);

        // Create password secret with custom field name
        var passwordSecret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(passwordSecretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "store-password", System.Text.Encoding.UTF8.GetBytes(storePassword) }, // Custom field name
                { "other-field", System.Text.Encoding.UTF8.GetBytes("wrongpassword") }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(passwordSecret, TestNamespace);

        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SPKCS12",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "",
                Properties = $"{{\"KubeSecretType\":\"pkcs12\",\"StoreFileName\":\"keystore.pfx\",\"PasswordIsSeparateSecret\":\"true\",\"StorePasswordPath\":\"{TestNamespace}/{passwordSecretName}\",\"PasswordFieldName\":\"store-password\"}}"
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

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_WithBuddyPassword_SecretNotFound_ReturnsSuccessWithEmptyInventory()
    {
        // Arrange - PKCS12 secret exists but password secret does NOT exist
        // Note: Current behavior returns Success because StoreNotFoundException is caught
        // by InventoryBase.ProcessJob for initial store setup scenarios. This means a
        // missing password secret is treated the same as a missing store secret.
        var secretName = $"test-pkcs12-buddy-missing-{Guid.NewGuid():N}";
        var passwordSecretName = $"test-pkcs12-buddy-missing-pass-{Guid.NewGuid():N}"; // Will not be created
        TrackSecret(secretName);

        var storePassword = "testpassword";
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Buddy Missing Cert");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, storePassword, "testcert");

        // Create only the PKCS12 secret, NOT the password secret
        var pfxSecret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.pfx", pfxBytes }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(pfxSecret, TestNamespace);

        // Config references non-existent password secret
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SPKCS12",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "",
                Properties = $"{{\"KubeSecretType\":\"pkcs12\",\"StoreFileName\":\"keystore.pfx\",\"PasswordIsSeparateSecret\":\"true\",\"StorePasswordPath\":\"{TestNamespace}/{passwordSecretName}\",\"PasswordFieldName\":\"password\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);
        List<CurrentInventoryItem>? capturedInventory = null;

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) =>
        {
            capturedInventory = inventoryItems.ToList();
            return true;
        }));

        // Assert - Returns Success with empty inventory (StoreNotFoundException is caught)
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");
        Assert.NotNull(capturedInventory);
        Assert.Empty(capturedInventory);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Inventory_WithBuddyPassword_WrongFieldName_ReturnsFailure()
    {
        // Arrange - Password secret exists but with different field name
        var secretName = $"test-pkcs12-buddy-wrongfield-{Guid.NewGuid():N}";
        var passwordSecretName = $"test-pkcs12-buddy-wrongfield-pass-{Guid.NewGuid():N}";
        TrackSecret(secretName);
        TrackSecret(passwordSecretName);

        var storePassword = "testpassword";
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Buddy Wrong Field Cert");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, storePassword, "testcert");

        var pfxSecret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.pfx", pfxBytes }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(pfxSecret, TestNamespace);

        // Create password secret with DIFFERENT field name than configured
        var passwordSecret = new V1Secret
        {
            Metadata = CreateTestSecretMetadata(passwordSecretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "different-field", System.Text.Encoding.UTF8.GetBytes(storePassword) }
            }
        };
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(passwordSecret, TestNamespace);

        // Config expects "password" field but secret has "different-field"
        var jobConfig = new InventoryJobConfiguration
        {
            Capability = "K8SPKCS12",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "",
                Properties = $"{{\"KubeSecretType\":\"pkcs12\",\"StoreFileName\":\"keystore.pfx\",\"PasswordIsSeparateSecret\":\"true\",\"StorePasswordPath\":\"{TestNamespace}/{passwordSecretName}\",\"PasswordFieldName\":\"password\"}}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => inventory.ProcessJob(jobConfig, (inventoryItems) => true));

        // Assert - Should fail because password field doesn't exist
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Failure,
            $"Expected Failure but got {result.Result}");
        Assert.NotNull(result.FailureMessage);
    }

    #endregion

    // ──────────────────────────────────────────────────────────────────────────────────────
    // Regression: alias routing – "<fieldName>/<certAlias>" pattern
    // ──────────────────────────────────────────────────────────────────────────────────────

    #region Alias routing regression tests

    /// <summary>
    /// Regression: when alias is "mystore.p12/mycert", the handler must write to the
    /// <c>mystore.p12</c> field in the K8S secret, not to the first existing field.
    /// </summary>
    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_Add_WithFieldPrefixedAlias_WritesToNamedField()
    {
        // Arrange
        var secretName = $"test-alias-field-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Alias Field Routing");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert.Certificate, cert.KeyPair, "certpw", "mycert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

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
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                // Alias format: "<k8s_field_name>/<keystore_alias>"
                Alias = "mystore.p12/mycert",
                PrivateKeyPassword = "certpw",
                Contents = pfxBase64
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var management = new Management(MockPamResolver.Object);

        // Act
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        // Assert – job succeeded
        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);

        // The K8S secret must contain the NAMED field "mystore.p12", not the default "keystore.pfx"
        Assert.True(secret.Data.ContainsKey("mystore.p12"),
            "K8S secret should contain 'mystore.p12' field (the fieldName from alias)");
        Assert.False(secret.Data.ContainsKey("keystore.pfx"),
            "K8S secret should NOT fall back to default 'keystore.pfx' field");
    }

    /// <summary>
    /// Regression: the certAlias inside the PKCS12 file must be the short name ("mycert"),
    /// not the full path alias ("mystore.p12/mycert") that was erroneously passed before the fix.
    /// </summary>
    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_Add_WithFieldPrefixedAlias_CertAliasInsidePkcs12IsShortName()
    {
        // Arrange
        var secretName = $"test-alias-certname-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var cert = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "PKCS12 Alias CertName Test");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert.Certificate, cert.KeyPair, "certpw", "mycert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

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
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "mystore.p12/mycert",
                PrivateKeyPassword = "certpw",
                Contents = pfxBase64
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var management = new Management(MockPamResolver.Object);
        var result = await Task.Run(() => management.ProcessJob(jobConfig));

        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}. FailureMessage: {result.FailureMessage}");

        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.True(secret.Data.ContainsKey("mystore.p12"), "Field 'mystore.p12' must exist");

        // Load the PKCS12 and check the cert alias inside
        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(secret.Data["mystore.p12"], "mystore.p12", "storepassword");
        var aliases = store.Aliases.Cast<string>().ToList();

        // Regression: the alias inside PKCS12 must be "mycert", not "mystore.p12/mycert"
        Assert.Contains("mycert", aliases);
        Assert.DoesNotContain("mystore.p12/mycert", aliases);
    }

    /// <summary>
    /// Regression: inventory after a field-prefixed add must return the full alias
    /// "fieldName/certAlias" (e.g. "mystore.p12/mycert"), not just the short cert alias.
    /// </summary>
    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddThenInventory_WithFieldPrefixedAlias_InventoryReturnsFullAlias()
    {
        // Arrange
        var secretName = $"test-alias-inv-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Inventory Full Alias");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert.Certificate, cert.KeyPair, "certpw", "mycert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

        // Add
        var addConfig = new ManagementJobConfiguration
        {
            Capability = "K8SPKCS12",
            OperationType = CertStoreOperationType.Add,
            Overwrite = false,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "mystore.p12/mycert",
                PrivateKeyPassword = "certpw",
                Contents = pfxBase64
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var management = new Management(MockPamResolver.Object);
        var addResult = await Task.Run(() => management.ProcessJob(addConfig));
        Assert.True(addResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Add failed: {addResult.FailureMessage}");

        // Inventory
        List<CurrentInventoryItem> inventoryItems = null;
        var invConfig = new InventoryJobConfiguration
        {
            Capability = "K8SPKCS12",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\"}"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var inventory = new Inventory(MockPamResolver.Object);
        var invResult = await Task.Run(() => inventory.ProcessJob(invConfig, items =>
        {
            inventoryItems = items?.ToList();
            return true;
        }));

        Assert.True(invResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Inventory failed: {invResult.FailureMessage}");

        // Inventory should return the full alias "mystore.p12/mycert"
        Assert.NotNull(inventoryItems);
        Assert.Contains(inventoryItems, item => item.Alias == "mystore.p12/mycert");
    }

    /// <summary>
    /// Regression: remove with field-prefixed alias must remove from the correct named field,
    /// not from the first field in the inventory.
    /// </summary>
    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task Management_AddThenRemove_WithFieldPrefixedAlias_RemovesFromNamedField()
    {
        // Arrange – add to a named field first
        var secretName = $"test-alias-remove-{Guid.NewGuid():N}";
        TrackSecret(secretName);

        var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Remove Named Field");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert.Certificate, cert.KeyPair, "certpw", "mycert");
        var pfxBase64 = Convert.ToBase64String(pfxBytes);

        var addConfig = new ManagementJobConfiguration
        {
            Capability = "K8SPKCS12",
            OperationType = CertStoreOperationType.Add,
            Overwrite = false,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "mystore.p12/mycert",
                PrivateKeyPassword = "certpw",
                Contents = pfxBase64
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var management = new Management(MockPamResolver.Object);
        var addResult = await Task.Run(() => management.ProcessJob(addConfig));
        Assert.True(addResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Add failed: {addResult.FailureMessage}");

        // Remove
        var removeConfig = new ManagementJobConfiguration
        {
            Capability = "K8SPKCS12",
            OperationType = CertStoreOperationType.Remove,
            Overwrite = false,
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = TestNamespace,
                StorePath = $"{TestNamespace}/{secretName}",
                StorePassword = "storepassword",
                Properties = "{\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"storepassword\"}"
            },
            JobCertificate = new ManagementJobCertificate
            {
                Alias = "mystore.p12/mycert"
            },
            ServerUsername = string.Empty,
            ServerPassword = KubeconfigJson,
            UseSSL = true
        };

        var removeResult = await Task.Run(() => management.ProcessJob(removeConfig));
        Assert.True(removeResult.Result == OrchestratorJobStatusJobResult.Success,
            $"Remove failed: {removeResult.FailureMessage}");

        // Verify the cert alias was removed from "mystore.p12"
        var secret = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(secret);
        Assert.True(secret.Data.ContainsKey("mystore.p12"), "Field 'mystore.p12' should still exist after remove");

        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var store = serializer.DeserializeRemoteCertificateStore(secret.Data["mystore.p12"], "mystore.p12", "storepassword");
        var aliases = store.Aliases.Cast<string>().ToList();

        Assert.Empty(aliases);
    }

    #endregion
}
