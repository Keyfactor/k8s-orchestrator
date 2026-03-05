// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using k8s;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.K8S.Tests.Attributes;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Keyfactor.Orchestrators.K8S.Tests.Integration.Fixtures;
using Org.BouncyCastle.Pkcs;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;
using CertificateUtilities = Keyfactor.Extensions.Orchestrator.K8S.Utilities.CertificateUtilities;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration;

/// <summary>
/// Integration tests for KubeCertificateManagerClient directly against a real Kubernetes cluster.
/// Tests are gated by RUN_INTEGRATION_TESTS=true environment variable.
/// </summary>
[Collection("KubeClient Integration Tests")]
public class KubeClientIntegrationTests : IntegrationTestBase
{
    protected override string BaseTestNamespace => "keyfactor-kubeclient-integration-tests";

    public KubeClientIntegrationTests(IntegrationTestFixture fixture) : base(fixture)
    {
    }

    private KubeCertificateManagerClient CreateClient()
    {
        return new KubeCertificateManagerClient(KubeconfigJson);
    }

    #region Constructor and Connection Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void Constructor_ValidKubeconfig_CreatesClient()
    {
        var client = CreateClient();

        Assert.NotNull(client);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void GetHost_ReturnsClusterUrl()
    {
        var client = CreateClient();

        var host = client.GetHost();

        Assert.NotNull(host);
        Assert.StartsWith("https://", host);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void GetClusterName_ReturnsClusterName()
    {
        var client = CreateClient();

        var clusterName = client.GetClusterName();

        Assert.NotNull(clusterName);
        Assert.NotEmpty(clusterName);
    }

    #endregion

    #region Secret CRUD Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task GetCertificateStoreSecret_ExistingSecret_ReturnsSecret()
    {
        // Arrange
        var secretName = $"test-get-secret-{TestRunId}";
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test Get Secret");
        var certPem = ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        }, TestNamespace);
        TrackSecret(secretName);

        var client = CreateClient();

        // Act
        var secret = client.GetCertificateStoreSecret(secretName, TestNamespace);

        // Assert
        Assert.NotNull(secret);
        Assert.Equal(secretName, secret.Metadata.Name);
        Assert.True(secret.Data.ContainsKey("tls.crt"));
        Assert.True(secret.Data.ContainsKey("tls.key"));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void GetCertificateStoreSecret_NonExistent_ThrowsStoreNotFoundException()
    {
        var client = CreateClient();

        Assert.Throws<StoreNotFoundException>(() =>
            client.GetCertificateStoreSecret("nonexistent-secret-xyz", TestNamespace));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task CreateOrUpdateCertificateStoreSecret_PEM_CreatesNewSecret()
    {
        // Arrange
        var secretName = $"test-create-pem-{TestRunId}";
        TrackSecret(secretName);
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test Create PEM");
        var certPem = ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var client = CreateClient();

        // Act
        var result = client.CreateOrUpdateCertificateStoreSecret(
            keyPem, certPem, new List<string>(),
            secretName, TestNamespace, "opaque");

        // Assert
        Assert.NotNull(result);
        var fetched = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(fetched);
        var fetchedCert = Encoding.UTF8.GetString(fetched.Data["tls.crt"]);
        Assert.Contains("BEGIN CERTIFICATE", fetchedCert);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task CreateOrUpdateCertificateStoreSecret_PEM_UpdatesExistingSecret()
    {
        // Arrange - create initial secret
        var secretName = $"test-update-pem-{TestRunId}";
        var certInfo1 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test Update PEM 1");
        var certPem1 = ConvertCertificateToPem(certInfo1.Certificate);
        var keyPem1 = ConvertPrivateKeyToPem(certInfo1.KeyPair.Private);

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem1) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem1) }
            }
        }, TestNamespace);
        TrackSecret(secretName);

        // Arrange - new cert to update with
        var certInfo2 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test Update PEM 2");
        var certPem2 = ConvertCertificateToPem(certInfo2.Certificate);
        var keyPem2 = ConvertPrivateKeyToPem(certInfo2.KeyPair.Private);

        var client = CreateClient();

        // Act
        var result = client.CreateOrUpdateCertificateStoreSecret(
            keyPem2, certPem2, new List<string>(),
            secretName, TestNamespace, "opaque",
            overwrite: true);

        // Assert
        Assert.NotNull(result);
        var fetched = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        var fetchedCert = Encoding.UTF8.GetString(fetched.Data["tls.crt"]);
        Assert.Contains("BEGIN CERTIFICATE", fetchedCert);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task CreateOrUpdateCertificateStoreSecret_TLS_CreatesNewSecret()
    {
        // Arrange
        var secretName = $"test-create-tls-{TestRunId}";
        TrackSecret(secretName);
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test Create TLS");
        var certPem = ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var client = CreateClient();

        // Act
        var result = client.CreateOrUpdateCertificateStoreSecret(
            keyPem, certPem, new List<string>(),
            secretName, TestNamespace, "tls_secret");

        // Assert
        Assert.NotNull(result);
        var fetched = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(fetched);
        Assert.Equal("kubernetes.io/tls", fetched.Type);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task CreateOrUpdateCertificateStoreSecret_WithChain_StoresChainSeparately()
    {
        // Arrange
        var secretName = $"test-create-chain-{TestRunId}";
        TrackSecret(secretName);
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.EcP256);
        var certPem = ConvertCertificateToPem(chain[0].Certificate);
        var keyPem = ConvertPrivateKeyToPem(chain[0].KeyPair.Private);
        var chainPem = new List<string>
        {
            ConvertCertificateToPem(chain[1].Certificate),
            ConvertCertificateToPem(chain[2].Certificate)
        };

        var client = CreateClient();

        // Act
        var result = client.CreateOrUpdateCertificateStoreSecret(
            keyPem, certPem, chainPem,
            secretName, TestNamespace, "opaque",
            separateChain: true, includeChain: true);

        // Assert
        Assert.NotNull(result);
        var fetched = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.True(fetched.Data.ContainsKey("tls.crt"));
        Assert.True(fetched.Data.ContainsKey("ca.crt"));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task DeleteCertificateStoreSecret_ExistingSecret_DeletesSuccessfully()
    {
        // Arrange
        var secretName = $"test-delete-secret-{TestRunId}";
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test Delete");
        var certPem = ConvertCertificateToPem(certInfo.Certificate);

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
            }
        }, TestNamespace);
        // Don't track — we're deleting it

        var client = CreateClient();

        // Act
        var result = client.DeleteCertificateStoreSecret(secretName, TestNamespace, "opaque", "");

        // Assert
        Assert.NotNull(result);
    }

    #endregion

    #region PKCS12 Secret Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task GetPkcs12Secret_ExistingSecret_ReturnsSecretWithInventory()
    {
        // Arrange
        var secretName = $"test-get-p12-{TestRunId}";
        var p12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.EcP256, "testpwd", "test-alias");

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.p12", p12Bytes }
            }
        }, TestNamespace);
        TrackSecret(secretName);

        var client = CreateClient();

        // Act
        var result = client.GetPkcs12Secret(secretName, TestNamespace, "testpwd");

        // Assert
        Assert.NotNull(result.Secret);
        Assert.NotEmpty(result.Inventory);
        Assert.True(result.Inventory.ContainsKey("keystore.p12"));
        Assert.Equal($"{TestNamespace}/secrets/{secretName}", result.SecretPath);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void GetPkcs12Secret_NonExistent_ThrowsStoreNotFoundException()
    {
        var client = CreateClient();

        Assert.Throws<StoreNotFoundException>(() =>
            client.GetPkcs12Secret("nonexistent-p12-xyz", TestNamespace, "testpwd"));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task GetPkcs12Secret_CustomAllowedKeys_FiltersCorrectly()
    {
        // Arrange
        var secretName = $"test-p12-filter-{TestRunId}";
        var p12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.EcP256, "testpwd");

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.p12", p12Bytes },
                { "config.yaml", Encoding.UTF8.GetBytes("not-a-keystore") }
            }
        }, TestNamespace);
        TrackSecret(secretName);

        var client = CreateClient();

        // Act
        var result = client.GetPkcs12Secret(secretName, TestNamespace, "testpwd",
            allowedKeys: new List<string> { "p12" });

        // Assert
        Assert.Single(result.Inventory);
        Assert.True(result.Inventory.ContainsKey("keystore.p12"));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task CreateOrUpdatePkcs12Secret_CreatesNewSecret()
    {
        // Arrange
        var secretName = $"test-create-p12-{TestRunId}";
        TrackSecret(secretName);
        var p12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.EcP256, "testpwd");

        var client = CreateClient();

        var pkcs12Data = new KubeCertificateManagerClient.Pkcs12Secret
        {
            Secret = null,
            SecretPath = $"{TestNamespace}/secrets/{secretName}",
            SecretFieldName = "keystore.p12",
            Password = "testpwd",
            Inventory = new Dictionary<string, byte[]>
            {
                { "keystore.p12", p12Bytes }
            }
        };

        // Act
        var result = client.CreateOrUpdatePkcs12Secret(pkcs12Data, secretName, TestNamespace);

        // Assert
        Assert.NotNull(result);
        var fetched = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.True(fetched.Data.ContainsKey("keystore.p12"));
    }

    #endregion

    #region JKS Secret Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task GetJksSecret_ExistingSecret_ReturnsSecretWithInventory()
    {
        // Arrange
        var secretName = $"test-get-jks-{TestRunId}";
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test JKS Get");
        var jksBytes = GenerateJks(certInfo.Certificate, certInfo.KeyPair, "testpwd", "test-alias");

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.jks", jksBytes }
            }
        }, TestNamespace);
        TrackSecret(secretName);

        var client = CreateClient();

        // Act
        var result = client.GetJksSecret(secretName, TestNamespace, "testpwd");

        // Assert
        Assert.NotNull(result.Secret);
        Assert.NotEmpty(result.Inventory);
        Assert.True(result.Inventory.ContainsKey("keystore.jks"));
        Assert.Equal($"{TestNamespace}/secrets/{secretName}", result.SecretPath);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void GetJksSecret_NonExistent_ThrowsStoreNotFoundException()
    {
        var client = CreateClient();

        Assert.Throws<StoreNotFoundException>(() =>
            client.GetJksSecret("nonexistent-jks-xyz", TestNamespace, "testpwd"));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task GetJksSecret_EmptyData_ThrowsInvalidK8SSecretException()
    {
        // Arrange
        var secretName = $"test-jks-empty-{TestRunId}";
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque"
            // No Data
        }, TestNamespace);
        TrackSecret(secretName);

        var client = CreateClient();

        // Act & Assert
        Assert.Throws<InvalidK8SSecretException>(() =>
            client.GetJksSecret(secretName, TestNamespace, "testpwd"));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task CreateOrUpdateJksSecret_CreatesNewSecret()
    {
        // Arrange
        var secretName = $"test-create-jks-{TestRunId}";
        TrackSecret(secretName);
        var certInfoJks = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test JKS Create");
        var jksBytes = GenerateJks(certInfoJks.Certificate, certInfoJks.KeyPair, "testpwd", "test-alias");

        var client = CreateClient();

        var jksData = new KubeCertificateManagerClient.JksSecret
        {
            Secret = null,
            SecretPath = $"{TestNamespace}/secrets/{secretName}",
            SecretFieldName = "keystore.jks",
            Password = "testpwd",
            Inventory = new Dictionary<string, byte[]>
            {
                { "keystore.jks", jksBytes }
            }
        };

        // Act
        var result = client.CreateOrUpdateJksSecret(jksData, secretName, TestNamespace);

        // Assert
        Assert.NotNull(result);
        var fetched = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.True(fetched.Data.ContainsKey("keystore.jks"));
    }

    #endregion

    #region Buddy Password Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task CreateOrUpdateBuddyPass_CreatesPasswordSecret()
    {
        // Arrange
        var mainSecretName = $"test-buddy-main-{TestRunId}";
        var buddySecretName = $"test-buddy-pass-{TestRunId}";
        var passwordSecretPath = $"{TestNamespace}/{buddySecretName}";
        TrackSecret(buddySecretName);

        var client = CreateClient();

        // Act
        var result = client.CreateOrUpdateBuddyPass(
            mainSecretName, "password", passwordSecretPath, "my-secret-password");

        // Assert
        Assert.NotNull(result);
        var fetched = await K8sClient.CoreV1.ReadNamespacedSecretAsync(buddySecretName, TestNamespace);
        Assert.NotNull(fetched);
        var storedPassword = Encoding.UTF8.GetString(fetched.Data["password"]);
        Assert.Equal("my-secret-password", storedPassword);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task CreateOrUpdateBuddyPass_UpdatesExistingPasswordSecret()
    {
        // Arrange - create initial password secret
        var mainSecretName = $"test-buddy-upd-{TestRunId}";
        var buddySecretName = $"test-buddy-pass2-{TestRunId}";
        var passwordSecretPath = $"{TestNamespace}/{buddySecretName}";

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(buddySecretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "password", Encoding.UTF8.GetBytes("old-password") }
            }
        }, TestNamespace);
        TrackSecret(buddySecretName);

        var client = CreateClient();

        // Act
        client.CreateOrUpdateBuddyPass(
            mainSecretName, "password", passwordSecretPath, "new-password");

        // Assert
        var fetched = await K8sClient.CoreV1.ReadNamespacedSecretAsync(buddySecretName, TestNamespace);
        var storedPassword = Encoding.UTF8.GetString(fetched.Data["password"]);
        Assert.Equal("new-password", storedPassword);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task ReadBuddyPass_ExistingSecret_ReturnsSecret()
    {
        // Arrange
        var mainSecretName = $"test-read-buddy-{TestRunId}";
        var buddySecretName = $"test-read-bpass-{TestRunId}";
        var passwordSecretPath = $"{TestNamespace}/{buddySecretName}";

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(buddySecretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "password", Encoding.UTF8.GetBytes("my-password") }
            }
        }, TestNamespace);
        TrackSecret(buddySecretName);

        // Also create the main secret (ReadBuddyPass uses mainSecretName for the lookup)
        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(mainSecretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "password", Encoding.UTF8.GetBytes("my-password") }
            }
        }, TestNamespace);
        TrackSecret(mainSecretName);

        var client = CreateClient();

        // Act
        var result = client.ReadBuddyPass(mainSecretName, passwordSecretPath);

        // Assert
        Assert.NotNull(result);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void ReadBuddyPass_NonExistent_ThrowsStoreNotFoundException()
    {
        var client = CreateClient();

        Assert.Throws<StoreNotFoundException>(() =>
            client.ReadBuddyPass("nonexistent-main", $"{TestNamespace}/nonexistent-buddy-xyz"));
    }

    #endregion

    #region Discovery Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task DiscoverSecrets_OpaqueType_FindsSecretsInNamespace()
    {
        // Arrange
        var secretName = $"test-discover-opaque-{TestRunId}";
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test Discover Opaque");
        var certPem = ConvertCertificateToPem(certInfo.Certificate);

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
            }
        }, TestNamespace);
        TrackSecret(secretName);

        var client = CreateClient();

        // Act
        var locations = client.DiscoverSecrets(
            new[] { "tls.crt", "tls.key", "ca.crt" },
            "opaque",
            TestNamespace);

        // Assert
        Assert.NotNull(locations);
        Assert.NotEmpty(locations);
        Assert.Contains(locations, l => l.Contains(secretName));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task DiscoverSecrets_TlsType_FindsTlsSecrets()
    {
        // Arrange
        var secretName = $"test-discover-tls-{TestRunId}";
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test Discover TLS");
        var certPem = ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        }, TestNamespace);
        TrackSecret(secretName);

        var client = CreateClient();

        // Act
        var locations = client.DiscoverSecrets(
            new[] { "tls.crt", "tls.key" },
            "tls",
            TestNamespace);

        // Assert
        Assert.NotNull(locations);
        Assert.NotEmpty(locations);
        Assert.Contains(locations, l => l.Contains(secretName));
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void DiscoverSecrets_ClusterType_ReturnsClusterName()
    {
        var client = CreateClient();

        // Act
        var locations = client.DiscoverSecrets(
            Array.Empty<string>(),
            "cluster");

        // Assert
        Assert.Single(locations);
        Assert.NotEmpty(locations[0]);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void DiscoverSecrets_NamespaceType_ReturnsNamespaceLocations()
    {
        var client = CreateClient();

        // Act
        var locations = client.DiscoverSecrets(
            Array.Empty<string>(),
            "namespace",
            TestNamespace);

        // Assert
        Assert.NotNull(locations);
        Assert.NotEmpty(locations);
        Assert.Contains(locations, l => l.Contains(TestNamespace));
    }

    #endregion

    #region PKCS12 Store Management Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task CreateOrUpdateCertificateStoreSecret_PKCS12_CreatesNewStore()
    {
        // Arrange
        var secretName = $"test-create-p12store-{TestRunId}";
        TrackSecret(secretName);
        var p12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.EcP256, "testpwd");
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test PKCS12 Store");

        var jobCert = new K8SJobCertificate
        {
            Alias = "test-alias",
            CertBytes = p12Bytes,
            Pkcs12 = p12Bytes,
            Password = "testpwd"
        };

        var client = CreateClient();

        // Act
        var result = client.CreateOrUpdateCertificateStoreSecret(
            jobCert, secretName, TestNamespace, "pkcs12",
            overwrite: true, password: "testpwd");

        // Assert
        Assert.NotNull(result);
        var fetched = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.NotNull(fetched);
        Assert.Equal("Opaque", fetched.Type);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task UpdatePKCS12SecretStore_AddsNewCertToExistingStore()
    {
        // Arrange - create initial secret with PKCS12 data
        var secretName = $"test-update-p12store-{TestRunId}";
        var p12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.EcP256, "testpwd", "initial-alias");

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.p12", p12Bytes }
            }
        }, TestNamespace);
        TrackSecret(secretName);

        // New cert to add
        var newP12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.Rsa2048, "testpwd", "new-alias");
        var jobCert = new K8SJobCertificate
        {
            Alias = "new-alias",
            CertBytes = newP12Bytes,
            Pkcs12 = newP12Bytes,
            Password = "testpwd"
        };

        var client = CreateClient();

        // Act
        var result = client.UpdatePKCS12SecretStore(
            jobCert, secretName, TestNamespace, "pkcs12",
            "keystore.p12", "testpwd", new V1Secret(),
            overwrite: false);

        // Assert
        Assert.NotNull(result);
        var fetched = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);
        Assert.True(fetched.Data.ContainsKey("keystore.p12"));

        // Verify the PKCS12 store has entries
        var store = new Pkcs12StoreBuilder().Build();
        using var ms = new System.IO.MemoryStream(fetched.Data["keystore.p12"]);
        store.Load(ms, "testpwd".ToCharArray());
        Assert.True(store.Count >= 1);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task RemoveFromPKCS12SecretStore_RemovesCertificateFromStore()
    {
        // Arrange - create secret with PKCS12 containing 2 entries
        var secretName = $"test-remove-p12-{TestRunId}";
        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Remove P12 Cert 1");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Remove P12 Cert 2");
        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate cert, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair)>
        {
            { "alias1", (cert1.Certificate, cert1.KeyPair) },
            { "alias2", (cert2.Certificate, cert2.KeyPair) }
        };
        var p12Bytes = GeneratePkcs12WithMultipleEntries(entries, "testpwd");

        await K8sClient.CoreV1.CreateNamespacedSecretAsync(new V1Secret
        {
            Metadata = CreateTestSecretMetadata(secretName),
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "keystore.p12", p12Bytes }
            }
        }, TestNamespace);
        TrackSecret(secretName);

        var jobCert = new K8SJobCertificate
        {
            Alias = "alias1",
            Password = "testpwd"
        };

        var client = CreateClient();

        // Act
        var result = client.RemoveFromPKCS12SecretStore(
            jobCert, secretName, TestNamespace, "pkcs12",
            "keystore.p12", "testpwd", new V1Secret());

        // Assert
        Assert.NotNull(result);
        var fetched = await K8sClient.CoreV1.ReadNamespacedSecretAsync(secretName, TestNamespace);

        var store = new Pkcs12StoreBuilder().Build();
        using var ms = new System.IO.MemoryStream(fetched.Data["keystore.p12"]);
        store.Load(ms, "testpwd".ToCharArray());
        // alias1 should be removed
        Assert.False(store.ContainsAlias("alias1"));
    }

    #endregion

    #region CreatePKCS12Collection Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void CreatePKCS12Collection_ValidPkcs12_ReturnsStore()
    {
        var client = CreateClient();
        var p12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.EcP256, "pwd123");

        // Act
        var store = client.CreatePKCS12Collection(p12Bytes, "pwd123", "newpwd");

        // Assert
        Assert.NotNull(store);
        Assert.True(store.Count > 0);
    }

    #endregion

    #region Certificate Operations (Delegated) Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void ReadPemCertificate_ValidPem_ReturnsCertificate()
    {
        var client = CreateClient();
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test PEM Read");
        var certPem = ConvertCertificateToPem(certInfo.Certificate);

        // Act
        var result = client.ReadPemCertificate(certPem);

        // Assert
        Assert.NotNull(result);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void ReadDerCertificate_ValidDer_ReturnsCertificate()
    {
        var client = CreateClient();
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test DER Read");
        var derB64 = Convert.ToBase64String(certInfo.Certificate.GetEncoded());

        // Act
        var result = client.ReadDerCertificate(derB64);

        // Assert
        Assert.NotNull(result);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void ConvertToPem_ValidCertificate_ReturnsPemString()
    {
        var client = CreateClient();
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Test ConvertToPem");

        // Act
        var pem = client.ConvertToPem(certInfo.Certificate);

        // Assert
        Assert.Contains("BEGIN CERTIFICATE", pem);
        Assert.Contains("END CERTIFICATE", pem);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void ExtractPrivateKeyAsPem_ValidPkcs12_ReturnsKey()
    {
        var client = CreateClient();
        var p12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.EcP256, "testpwd");
        var store = new Pkcs12StoreBuilder().Build();
        using var ms = new System.IO.MemoryStream(p12Bytes);
        store.Load(ms, "testpwd".ToCharArray());

        // Act
        var keyPem = client.ExtractPrivateKeyAsPem(store, "testpwd");

        // Assert
        Assert.Contains("PRIVATE KEY", keyPem);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void LoadCertificateChain_ValidPem_ReturnsChain()
    {
        var client = CreateClient();
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.EcP256);
        var chainPem = string.Join("\n",
            chain.Select(c => ConvertCertificateToPem(c.Certificate)));

        // Act
        var result = client.LoadCertificateChain(chainPem);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(3, result.Count);
    }

    #endregion

    #region CSR Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void GenerateCertificateRequest_ValidParams_ReturnsCsrObject()
    {
        var client = CreateClient();

        // Act
        var csr = client.GenerateCertificateRequest(
            "CN=test-csr",
            new[] { "test.example.com" },
            new[] { System.Net.IPAddress.Loopback });

        // Assert
        Assert.NotNull(csr.Csr);
        Assert.Contains("BEGIN CERTIFICATE REQUEST", csr.Csr);
        Assert.NotNull(csr.PrivateKey);
        Assert.Contains("BEGIN PRIVATE KEY", csr.PrivateKey);
        Assert.NotNull(csr.PublicKey);
        Assert.Contains("BEGIN PUBLIC KEY", csr.PublicKey);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void ListAllCertificateSigningRequests_ReturnsResults()
    {
        var client = CreateClient();

        // Act
        var results = client.ListAllCertificateSigningRequests();

        // Assert - should not throw, may return empty dict if no CSRs exist
        Assert.NotNull(results);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void DiscoverCertificates_ReturnsLocations()
    {
        var client = CreateClient();

        // Act
        var locations = client.DiscoverCertificates();

        // Assert - should not throw, may be empty if no signed CSRs exist
        Assert.NotNull(locations);
    }

    #endregion

    #region Placeholder Inventory Methods Tests

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void GetOpaqueSecretCertificateInventory_ReturnsEmptyList()
    {
        var client = CreateClient();

        var result = client.GetOpaqueSecretCertificateInventory();

        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public void GetTlsSecretCertificateInventory_ReturnsEmptyList()
    {
        var client = CreateClient();

        var result = client.GetTlsSecretCertificateInventory();

        Assert.NotNull(result);
        Assert.Empty(result);
    }

    #endregion
}
