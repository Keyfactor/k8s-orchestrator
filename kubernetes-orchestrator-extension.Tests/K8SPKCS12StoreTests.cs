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
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SPKCS12;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Org.BouncyCastle.Pkcs;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests;

/// <summary>
/// Comprehensive unit tests for K8SPKCS12 store type operations.
/// Tests cover all key types, password scenarios, chain handling, and edge cases.
/// </summary>
public class K8SPKCS12StoreTests
{
    private readonly Pkcs12CertificateStoreSerializer _serializer;

    public K8SPKCS12StoreTests()
    {
        _serializer = new Pkcs12CertificateStoreSerializer(storeProperties: null);
    }

    #region Basic Deserialization Tests

    [Fact]
    public void DeserializeRemoteCertificateStore_ValidPkcs12WithPassword_ReturnsStore()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test PKCS12 Cert");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password", "testcert");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_EmptyPassword_SuccessfullyLoadsStore()
    {
        // Arrange - PKCS12 can have empty passwords
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "", "testcert");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "");

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_NullPassword_SuccessfullyLoadsStore()
    {
        // Arrange - PKCS12 treats null same as empty
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "", "testcert");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", null);

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_WrongPassword_ThrowsException()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "correctpassword");

        // Act & Assert
        var exception = Assert.Throws<IOException>(() =>
            _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "wrongpassword"));

        Assert.Contains("password", exception.Message.ToLower());
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_CorruptedData_ThrowsException()
    {
        // Arrange
        var corruptedData = CertificateTestHelper.GenerateCorruptedData(500);

        // Act & Assert
        Assert.ThrowsAny<Exception>(() =>
            _serializer.DeserializeRemoteCertificateStore(corruptedData, "/test/path", "password"));
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_NullData_ThrowsException()
    {
        // Act & Assert
        Assert.ThrowsAny<Exception>(() =>
            _serializer.DeserializeRemoteCertificateStore(null, "/test/path", "password"));
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_EmptyData_ThrowsException()
    {
        // Act & Assert
        Assert.ThrowsAny<Exception>(() =>
            _serializer.DeserializeRemoteCertificateStore(Array.Empty<byte>(), "/test/path", "password"));
    }

    #endregion

    #region Key Type Coverage Tests

    [Theory]
    [InlineData(KeyType.Rsa1024)]
    [InlineData(KeyType.Rsa2048)]
    [InlineData(KeyType.Rsa4096)]
    public void DeserializeRemoteCertificateStore_RsaKeys_SuccessfullyLoadsStore(KeyType keyType)
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(keyType, $"Test {keyType} Cert");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    [Theory]
    [InlineData(KeyType.EcP256)]
    [InlineData(KeyType.EcP384)]
    [InlineData(KeyType.EcP521)]
    public void DeserializeRemoteCertificateStore_EcKeys_SuccessfullyLoadsStore(KeyType keyType)
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(keyType, $"Test {keyType} Cert");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    [Theory]
    [InlineData(KeyType.Dsa1024)]
    [InlineData(KeyType.Dsa2048)]
    public void DeserializeRemoteCertificateStore_DsaKeys_SuccessfullyLoadsStore(KeyType keyType)
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(keyType, $"Test {keyType} Cert");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.Ed448)]
    public void DeserializeRemoteCertificateStore_EdwardsKeys_SuccessfullyLoadsStore(KeyType keyType)
    {
        // Arrange - Edwards curve keys (Ed25519/Ed448) are supported via BouncyCastle PKCS12
        var certInfo = CachedCertificateProvider.GetOrCreate(keyType, $"Test {keyType} Cert");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    #endregion

    #region Password Scenarios Tests

    [Theory]
    [InlineData("password")]
    [InlineData("P@ssw0rd!")]
    [InlineData("密码")]
    [InlineData("🔐🔑")]
    [InlineData("pass word")]
    public void DeserializeRemoteCertificateStore_VariousPasswords_SuccessfullyLoadsStore(string password)
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, password);

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", password);

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_VeryLongPassword_SuccessfullyLoadsStore()
    {
        // Arrange
        var longPassword = new string('x', 1000);
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, longPassword);

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", longPassword);

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    #endregion

    #region Certificate Chain Tests

    [Fact]
    public void DeserializeRemoteCertificateStore_CertificateWithChain_LoadsAllCertificates()
    {
        // Arrange
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "Leaf");
        var leafCert = chain[0].Certificate;
        var leafKeyPair = chain[0].KeyPair;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(
            leafCert,
            leafKeyPair,
            "password",
            "leaf",
            new[] { intermediateCert, rootCert });

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert
        Assert.NotNull(store);
        var certChain = store.GetCertificateChain("leaf");
        Assert.NotNull(certChain);
        Assert.Equal(3, certChain.Length); // Leaf + Intermediate + Root
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_SingleCertificate_LoadsWithoutChain()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert
        Assert.NotNull(store);
        var certChain = store.GetCertificateChain("testcert");
        Assert.NotNull(certChain);
        Assert.Single(certChain); // Only the leaf certificate
    }

    #endregion

    #region Multiple Aliases Tests

    [Fact]
    public void DeserializeRemoteCertificateStore_MultipleAliases_LoadsAllCertificates()
    {
        // Arrange
        var cert1Info = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert 1");
        var cert2Info = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Cert 2");
        var cert3Info = CachedCertificateProvider.GetOrCreate(KeyType.Rsa4096, "Cert 3");

        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "alias1", (cert1Info.Certificate, cert1Info.KeyPair) },
            { "alias2", (cert2Info.Certificate, cert2Info.KeyPair) },
            { "alias3", (cert3Info.Certificate, cert3Info.KeyPair) }
        };

        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(entries, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert
        Assert.NotNull(store);
        var aliases = store.Aliases.ToList();
        Assert.Equal(3, aliases.Count);
        Assert.Contains("alias1", aliases);
        Assert.Contains("alias2", aliases);
        Assert.Contains("alias3", aliases);
    }

    #endregion

    #region Serialization Tests

    [Fact]
    public void SerializeRemoteCertificateStore_ValidStore_ReturnsSerializedData()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password");
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Act
        var serialized = _serializer.SerializeRemoteCertificateStore(store, "/test/path", "store.pfx", "password");

        // Assert
        Assert.NotNull(serialized);
        Assert.Single(serialized);
        Assert.Equal("/test/path/store.pfx", serialized[0].FilePath);
        Assert.NotNull(serialized[0].Contents);
        Assert.NotEmpty(serialized[0].Contents);
    }

    [Fact]
    public void SerializeRemoteCertificateStore_RoundTrip_PreservesData()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password", "testcert");
        var originalStore = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Act - Serialize
        var serialized = _serializer.SerializeRemoteCertificateStore(originalStore, "/test/path", "store.pfx", "password");

        // Act - Deserialize again
        var roundTripStore = _serializer.DeserializeRemoteCertificateStore(serialized[0].Contents, "/test/path", "password");

        // Assert
        Assert.NotNull(roundTripStore);
        var originalAliases = originalStore.Aliases.ToList();
        var roundTripAliases = roundTripStore.Aliases.ToList();
        Assert.Equal(originalAliases.Count, roundTripAliases.Count);

        foreach (var alias in originalAliases)
        {
            Assert.Contains(alias, roundTripAliases);
            var originalCert = originalStore.GetCertificate(alias);
            var roundTripCert = roundTripStore.GetCertificate(alias);
            Assert.Equal(originalCert.Certificate.GetEncoded(), roundTripCert.Certificate.GetEncoded());
        }
    }

    #endregion

    #region GetPrivateKeyPath Tests

    [Fact]
    public void GetPrivateKeyPath_ReturnsNull()
    {
        // PKCS12 stores contain private keys inline, so this should return null
        // Act
        var path = _serializer.GetPrivateKeyPath();

        // Assert
        Assert.Null(path);
    }

    #endregion

    #region IncludeCertChain=false Tests

    [Fact]
    public void Management_IncludeCertChainFalse_OnlyLeafCertInChain()
    {
        // When IncludeCertChain=false is set for PKCS12 stores, only the leaf certificate
        // should be stored in the keystore, not the intermediate or root certificates.

        // Arrange - Generate a certificate chain and create PKCS12 with ONLY the leaf
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKeyPair = chain[0].KeyPair;

        // Create PKCS12 with only the leaf certificate (no chain) - simulating IncludeCertChain=false
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(
            leafCert,
            leafKeyPair,
            "password",
            "leaf-only",
            chain: null  // No chain certificates
        );

        // Act - Deserialize and verify
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert
        Assert.NotNull(store);
        var certChain = store.GetCertificateChain("leaf-only");
        Assert.NotNull(certChain);

        // When IncludeCertChain=false, only the leaf certificate should be present
        Assert.Single(certChain);

        // Verify it's the leaf certificate
        var storedCert = certChain[0].Certificate;
        Assert.Equal(leafCert.SubjectDN.ToString(), storedCert.SubjectDN.ToString());
    }

    [Fact]
    public void IncludeCertChainFalse_VersusTrue_DifferentChainLengths()
    {
        // Compare PKCS12 with IncludeCertChain=true vs IncludeCertChain=false
        // Arrange
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKeyPair = chain[0].KeyPair;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        // IncludeCertChain=false: Only leaf certificate
        var pkcs12False = CertificateTestHelper.GeneratePkcs12(
            leafCert,
            leafKeyPair,
            "password",
            "leaf-only",
            chain: null
        );

        // IncludeCertChain=true: Leaf + full chain
        var pkcs12True = CertificateTestHelper.GeneratePkcs12(
            leafCert,
            leafKeyPair,
            "password",
            "with-chain",
            chain: new[] { intermediateCert, rootCert }
        );

        // Deserialize both
        var storeFalse = _serializer.DeserializeRemoteCertificateStore(pkcs12False, "/test/path", "password");
        var storeTrue = _serializer.DeserializeRemoteCertificateStore(pkcs12True, "/test/path", "password");

        // Assert - IncludeCertChain=false has only 1 cert in chain
        var chainFalse = storeFalse.GetCertificateChain("leaf-only");
        Assert.Single(chainFalse);

        // Assert - IncludeCertChain=true has 3 certs in chain
        var chainTrue = storeTrue.GetCertificateChain("with-chain");
        Assert.Equal(3, chainTrue.Length);
    }

    [Theory]
    [InlineData(KeyType.Rsa2048)]
    [InlineData(KeyType.EcP256)]
    [InlineData(KeyType.EcP384)]
    public void IncludeCertChainFalse_VariousKeyTypes_OnlyLeafCertInChain(KeyType keyType)
    {
        // Verify that IncludeCertChain=false behavior works with various key types for PKCS12
        // Arrange
        var chain = CachedCertificateProvider.GetOrCreateChain(keyType);
        var leafCert = chain[0].Certificate;
        var leafKeyPair = chain[0].KeyPair;

        // Create PKCS12 with only the leaf certificate
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(
            leafCert,
            leafKeyPair,
            "password",
            "testcert",
            chain: null
        );

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert - Only 1 certificate in the chain
        var certChain = store.GetCertificateChain("testcert");
        Assert.Single(certChain);
        Assert.Equal(leafCert.SubjectDN.ToString(), certChain[0].Certificate.SubjectDN.ToString());
    }

    [Fact]
    public void IncludeCertChainFalse_RoundTrip_PreservesLeafOnly()
    {
        // Verify that round-trip serialization preserves the leaf-only chain
        // Arrange
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKeyPair = chain[0].KeyPair;

        var originalPkcs12 = CertificateTestHelper.GeneratePkcs12(
            leafCert,
            leafKeyPair,
            "password",
            "leaf-only",
            chain: null
        );

        var originalStore = _serializer.DeserializeRemoteCertificateStore(originalPkcs12, "/test/path", "password");

        // Act - Round-trip: serialize and deserialize again
        var serialized = _serializer.SerializeRemoteCertificateStore(originalStore, "/test/path", "store.pfx", "password");
        var roundTripStore = _serializer.DeserializeRemoteCertificateStore(serialized[0].Contents, "/test/path", "password");

        // Assert - Still only 1 certificate in chain after round-trip
        var roundTripChain = roundTripStore.GetCertificateChain("leaf-only");
        Assert.Single(roundTripChain);
        Assert.Equal(leafCert.SubjectDN.ToString(), roundTripChain[0].Certificate.SubjectDN.ToString());
    }

    [Fact]
    public void IncludeCertChainFalse_EmptyPassword_OnlyLeafCertInChain()
    {
        // PKCS12 supports empty passwords - verify IncludeCertChain=false works with empty password
        // Arrange
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKeyPair = chain[0].KeyPair;

        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(
            leafCert,
            leafKeyPair,
            "",  // Empty password
            "leaf-only",
            chain: null
        );

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "");

        // Assert
        var certChain = store.GetCertificateChain("leaf-only");
        Assert.Single(certChain);
        Assert.Equal(leafCert.SubjectDN.ToString(), certChain[0].Certificate.SubjectDN.ToString());
    }

    #endregion

    #region Multiple PKCS12 Files in Single Secret Tests

    [Fact]
    public void Inventory_SecretWithMultiplePkcs12Files_LoadsAllKeystores()
    {
        // Test that multiple PKCS12 files stored in a single Kubernetes secret are all loaded correctly.
        // This simulates a K8s secret with multiple data fields like:
        // data:
        //   app.pfx: <base64>
        //   ca.p12: <base64>
        //   truststore.pfx: <base64>

        // Arrange - Create separate PKCS12 files with different certificates
        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "App Certificate");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "CA Certificate");
        var cert3 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa4096, "Truststore Certificate");

        // Generate separate PKCS12 files
        var appPfxBytes = CertificateTestHelper.GeneratePkcs12(cert1.Certificate, cert1.KeyPair, "password", "appcert");
        var caP12Bytes = CertificateTestHelper.GeneratePkcs12(cert2.Certificate, cert2.KeyPair, "password", "cacert");
        var truststorePfxBytes = CertificateTestHelper.GeneratePkcs12(cert3.Certificate, cert3.KeyPair, "password", "trustcert");

        // Simulate multiple PKCS12 files in a secret's Inventory dictionary
        var inventoryDict = new Dictionary<string, byte[]>
        {
            { "app.pfx", appPfxBytes },
            { "ca.p12", caP12Bytes },
            { "truststore.pfx", truststorePfxBytes }
        };

        // Act - Deserialize each PKCS12 file and collect all aliases
        var allAliases = new Dictionary<string, List<string>>();
        foreach (var (keyName, keyBytes) in inventoryDict)
        {
            var store = _serializer.DeserializeRemoteCertificateStore(keyBytes, $"/test/{keyName}", "password");
            allAliases[keyName] = store.Aliases.ToList();
        }

        // Assert - All three PKCS12 files should be loaded
        Assert.Equal(3, allAliases.Count);
        Assert.Contains("app.pfx", allAliases.Keys);
        Assert.Contains("ca.p12", allAliases.Keys);
        Assert.Contains("truststore.pfx", allAliases.Keys);
    }

    [Fact]
    public void Inventory_SecretWithMultiplePkcs12Files_EachHasCorrectAliases()
    {
        // Test that aliases from each PKCS12 file are correctly attributed to the right file.
        // Each PKCS12 file has unique aliases that should be identifiable.

        // Arrange - Create PKCS12 files with different unique aliases
        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Web Server");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Database");
        var cert3 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa4096, "API Gateway");

        // Create PKCS12 files with specific unique aliases
        var webPfxBytes = CertificateTestHelper.GeneratePkcs12(cert1.Certificate, cert1.KeyPair, "password", "webserver-cert");
        var dbPfxBytes = CertificateTestHelper.GeneratePkcs12(cert2.Certificate, cert2.KeyPair, "password", "database-cert");
        var apiPfxBytes = CertificateTestHelper.GeneratePkcs12(cert3.Certificate, cert3.KeyPair, "password", "apigateway-cert");

        var inventoryDict = new Dictionary<string, byte[]>
        {
            { "web.pfx", webPfxBytes },
            { "db.pfx", dbPfxBytes },
            { "api.pfx", apiPfxBytes }
        };

        // Act - Deserialize each PKCS12 and verify aliases
        var webStore = _serializer.DeserializeRemoteCertificateStore(inventoryDict["web.pfx"], "/test/web.pfx", "password");
        var dbStore = _serializer.DeserializeRemoteCertificateStore(inventoryDict["db.pfx"], "/test/db.pfx", "password");
        var apiStore = _serializer.DeserializeRemoteCertificateStore(inventoryDict["api.pfx"], "/test/api.pfx", "password");

        // Assert - Each store has exactly one alias with the expected name
        var webAliases = webStore.Aliases.ToList();
        var dbAliases = dbStore.Aliases.ToList();
        var apiAliases = apiStore.Aliases.ToList();

        Assert.Single(webAliases);
        Assert.Single(dbAliases);
        Assert.Single(apiAliases);

        Assert.Contains("webserver-cert", webAliases);
        Assert.Contains("database-cert", dbAliases);
        Assert.Contains("apigateway-cert", apiAliases);

        // Verify that aliases are NOT mixed between files
        Assert.DoesNotContain("database-cert", webAliases);
        Assert.DoesNotContain("apigateway-cert", webAliases);
        Assert.DoesNotContain("webserver-cert", dbAliases);
    }

    [Fact]
    public void Inventory_SecretWithMultiplePkcs12Files_DifferentPasswords_ThrowsOnWrongPassword()
    {
        // Test behavior when PKCS12 files have different passwords.
        // In practice, K8S stores usually have the same password for all files,
        // but we should handle cases where they differ.

        // Arrange
        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert 1");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert 2");

        var pfx1Bytes = CertificateTestHelper.GeneratePkcs12(cert1.Certificate, cert1.KeyPair, "password1", "cert1");
        var pfx2Bytes = CertificateTestHelper.GeneratePkcs12(cert2.Certificate, cert2.KeyPair, "password2", "cert2");

        // Act & Assert - First file loads with correct password
        var store1 = _serializer.DeserializeRemoteCertificateStore(pfx1Bytes, "/test/file1.pfx", "password1");
        Assert.NotNull(store1);
        Assert.Single(store1.Aliases);

        // Second file should throw with wrong password
        Assert.ThrowsAny<Exception>(() =>
            _serializer.DeserializeRemoteCertificateStore(pfx2Bytes, "/test/file2.pfx", "password1"));

        // Second file loads with correct password
        var store2 = _serializer.DeserializeRemoteCertificateStore(pfx2Bytes, "/test/file2.pfx", "password2");
        Assert.NotNull(store2);
        Assert.Single(store2.Aliases);
    }

    [Fact]
    public void Inventory_SecretWithMultiplePkcs12Files_EachWithMultipleEntries_LoadsAllCorrectly()
    {
        // Test that multiple PKCS12 files, each containing multiple entries, all load correctly.

        // Arrange - Create two PKCS12 files, each with multiple aliases
        var cert1a = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "App Server 1");
        var cert1b = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "App Server 2");
        var cert2a = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Backend 1");
        var cert2b = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Backend 2");
        var cert2c = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Backend 3");

        var appEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "app-server-1", (cert1a.Certificate, cert1a.KeyPair) },
            { "app-server-2", (cert1b.Certificate, cert1b.KeyPair) }
        };

        var backendEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "backend-1", (cert2a.Certificate, cert2a.KeyPair) },
            { "backend-2", (cert2b.Certificate, cert2b.KeyPair) },
            { "backend-3", (cert2c.Certificate, cert2c.KeyPair) }
        };

        var appPfxBytes = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(appEntries, "password");
        var backendPfxBytes = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(backendEntries, "password");

        var inventoryDict = new Dictionary<string, byte[]>
        {
            { "app.pfx", appPfxBytes },
            { "backend.pfx", backendPfxBytes }
        };

        // Act
        var appStore = _serializer.DeserializeRemoteCertificateStore(inventoryDict["app.pfx"], "/test/app.pfx", "password");
        var backendStore = _serializer.DeserializeRemoteCertificateStore(inventoryDict["backend.pfx"], "/test/backend.pfx", "password");

        // Assert
        var appAliases = appStore.Aliases.ToList();
        var backendAliases = backendStore.Aliases.ToList();

        Assert.Equal(2, appAliases.Count);
        Assert.Equal(3, backendAliases.Count);

        Assert.Contains("app-server-1", appAliases);
        Assert.Contains("app-server-2", appAliases);

        Assert.Contains("backend-1", backendAliases);
        Assert.Contains("backend-2", backendAliases);
        Assert.Contains("backend-3", backendAliases);

        // Total aliases across all files
        Assert.Equal(5, appAliases.Count + backendAliases.Count);
    }

    #endregion

    #region Edge Case Tests

    [Fact]
    public void DeserializeRemoteCertificateStore_PartiallyCorruptedData_ThrowsException()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var validPkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password");
        var corruptedBytes = CertificateTestHelper.CorruptData(validPkcs12Bytes, bytesToCorrupt: 10);

        // Act & Assert
        Assert.ThrowsAny<Exception>(() =>
            _serializer.DeserializeRemoteCertificateStore(corruptedBytes, "/test/path", "password"));
    }

    [Fact]
    public void SerializeRemoteCertificateStore_EmptyStore_ReturnsValidOutput()
    {
        // Arrange
        var emptyStore = new Pkcs12StoreBuilder().Build();

        // Act
        var serialized = _serializer.SerializeRemoteCertificateStore(emptyStore, "/test/path", "empty.pfx", "password");

        // Assert
        Assert.NotNull(serialized);
        Assert.Single(serialized);
        Assert.NotNull(serialized[0].Contents);
    }

    [Fact]
    public void SerializeRemoteCertificateStore_DifferentPassword_SuccessfullySerializes()
    {
        // Tests that we can deserialize with one password and serialize with a different one
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password1");
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password1");

        // Act
        var serialized = _serializer.SerializeRemoteCertificateStore(store, "/test/path", "store.pfx", "password2");

        // Assert - Deserialize with new password
        var newStore = _serializer.DeserializeRemoteCertificateStore(serialized[0].Contents, "/test/path", "password2");
        Assert.NotNull(newStore);
        Assert.Equal(store.Aliases.ToList().Count, newStore.Aliases.ToList().Count);
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_CertificateOnlyEntry_SuccessfullyLoadsStore()
    {
        // PKCS12 can contain certificate entries without private keys
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var storeBuilder = new Pkcs12StoreBuilder();
        var store = storeBuilder.Build();

        // Add certificate without private key
        store.SetCertificateEntry("certonly", new Org.BouncyCastle.Pkcs.X509CertificateEntry(certInfo.Certificate));

        using var ms = new MemoryStream();
        store.Save(ms, "password".ToCharArray(), new Org.BouncyCastle.Security.SecureRandom());
        var pkcs12Bytes = ms.ToArray();

        // Act
        var loadedStore = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert
        Assert.NotNull(loadedStore);
        Assert.Contains("certonly", loadedStore.Aliases.ToList());
        Assert.False(loadedStore.IsKeyEntry("certonly"));
    }

    #endregion

    #region Mixed Entry Types Tests (Private Keys + Trusted Certs)

    [Fact]
    public void DeserializeRemoteCertificateStore_MixedEntryTypes_LoadsBothTypes()
    {
        // Arrange - Create a PKCS12 with both private key entries and trusted certificate entries
        var privateKeyEntry1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Server Cert 1");
        var privateKeyEntry2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Server Cert 2");
        var trustedCert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Trusted Root CA");
        var trustedCert2 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa4096, "Trusted Intermediate CA");

        var privateKeyEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "server1", (privateKeyEntry1.Certificate, privateKeyEntry1.KeyPair) },
            { "server2", (privateKeyEntry2.Certificate, privateKeyEntry2.KeyPair) }
        };

        var trustedCertEntries = new Dictionary<string, Org.BouncyCastle.X509.X509Certificate>
        {
            { "root-ca", trustedCert1.Certificate },
            { "intermediate-ca", trustedCert2.Certificate }
        };

        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12WithMixedEntries(privateKeyEntries, trustedCertEntries, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert - All 4 entries should be loaded
        Assert.NotNull(store);
        var aliases = store.Aliases.ToList();
        Assert.Equal(4, aliases.Count);
        Assert.Contains("server1", aliases);
        Assert.Contains("server2", aliases);
        Assert.Contains("root-ca", aliases);
        Assert.Contains("intermediate-ca", aliases);
    }

    [Fact]
    public void Inventory_MixedEntryTypes_ReportsCorrectPrivateKeyStatus()
    {
        // Arrange - Create a PKCS12 with both private key entries and trusted certificate entries
        var privateKeyEntry = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Server Cert");
        var trustedCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Trusted CA");

        var privateKeyEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "server", (privateKeyEntry.Certificate, privateKeyEntry.KeyPair) }
        };

        var trustedCertEntries = new Dictionary<string, Org.BouncyCastle.X509.X509Certificate>
        {
            { "trusted-ca", trustedCert.Certificate }
        };

        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12WithMixedEntries(privateKeyEntries, trustedCertEntries, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert - Verify IsKeyEntry returns correct values
        Assert.True(store.IsKeyEntry("server"), "server should be a key entry (has private key)");
        Assert.False(store.IsKeyEntry("trusted-ca"), "trusted-ca should NOT be a key entry (certificate only)");

        // Verify we can get the certificate from both entries
        var serverCert = store.GetCertificate("server");
        var trustedCaCert = store.GetCertificate("trusted-ca");
        Assert.NotNull(serverCert);
        Assert.NotNull(trustedCaCert);
    }

    [Fact]
    public void CreateOrUpdatePkcs12_AddTrustedCertEntry_PreservesExistingEntries()
    {
        // Arrange - Create initial PKCS12 with a private key entry
        var existingCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Existing Server Cert");
        var existingPkcs12 = CertificateTestHelper.GeneratePkcs12(existingCert.Certificate, existingCert.KeyPair, "password", "existing-server");

        // Create a trusted certificate (no private key) to add
        var trustedCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Trusted CA");

        // Convert trusted cert to DER bytes (certificate only, no private key)
        var trustedCertBytes = trustedCert.Certificate.GetEncoded();

        // Act - Add the trusted certificate entry
        var updatedPkcs12Bytes = _serializer.CreateOrUpdatePkcs12(
            trustedCertBytes,
            null, // No password for certificate-only
            "trusted-ca",
            existingPkcs12,
            "password",
            remove: false,
            includeChain: true);

        // Deserialize and verify
        var store = _serializer.DeserializeRemoteCertificateStore(updatedPkcs12Bytes, "/test/path", "password");

        // Assert - Both entries should exist
        var aliases = store.Aliases.ToList();
        Assert.Equal(2, aliases.Count);
        Assert.Contains("existing-server", aliases);
        Assert.Contains("trusted-ca", aliases);

        // Verify entry types are preserved
        Assert.True(store.IsKeyEntry("existing-server"), "existing-server should still be a key entry");
        Assert.False(store.IsKeyEntry("trusted-ca"), "trusted-ca should be a certificate-only entry");
    }

    [Fact]
    public void SerializeRemoteCertificateStore_MixedEntryTypes_PreservesEntryTypes()
    {
        // Arrange - Create a PKCS12 with mixed entry types
        var privateKeyEntry = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Server Cert");
        var trustedCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Trusted CA");

        var privateKeyEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "server", (privateKeyEntry.Certificate, privateKeyEntry.KeyPair) }
        };

        var trustedCertEntries = new Dictionary<string, Org.BouncyCastle.X509.X509Certificate>
        {
            { "trusted-ca", trustedCert.Certificate }
        };

        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12WithMixedEntries(privateKeyEntries, trustedCertEntries, "password");
        var originalStore = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Act - Serialize and deserialize
        var serialized = _serializer.SerializeRemoteCertificateStore(originalStore, "/test/path", "store.pfx", "password");
        var roundTripStore = _serializer.DeserializeRemoteCertificateStore(serialized[0].Contents, "/test/path", "password");

        // Assert - Entry types should be preserved after round-trip
        Assert.True(roundTripStore.IsKeyEntry("server"), "server should still be a key entry after round-trip");
        Assert.False(roundTripStore.IsKeyEntry("trusted-ca"), "trusted-ca should still be certificate-only after round-trip");
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_MixedEntryTypes_CorrectCertificateChainForKeyEntries()
    {
        // Arrange - Create a PKCS12 with a private key entry that has a chain and a trusted cert entry
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "Server");
        var serverCert = chain[0];
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;
        var trustedCa = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "External Trusted CA");

        // Create PKCS12 manually with chain for key entry
        var store = new Pkcs12StoreBuilder().Build();
        var certChain = new[]
        {
            new X509CertificateEntry(serverCert.Certificate),
            new X509CertificateEntry(intermediateCert),
            new X509CertificateEntry(rootCert)
        };
        store.SetKeyEntry("server", new AsymmetricKeyEntry(serverCert.KeyPair.Private), certChain);
        store.SetCertificateEntry("external-ca", new X509CertificateEntry(trustedCa.Certificate));

        using var ms = new MemoryStream();
        store.Save(ms, "password".ToCharArray(), new Org.BouncyCastle.Security.SecureRandom());
        var pkcs12Bytes = ms.ToArray();

        // Act
        var loadedStore = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert - Key entry should have full chain
        var serverChain = loadedStore.GetCertificateChain("server");
        Assert.NotNull(serverChain);
        Assert.Equal(3, serverChain.Length);

        // Trusted cert entry should have no chain (just the certificate)
        var externalCaChain = loadedStore.GetCertificateChain("external-ca");
        Assert.Null(externalCaChain); // Certificate entries don't have chains, only key entries do
    }

    [Fact]
    public void CreateOrUpdatePkcs12_RemoveTrustedCertEntry_PreservesKeyEntries()
    {
        // Arrange - Create PKCS12 with both entry types
        var privateKeyEntry = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Server Cert");
        var trustedCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Trusted CA");

        var privateKeyEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "server", (privateKeyEntry.Certificate, privateKeyEntry.KeyPair) }
        };

        var trustedCertEntries = new Dictionary<string, Org.BouncyCastle.X509.X509Certificate>
        {
            { "trusted-ca", trustedCert.Certificate }
        };

        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12WithMixedEntries(privateKeyEntries, trustedCertEntries, "password");

        // Act - Remove the trusted cert entry
        var updatedPkcs12Bytes = _serializer.CreateOrUpdatePkcs12(
            Array.Empty<byte>(),
            null,
            "trusted-ca",
            pkcs12Bytes,
            "password",
            remove: true,
            includeChain: true);

        // Deserialize and verify
        var store = _serializer.DeserializeRemoteCertificateStore(updatedPkcs12Bytes, "/test/path", "password");

        // Assert - Only the key entry should remain
        var aliases = store.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("server", aliases);
        Assert.DoesNotContain("trusted-ca", aliases);
        Assert.True(store.IsKeyEntry("server"), "server should still be a key entry");
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_MixedEntryTypesWithEmptyPassword_LoadsCorrectly()
    {
        // Arrange - PKCS12 supports empty passwords
        var privateKeyEntry = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Server Cert");
        var trustedCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Trusted CA");

        var privateKeyEntries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "server", (privateKeyEntry.Certificate, privateKeyEntry.KeyPair) }
        };

        var trustedCertEntries = new Dictionary<string, Org.BouncyCastle.X509.X509Certificate>
        {
            { "trusted-ca", trustedCert.Certificate }
        };

        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12WithMixedEntries(privateKeyEntries, trustedCertEntries, "");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "");

        // Assert
        Assert.True(store.IsKeyEntry("server"), "server should be a key entry");
        Assert.False(store.IsKeyEntry("trusted-ca"), "trusted-ca should NOT be a key entry");
    }

    #endregion

    #region Empty Store Tests (Create Store If Missing)

    [Fact]
    public void CreateEmptyPkcs12Store_WithPassword_CanBeLoadedWithSamePassword()
    {
        // Arrange - Create an empty PKCS12 store (simulates "create store if missing")
        var storeBuilder = new Pkcs12StoreBuilder();
        var emptyStore = storeBuilder.Build();
        var password = "testpassword";

        // Act - Save the empty store
        using var outStream = new MemoryStream();
        emptyStore.Save(outStream, password.ToCharArray(), new Org.BouncyCastle.Security.SecureRandom());
        var emptyPkcs12Bytes = outStream.ToArray();

        // Assert - Should be valid PKCS12 that can be loaded
        Assert.NotNull(emptyPkcs12Bytes);
        Assert.NotEmpty(emptyPkcs12Bytes);

        // Verify it can be loaded
        var loadedStore = _serializer.DeserializeRemoteCertificateStore(emptyPkcs12Bytes, "/test/path", password);
        Assert.NotNull(loadedStore);
        Assert.Empty(loadedStore.Aliases.ToList());
    }

    [Fact]
    public void CreateEmptyPkcs12Store_WithEmptyPassword_CanBeLoadedWithEmptyPassword()
    {
        // Arrange - Create an empty PKCS12 store with empty password
        var storeBuilder = new Pkcs12StoreBuilder();
        var emptyStore = storeBuilder.Build();

        // Act - Save the empty store with empty password
        using var outStream = new MemoryStream();
        emptyStore.Save(outStream, Array.Empty<char>(), new Org.BouncyCastle.Security.SecureRandom());
        var emptyPkcs12Bytes = outStream.ToArray();

        // Assert - Should be valid PKCS12 that can be loaded
        Assert.NotNull(emptyPkcs12Bytes);
        Assert.NotEmpty(emptyPkcs12Bytes);

        // Verify it can be loaded
        var loadedStore = _serializer.DeserializeRemoteCertificateStore(emptyPkcs12Bytes, "/test/path", "");
        Assert.NotNull(loadedStore);
        Assert.Empty(loadedStore.Aliases.ToList());
    }

    [Fact]
    public void CreateEmptyPkcs12Store_ThenAddCertificate_Success()
    {
        // Arrange - Create an empty PKCS12 store
        var storeBuilder = new Pkcs12StoreBuilder();
        var emptyStore = storeBuilder.Build();
        var password = "testpassword";

        using var outStream = new MemoryStream();
        emptyStore.Save(outStream, password.ToCharArray(), new Org.BouncyCastle.Security.SecureRandom());
        var emptyPkcs12Bytes = outStream.ToArray();

        // Create a certificate to add
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "New Cert");
        var newCertPkcs12 = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, password, "newcert");

        // Act - Use CreateOrUpdatePkcs12 to add the certificate to the empty store
        var updatedPkcs12Bytes = _serializer.CreateOrUpdatePkcs12(
            newCertPkcs12,
            password,
            "newcert",
            emptyPkcs12Bytes,
            password,
            false,
            true);

        // Assert - Should have one certificate
        var loadedStore = _serializer.DeserializeRemoteCertificateStore(updatedPkcs12Bytes, "/test/path", password);
        var aliases = loadedStore.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("newcert", aliases);
    }

    #endregion

    #region RSA 8192 Key Tests

    [Fact]
    public void DeserializeRemoteCertificateStore_Rsa8192Key_SuccessfullyLoadsStore()
    {
        // Dedicated test for RSA 8192 key type - cached so it only generates once across all tests
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa8192, "Test Rsa8192 Cert");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    #endregion
}
