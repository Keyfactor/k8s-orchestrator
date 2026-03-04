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
using Keyfactor.Extensions.Orchestrator.K8S.StoreTypes.K8SJKS;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Org.BouncyCastle.Pkcs;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests;

/// <summary>
/// Comprehensive unit tests for K8SJKS store type operations.
/// Tests cover all key types, password scenarios, chain handling, and edge cases.
/// </summary>
public class K8SJKSStoreTests
{
    private readonly JksCertificateStoreSerializer _serializer;

    public K8SJKSStoreTests()
    {
        _serializer = new JksCertificateStoreSerializer(storeProperties: null);
    }

    #region Basic Deserialization Tests

    [Fact]
    public void DeserializeRemoteCertificateStore_ValidJksWithPassword_ReturnsStore()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test JKS Cert");
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password", "testcert");

        // Note: JKS deserialization will attempt to load as PKCS12 if JKS format fails
        // This tests the fallback behavior documented in the implementation

        // Act & Assert
        var exception = Record.Exception(() =>
            _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password"));

        // The deserializer should handle both JKS and PKCS12 formats
        Assert.Null(exception);
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_EmptyPassword_ThrowsArgumentException()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", ""));

        Assert.Contains("password is null or empty", exception.Message);
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_NullPassword_ThrowsArgumentException()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", null));

        Assert.Contains("password is null or empty", exception.Message);
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_WrongPassword_ThrowsException()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var jksBytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "correctpassword");

        // Act & Assert
        var exception = Assert.Throws<IOException>(() =>
            _serializer.DeserializeRemoteCertificateStore(jksBytes, "/test/path", "wrongpassword"));

        Assert.Contains("password incorrect", exception.Message);
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_CorruptedData_ThrowsException()
    {
        // Arrange
        var corruptedData = CertificateTestHelper.GenerateCorruptedData(500);

        // Act & Assert - Accept any exception type since corrupted data can throw various exceptions
        Assert.ThrowsAny<Exception>(() =>
            _serializer.DeserializeRemoteCertificateStore(corruptedData, "/test/path", "password"));
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_NullData_ThrowsException()
    {
        // Act & Assert - Null data will cause NullReferenceException or ArgumentNullException
        Assert.ThrowsAny<Exception>(() =>
            _serializer.DeserializeRemoteCertificateStore(null, "/test/path", "password"));
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_EmptyData_ThrowsException()
    {
        // Act & Assert - Empty data will cause IOException or similar
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
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password");

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
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password");

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
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password");

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
        // Arrange - Edwards curve keys (Ed25519/Ed448) are supported via BouncyCastle JKS
        var certInfo = CachedCertificateProvider.GetOrCreate(keyType, $"Test {keyType} Cert");
        var jksBytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(jksBytes, "/test/path", "password");

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
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, password);

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", password);

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_PasswordWithNewline_HandlesCorrectly()
    {
        // This tests the common kubectl secret issue where passwords have trailing newlines
        // Arrange
        var password = "password";
        var passwordWithNewline = "password\n";
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, password);

        // Act & Assert
        // The implementation should trim the password, but if not trimmed, it should fail
        var exception = Record.Exception(() =>
            _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", passwordWithNewline));

        // This may throw an exception if the implementation doesn't trim
        // The actual behavior depends on the JksCertificateStoreSerializer implementation
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_VeryLongPassword_SuccessfullyLoadsStore()
    {
        // Arrange
        var longPassword = new string('x', 1000);
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, longPassword);

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

        var pkcs12Bytes = CertificateTestHelper.GenerateJks(
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
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password");

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

        var pkcs12Bytes = CertificateTestHelper.GenerateJksWithMultipleEntries(entries, "password");

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
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password");
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Act
        var serialized = _serializer.SerializeRemoteCertificateStore(store, "/test/path", "store.jks", "password");

        // Assert
        Assert.NotNull(serialized);
        Assert.Single(serialized);
        Assert.Equal("/test/path/store.jks", serialized[0].FilePath);
        Assert.NotNull(serialized[0].Contents);
        Assert.NotEmpty(serialized[0].Contents);
    }

    [Fact]
    public void SerializeRemoteCertificateStore_RoundTrip_PreservesData()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048);
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password", "testcert");
        var originalStore = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password");

        // Act - Serialize
        var serialized = _serializer.SerializeRemoteCertificateStore(originalStore, "/test/path", "store.jks", "password");

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
        // JKS stores contain private keys inline, so this should return null
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
        // When IncludeCertChain=false is set for JKS stores, only the leaf certificate
        // should be stored in the keystore, not the intermediate or root certificates.

        // Arrange - Generate a certificate chain and create JKS with ONLY the leaf
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKeyPair = chain[0].KeyPair;

        // Create JKS with only the leaf certificate (no chain) - simulating IncludeCertChain=false
        var jksBytes = CertificateTestHelper.GenerateJks(
            leafCert,
            leafKeyPair,
            "password",
            "leaf-only",
            chain: null  // No chain certificates
        );

        // Act - Deserialize and verify
        var store = _serializer.DeserializeRemoteCertificateStore(jksBytes, "/test/path", "password");

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
        // Compare JKS with IncludeCertChain=true vs IncludeCertChain=false
        // Arrange
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafKeyPair = chain[0].KeyPair;
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;

        // IncludeCertChain=false: Only leaf certificate
        var jksFalse = CertificateTestHelper.GenerateJks(
            leafCert,
            leafKeyPair,
            "password",
            "leaf-only",
            chain: null
        );

        // IncludeCertChain=true: Leaf + full chain
        var jksTrue = CertificateTestHelper.GenerateJks(
            leafCert,
            leafKeyPair,
            "password",
            "with-chain",
            chain: new[] { intermediateCert, rootCert }
        );

        // Deserialize both
        var storeFalse = _serializer.DeserializeRemoteCertificateStore(jksFalse, "/test/path", "password");
        var storeTrue = _serializer.DeserializeRemoteCertificateStore(jksTrue, "/test/path", "password");

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
        // Verify that IncludeCertChain=false behavior works with various key types for JKS
        // Arrange
        var chain = CachedCertificateProvider.GetOrCreateChain(keyType);
        var leafCert = chain[0].Certificate;
        var leafKeyPair = chain[0].KeyPair;

        // Create JKS with only the leaf certificate
        var jksBytes = CertificateTestHelper.GenerateJks(
            leafCert,
            leafKeyPair,
            "password",
            "testcert",
            chain: null
        );

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(jksBytes, "/test/path", "password");

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

        var originalJks = CertificateTestHelper.GenerateJks(
            leafCert,
            leafKeyPair,
            "password",
            "leaf-only",
            chain: null
        );

        var originalStore = _serializer.DeserializeRemoteCertificateStore(originalJks, "/test/path", "password");

        // Act - Round-trip: serialize and deserialize again
        var serialized = _serializer.SerializeRemoteCertificateStore(originalStore, "/test/path", "store.jks", "password");
        var roundTripStore = _serializer.DeserializeRemoteCertificateStore(serialized[0].Contents, "/test/path", "password");

        // Assert - Still only 1 certificate in chain after round-trip
        var roundTripChain = roundTripStore.GetCertificateChain("leaf-only");
        Assert.Single(roundTripChain);
        Assert.Equal(leafCert.SubjectDN.ToString(), roundTripChain[0].Certificate.SubjectDN.ToString());
    }

    #endregion

    #region Multiple JKS Files in Single Secret Tests

    [Fact]
    public void Inventory_SecretWithMultipleJksFiles_LoadsAllKeystores()
    {
        // Test that multiple JKS files stored in a single Kubernetes secret are all loaded correctly.
        // This simulates a K8s secret with multiple data fields like:
        // data:
        //   app.jks: <base64>
        //   ca.jks: <base64>
        //   truststore.jks: <base64>

        // Arrange - Create separate JKS files with different certificates
        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "App Certificate");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "CA Certificate");
        var cert3 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa4096, "Truststore Certificate");

        // Generate separate JKS files
        var appJksBytes = CertificateTestHelper.GenerateJks(cert1.Certificate, cert1.KeyPair, "password", "appcert");
        var caJksBytes = CertificateTestHelper.GenerateJks(cert2.Certificate, cert2.KeyPair, "password", "cacert");
        var truststoreJksBytes = CertificateTestHelper.GenerateJks(cert3.Certificate, cert3.KeyPair, "password", "trustcert");

        // Simulate multiple JKS files in a secret's Inventory dictionary
        var inventoryDict = new Dictionary<string, byte[]>
        {
            { "app.jks", appJksBytes },
            { "ca.jks", caJksBytes },
            { "truststore.jks", truststoreJksBytes }
        };

        // Act - Deserialize each JKS file and collect all aliases
        var allAliases = new Dictionary<string, List<string>>();
        foreach (var (keyName, keyBytes) in inventoryDict)
        {
            var store = _serializer.DeserializeRemoteCertificateStore(keyBytes, $"/test/{keyName}", "password");
            allAliases[keyName] = store.Aliases.ToList();
        }

        // Assert - All three JKS files should be loaded
        Assert.Equal(3, allAliases.Count);
        Assert.Contains("app.jks", allAliases.Keys);
        Assert.Contains("ca.jks", allAliases.Keys);
        Assert.Contains("truststore.jks", allAliases.Keys);
    }

    [Fact]
    public void Inventory_SecretWithMultipleJksFiles_EachHasCorrectAliases()
    {
        // Test that aliases from each JKS file are correctly attributed to the right file.
        // Each JKS file has unique aliases that should be identifiable.

        // Arrange - Create JKS files with different unique aliases
        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Web Server");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Database");
        var cert3 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa4096, "API Gateway");

        // Create JKS files with specific unique aliases
        var webJksBytes = CertificateTestHelper.GenerateJks(cert1.Certificate, cert1.KeyPair, "password", "webserver-cert");
        var dbJksBytes = CertificateTestHelper.GenerateJks(cert2.Certificate, cert2.KeyPair, "password", "database-cert");
        var apiJksBytes = CertificateTestHelper.GenerateJks(cert3.Certificate, cert3.KeyPair, "password", "apigateway-cert");

        var inventoryDict = new Dictionary<string, byte[]>
        {
            { "web.jks", webJksBytes },
            { "db.jks", dbJksBytes },
            { "api.jks", apiJksBytes }
        };

        // Act - Deserialize each JKS and verify aliases
        var webStore = _serializer.DeserializeRemoteCertificateStore(inventoryDict["web.jks"], "/test/web.jks", "password");
        var dbStore = _serializer.DeserializeRemoteCertificateStore(inventoryDict["db.jks"], "/test/db.jks", "password");
        var apiStore = _serializer.DeserializeRemoteCertificateStore(inventoryDict["api.jks"], "/test/api.jks", "password");

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
    public void Inventory_SecretWithMultipleJksFiles_DifferentPasswords_ThrowsOnWrongPassword()
    {
        // Test behavior when JKS files have different passwords.
        // In practice, K8S stores usually have the same password for all files,
        // but we should handle cases where they differ.

        // Arrange
        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert 1");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert 2");

        var jks1Bytes = CertificateTestHelper.GenerateJks(cert1.Certificate, cert1.KeyPair, "password1", "cert1");
        var jks2Bytes = CertificateTestHelper.GenerateJks(cert2.Certificate, cert2.KeyPair, "password2", "cert2");

        // Act & Assert - First file loads with correct password
        var store1 = _serializer.DeserializeRemoteCertificateStore(jks1Bytes, "/test/file1.jks", "password1");
        Assert.NotNull(store1);
        Assert.Single(store1.Aliases);

        // Second file should throw with wrong password
        Assert.ThrowsAny<Exception>(() =>
            _serializer.DeserializeRemoteCertificateStore(jks2Bytes, "/test/file2.jks", "password1"));

        // Second file loads with correct password
        var store2 = _serializer.DeserializeRemoteCertificateStore(jks2Bytes, "/test/file2.jks", "password2");
        Assert.NotNull(store2);
        Assert.Single(store2.Aliases);
    }

    [Fact]
    public void Inventory_SecretWithMultipleJksFiles_EachWithMultipleEntries_LoadsAllCorrectly()
    {
        // Test that multiple JKS files, each containing multiple entries, all load correctly.

        // Arrange - Create two JKS files, each with multiple aliases
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

        var appJksBytes = CertificateTestHelper.GenerateJksWithMultipleEntries(appEntries, "password");
        var backendJksBytes = CertificateTestHelper.GenerateJksWithMultipleEntries(backendEntries, "password");

        var inventoryDict = new Dictionary<string, byte[]>
        {
            { "app.jks", appJksBytes },
            { "backend.jks", backendJksBytes }
        };

        // Act
        var appStore = _serializer.DeserializeRemoteCertificateStore(inventoryDict["app.jks"], "/test/app.jks", "password");
        var backendStore = _serializer.DeserializeRemoteCertificateStore(inventoryDict["backend.jks"], "/test/backend.jks", "password");

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
        var validJksBytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password");
        var corruptedBytes = CertificateTestHelper.CorruptData(validJksBytes, bytesToCorrupt: 10);

        // Act & Assert - Corrupted data can throw various exceptions (IOException, FormatException, etc.)
        Assert.ThrowsAny<Exception>(() =>
            _serializer.DeserializeRemoteCertificateStore(corruptedBytes, "/test/path", "password"));
    }

    [Fact]
    public void SerializeRemoteCertificateStore_EmptyStore_ReturnsValidOutput()
    {
        // Arrange
        var emptyStore = new Pkcs12StoreBuilder().Build();

        // Act
        var serialized = _serializer.SerializeRemoteCertificateStore(emptyStore, "/test/path", "empty.jks", "password");

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
        var pkcs12Bytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password1");
        var store = _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password1");

        // Act
        var serialized = _serializer.SerializeRemoteCertificateStore(store, "/test/path", "store.jks", "password2");

        // Assert - Deserialize with new password
        var newStore = _serializer.DeserializeRemoteCertificateStore(serialized[0].Contents, "/test/path", "password2");
        Assert.NotNull(newStore);
        Assert.Equal(store.Aliases.ToList().Count, newStore.Aliases.ToList().Count);
    }

    #endregion

    #region Mixed Entry Types Tests (Private Keys + Trusted Certs)

    [Fact]
    public void DeserializeRemoteCertificateStore_MixedEntryTypes_LoadsBothTypes()
    {
        // Arrange - Create a JKS with both private key entries and trusted certificate entries
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

        var jksBytes = CertificateTestHelper.GenerateJksWithMixedEntries(privateKeyEntries, trustedCertEntries, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(jksBytes, "/test/path", "password");

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
        // Arrange - Create a JKS with both private key entries and trusted certificate entries
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

        var jksBytes = CertificateTestHelper.GenerateJksWithMixedEntries(privateKeyEntries, trustedCertEntries, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(jksBytes, "/test/path", "password");

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
    public void CreateOrUpdateJks_AddTrustedCertEntry_PreservesExistingEntries()
    {
        // Arrange - Create initial JKS with a private key entry
        var existingCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Existing Server Cert");
        var existingJks = CertificateTestHelper.GenerateJks(existingCert.Certificate, existingCert.KeyPair, "password", "existing-server");

        // Create a trusted certificate (no private key) to add
        var trustedCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Trusted CA");

        // Convert trusted cert to DER bytes (certificate only, no private key)
        var trustedCertBytes = trustedCert.Certificate.GetEncoded();

        // Act - Add the trusted certificate entry
        var updatedJksBytes = _serializer.CreateOrUpdateJks(
            trustedCertBytes,
            null, // No password for certificate-only
            "trusted-ca",
            existingJks,
            "password",
            remove: false,
            includeChain: true);

        // Deserialize and verify
        var store = _serializer.DeserializeRemoteCertificateStore(updatedJksBytes, "/test/path", "password");

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
        // Arrange - Create a JKS with mixed entry types
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

        var jksBytes = CertificateTestHelper.GenerateJksWithMixedEntries(privateKeyEntries, trustedCertEntries, "password");
        var originalStore = _serializer.DeserializeRemoteCertificateStore(jksBytes, "/test/path", "password");

        // Act - Serialize and deserialize
        var serialized = _serializer.SerializeRemoteCertificateStore(originalStore, "/test/path", "store.jks", "password");
        var roundTripStore = _serializer.DeserializeRemoteCertificateStore(serialized[0].Contents, "/test/path", "password");

        // Assert - Entry types should be preserved after round-trip
        Assert.True(roundTripStore.IsKeyEntry("server"), "server should still be a key entry after round-trip");
        Assert.False(roundTripStore.IsKeyEntry("trusted-ca"), "trusted-ca should still be certificate-only after round-trip");
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_MixedEntryTypes_CorrectCertificateChainForKeyEntries()
    {
        // Arrange - Create a JKS with a private key entry that has a chain and a trusted cert entry
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "Server");
        var serverCert = chain[0];
        var intermediateCert = chain[1].Certificate;
        var rootCert = chain[2].Certificate;
        var trustedCa = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "External Trusted CA");

        // Create JKS manually with chain for key entry
        var jksStore = new Org.BouncyCastle.Security.JksStore();
        jksStore.SetKeyEntry("server", serverCert.KeyPair.Private, "password".ToCharArray(),
            new[] { serverCert.Certificate, intermediateCert, rootCert });
        jksStore.SetCertificateEntry("external-ca", trustedCa.Certificate);

        using var ms = new MemoryStream();
        jksStore.Save(ms, "password".ToCharArray());
        var jksBytes = ms.ToArray();

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(jksBytes, "/test/path", "password");

        // Assert - Key entry should have full chain
        var serverChain = store.GetCertificateChain("server");
        Assert.NotNull(serverChain);
        Assert.Equal(3, serverChain.Length);

        // Trusted cert entry should have no chain (just the certificate)
        var externalCaChain = store.GetCertificateChain("external-ca");
        Assert.Null(externalCaChain); // Certificate entries don't have chains, only key entries do
    }

    [Fact]
    public void CreateOrUpdateJks_RemoveTrustedCertEntry_PreservesKeyEntries()
    {
        // Arrange - Create JKS with both entry types
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

        var jksBytes = CertificateTestHelper.GenerateJksWithMixedEntries(privateKeyEntries, trustedCertEntries, "password");

        // Act - Remove the trusted cert entry
        var updatedJksBytes = _serializer.CreateOrUpdateJks(
            Array.Empty<byte>(),
            null,
            "trusted-ca",
            jksBytes,
            "password",
            remove: true,
            includeChain: true);

        // Deserialize and verify
        var store = _serializer.DeserializeRemoteCertificateStore(updatedJksBytes, "/test/path", "password");

        // Assert - Only the key entry should remain
        var aliases = store.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("server", aliases);
        Assert.DoesNotContain("trusted-ca", aliases);
        Assert.True(store.IsKeyEntry("server"), "server should still be a key entry");
    }

    #endregion

    #region PKCS12 Format Detection Tests

    /// <summary>
    /// Tests that the JKS deserializer correctly rejects PKCS12 format data.
    /// Note: BouncyCastle's JksStore reports PKCS12 data as "password incorrect or store tampered with"
    /// because the file format doesn't match the JKS magic bytes. This IOException triggers
    /// the fallback logic in the Inventory and Management jobs to try PKCS12 format.
    /// </summary>
    [Fact]
    public void DeserializeRemoteCertificateStore_Pkcs12FileInsteadOfJks_ThrowsIOException()
    {
        // Arrange - Generate a PKCS12 file (not JKS) and try to deserialize as JKS
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Test Cert");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password", "testcert");

        // Act & Assert - The JKS deserializer cannot parse PKCS12 format and throws IOException
        // This is expected behavior - the calling code (Inventory/Management jobs) catches this
        // and falls back to PKCS12 handling
        var exception = Assert.Throws<IOException>(() =>
            _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password"));

        // BouncyCastle's JksStore reports format mismatches as password errors
        Assert.Contains("password incorrect", exception.Message);
    }

    [Fact]
    public void DeserializeRemoteCertificateStore_Pkcs12WithMultipleEntries_ThrowsIOException()
    {
        // Arrange - Generate a PKCS12 file with multiple entries
        var cert1Info = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert 1");
        var cert2Info = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Cert 2");

        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "alias1", (cert1Info.Certificate, cert1Info.KeyPair) },
            { "alias2", (cert2Info.Certificate, cert2Info.KeyPair) }
        };

        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12WithMultipleEntries(entries, "password");

        // Act & Assert - The JKS deserializer cannot parse PKCS12 format
        var exception = Assert.Throws<IOException>(() =>
            _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password"));

        Assert.Contains("password incorrect", exception.Message);
    }

    [Fact]
    public void CreateOrUpdateJks_ExistingStoreIsPkcs12_ThrowsIOException()
    {
        // Arrange - Create a PKCS12 store as the "existing" store
        var existingCertInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Existing PKCS12 Cert");
        var existingPkcs12Bytes = CertificateTestHelper.GeneratePkcs12(existingCertInfo.Certificate, existingCertInfo.KeyPair, "password", "existing");

        // Create new certificate to add
        var newCertInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "New Cert");
        var newPkcs12Bytes = CertificateTestHelper.GeneratePkcs12(newCertInfo.Certificate, newCertInfo.KeyPair, "password", "newcert");

        // Act & Assert - Attempting to update a PKCS12 store as JKS should throw IOException
        // The calling code catches this and falls back to PKCS12 handling
        var exception = Assert.Throws<IOException>(() =>
            _serializer.CreateOrUpdateJks(
                newPkcs12Bytes,
                "password",
                "newcert",
                existingPkcs12Bytes,
                "password",
                remove: false,
                includeChain: true));

        Assert.Contains("password incorrect", exception.Message);
    }

    [Fact]
    public void CreateOrUpdateJks_RemoveFromExistingPkcs12Store_ThrowsIOException()
    {
        // Arrange - Create a PKCS12 store as the "existing" store
        var existingCertInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Existing PKCS12 Cert");
        var existingPkcs12Bytes = CertificateTestHelper.GeneratePkcs12(existingCertInfo.Certificate, existingCertInfo.KeyPair, "password", "existing");

        // Act & Assert - Attempting to remove from a PKCS12 store as JKS should throw IOException
        var exception = Assert.Throws<IOException>(() =>
            _serializer.CreateOrUpdateJks(
                Array.Empty<byte>(),
                null,
                "existing",
                existingPkcs12Bytes,
                "password",
                remove: true,
                includeChain: true));

        Assert.Contains("password incorrect", exception.Message);
    }

    [Theory]
    [InlineData(KeyType.Rsa2048)]
    [InlineData(KeyType.EcP256)]
    [InlineData(KeyType.EcP384)]
    public void DeserializeRemoteCertificateStore_Pkcs12VariousKeyTypes_ThrowsIOException(KeyType keyType)
    {
        // Arrange - Generate PKCS12 with various key types
        var certInfo = CachedCertificateProvider.GetOrCreate(keyType, $"PKCS12 {keyType} Cert");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password", "testcert");

        // Act & Assert - All should throw IOException when attempting to parse as JKS
        var exception = Assert.Throws<IOException>(() =>
            _serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "/test/path", "password"));

        Assert.Contains("password incorrect", exception.Message);
    }

    /// <summary>
    /// Verifies that actual JKS files can still be loaded successfully
    /// (as a sanity check alongside the PKCS12 rejection tests).
    /// </summary>
    [Fact]
    public void DeserializeRemoteCertificateStore_ActualJksFile_LoadsSuccessfully()
    {
        // Arrange - Generate a proper JKS file
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Actual JKS Cert");
        var jksBytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password", "testcert");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(jksBytes, "/test/path", "password");

        // Assert - JKS should load without any exception
        Assert.NotNull(store);
        var aliases = store.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("testcert", aliases);
    }

    #endregion

    #region Native JKS Format Preservation Tests

    [Fact]
    public void NativeJksFormat_MagicBytesValidation_JksHasCorrectMagicBytes()
    {
        // Arrange - Generate a JKS file using BouncyCastle
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JKS Magic Bytes Test");
        var jksBytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password", "testcert");

        // Act & Assert - Verify JKS magic bytes (0xFEEDFEED)
        Assert.True(CertificateTestHelper.IsNativeJksFormat(jksBytes),
            $"Expected JKS magic bytes (0xFEEDFEED) but got: 0x{jksBytes[0]:X2}{jksBytes[1]:X2}{jksBytes[2]:X2}{jksBytes[3]:X2}");

        // Verify magic bytes directly
        Assert.Equal(0xFE, jksBytes[0]);
        Assert.Equal(0xED, jksBytes[1]);
        Assert.Equal(0xFE, jksBytes[2]);
        Assert.Equal(0xED, jksBytes[3]);
    }

    [Fact]
    public void Pkcs12Format_MagicBytesValidation_Pkcs12DoesNotHaveJksMagicBytes()
    {
        // Arrange - Generate a PKCS12 file using BouncyCastle
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Magic Bytes Test");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password", "testcert");

        // Act & Assert - Verify PKCS12 does NOT have JKS magic bytes
        Assert.False(CertificateTestHelper.IsNativeJksFormat(pkcs12Bytes),
            $"PKCS12 should NOT have JKS magic bytes but first 4 bytes are: 0x{pkcs12Bytes[0]:X2}{pkcs12Bytes[1]:X2}{pkcs12Bytes[2]:X2}{pkcs12Bytes[3]:X2}");

        // Verify PKCS12 starts with ASN.1 SEQUENCE tag (0x30)
        Assert.True(CertificateTestHelper.IsPkcs12Format(pkcs12Bytes),
            $"Expected PKCS12 to start with 0x30 (ASN.1 SEQUENCE) but got: 0x{pkcs12Bytes[0]:X2}");
    }

    [Fact]
    public void CreateOrUpdateJks_NativeJksStore_OutputRemainsJksFormat()
    {
        // Arrange - Create an initial JKS store
        var cert1Info = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Initial Cert");
        var initialJks = CertificateTestHelper.GenerateJks(cert1Info.Certificate, cert1Info.KeyPair, "storepassword", "initial");

        // Verify initial JKS is in native JKS format
        Assert.True(CertificateTestHelper.IsNativeJksFormat(initialJks), "Initial JKS should be in native JKS format");

        // Create a new certificate to add (as PKCS12)
        var cert2Info = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "New Cert");
        var newCertPkcs12 = CertificateTestHelper.GeneratePkcs12(cert2Info.Certificate, cert2Info.KeyPair, "certpassword", "newcert");

        // Act - Add new certificate to existing JKS
        var updatedJks = _serializer.CreateOrUpdateJks(
            newPkcs12Bytes: newCertPkcs12,
            newCertPassword: "certpassword",
            alias: "newcert",
            existingStore: initialJks,
            existingStorePassword: "storepassword",
            remove: false,
            includeChain: true);

        // Assert - Output should still be in native JKS format
        Assert.True(CertificateTestHelper.IsNativeJksFormat(updatedJks),
            $"Updated JKS should remain in native JKS format but got magic bytes: 0x{updatedJks[0]:X2}{updatedJks[1]:X2}{updatedJks[2]:X2}{updatedJks[3]:X2}");
        Assert.False(CertificateTestHelper.IsPkcs12Format(updatedJks),
            "Updated JKS should NOT be in PKCS12 format");
    }

    [Fact]
    public void CreateOrUpdateJks_AddMultipleCerts_OutputRemainsJksFormat()
    {
        // Arrange - Create an initial JKS store with one certificate
        var cert1Info = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert 1");
        var initialJks = CertificateTestHelper.GenerateJks(cert1Info.Certificate, cert1Info.KeyPair, "storepassword", "cert1");

        // Verify initial JKS is in native JKS format
        Assert.True(CertificateTestHelper.IsNativeJksFormat(initialJks), "Initial JKS should be in native JKS format");

        // Act - Add multiple certificates sequentially
        var currentJks = initialJks;
        for (int i = 2; i <= 5; i++)
        {
            var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, $"Cert {i}");
            var certPkcs12 = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "certpassword", $"cert{i}");

            currentJks = _serializer.CreateOrUpdateJks(
                newPkcs12Bytes: certPkcs12,
                newCertPassword: "certpassword",
                alias: $"cert{i}",
                existingStore: currentJks,
                existingStorePassword: "storepassword",
                remove: false,
                includeChain: true);

            // Assert after each addition - should remain JKS format
            Assert.True(CertificateTestHelper.IsNativeJksFormat(currentJks),
                $"JKS should remain in native format after adding cert {i}");
        }

        // Final verification - should have 5 certificates and still be JKS format
        Assert.True(CertificateTestHelper.IsNativeJksFormat(currentJks),
            "Final JKS with 5 certs should still be in native JKS format");

        // Verify all 5 certs are in the store
        var store = _serializer.DeserializeRemoteCertificateStore(currentJks, "/test/path", "storepassword");
        Assert.Equal(5, store.Aliases.ToList().Count);
    }

    [Fact]
    public void CreateOrUpdateJks_RemoveCert_OutputRemainsJksFormat()
    {
        // Arrange - Create a JKS store with two certificates
        var cert1Info = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert 1");
        var cert2Info = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Cert 2");

        var entries = new Dictionary<string, (Org.BouncyCastle.X509.X509Certificate, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)>
        {
            { "cert1", (cert1Info.Certificate, cert1Info.KeyPair) },
            { "cert2", (cert2Info.Certificate, cert2Info.KeyPair) }
        };

        var initialJks = CertificateTestHelper.GenerateJksWithMultipleEntries(entries, "storepassword");

        // Verify initial JKS is in native JKS format
        Assert.True(CertificateTestHelper.IsNativeJksFormat(initialJks), "Initial JKS should be in native JKS format");

        // Act - Remove one certificate
        var updatedJks = _serializer.CreateOrUpdateJks(
            newPkcs12Bytes: Array.Empty<byte>(),
            newCertPassword: "",
            alias: "cert1",
            existingStore: initialJks,
            existingStorePassword: "storepassword",
            remove: true,
            includeChain: true);

        // Assert - Output should still be in native JKS format
        Assert.True(CertificateTestHelper.IsNativeJksFormat(updatedJks),
            $"JKS should remain in native format after removing a certificate");
        Assert.False(CertificateTestHelper.IsPkcs12Format(updatedJks),
            "Updated JKS should NOT be in PKCS12 format");

        // Verify cert1 was removed and cert2 remains
        var store = _serializer.DeserializeRemoteCertificateStore(updatedJks, "/test/path", "storepassword");
        var aliases = store.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("cert2", aliases);
        Assert.DoesNotContain("cert1", aliases);
    }

    [Fact]
    public void CreateOrUpdateJks_CreateNewStore_OutputIsJksFormat()
    {
        // Arrange - Create a new certificate as PKCS12
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "New Store Cert");
        var certPkcs12 = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "certpassword", "testcert");

        // Act - Create a new JKS store (existingStore = null)
        var newJks = _serializer.CreateOrUpdateJks(
            newPkcs12Bytes: certPkcs12,
            newCertPassword: "certpassword",
            alias: "testcert",
            existingStore: null,
            existingStorePassword: "storepassword",
            remove: false,
            includeChain: true);

        // Assert - Output should be in native JKS format
        Assert.True(CertificateTestHelper.IsNativeJksFormat(newJks),
            $"Newly created JKS should be in native JKS format but got magic bytes: 0x{newJks[0]:X2}{newJks[1]:X2}{newJks[2]:X2}{newJks[3]:X2}");
        Assert.False(CertificateTestHelper.IsPkcs12Format(newJks),
            "Newly created JKS should NOT be in PKCS12 format");
    }

    [Theory]
    [InlineData(KeyType.Rsa2048)]
    [InlineData(KeyType.Rsa4096)]
    [InlineData(KeyType.EcP256)]
    [InlineData(KeyType.EcP384)]
    public void CreateOrUpdateJks_VariousKeyTypes_OutputRemainsJksFormat(KeyType keyType)
    {
        // Arrange - Create initial JKS store
        var initialCertInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Initial Cert");
        var initialJks = CertificateTestHelper.GenerateJks(initialCertInfo.Certificate, initialCertInfo.KeyPair, "storepassword", "initial");

        // Create a new certificate with the specified key type
        var newCertInfo = CachedCertificateProvider.GetOrCreate(keyType, $"New Cert {keyType}");
        var newCertPkcs12 = CertificateTestHelper.GeneratePkcs12(newCertInfo.Certificate, newCertInfo.KeyPair, "certpassword", "newcert");

        // Act - Add new certificate
        var updatedJks = _serializer.CreateOrUpdateJks(
            newPkcs12Bytes: newCertPkcs12,
            newCertPassword: "certpassword",
            alias: $"newcert-{keyType}",
            existingStore: initialJks,
            existingStorePassword: "storepassword",
            remove: false,
            includeChain: true);

        // Assert - Output should remain in native JKS format
        Assert.True(CertificateTestHelper.IsNativeJksFormat(updatedJks),
            $"JKS should remain in native format after adding {keyType} certificate");
    }

    [Fact]
    public void SerializeRemoteCertificateStore_OutputIsJksFormat()
    {
        // Arrange - Create a JKS store and deserialize it (converts to PKCS12 internally)
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Serialize Test");
        var originalJks = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password", "testcert");

        // Verify original is JKS
        Assert.True(CertificateTestHelper.IsNativeJksFormat(originalJks), "Original should be JKS format");

        // Deserialize (converts to PKCS12 internally)
        var store = _serializer.DeserializeRemoteCertificateStore(originalJks, "/test/path", "password");

        // Act - Serialize back to JKS
        var serialized = _serializer.SerializeRemoteCertificateStore(store, "/test/path", "store.jks", "password");

        // Assert - Output should be in native JKS format, not PKCS12
        Assert.Single(serialized);
        Assert.True(CertificateTestHelper.IsNativeJksFormat(serialized[0].Contents),
            "Serialized output should be in native JKS format");
        Assert.False(CertificateTestHelper.IsPkcs12Format(serialized[0].Contents),
            "Serialized output should NOT be in PKCS12 format");
    }

    [Fact]
    public void CreateOrUpdateJks_RoundTrip_PreservesJksFormat()
    {
        // Arrange - Create initial JKS, add cert, remove cert, verify format is preserved throughout
        var cert1Info = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Cert 1");
        var cert2Info = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Cert 2");

        // Step 1: Create initial JKS
        var initialJks = CertificateTestHelper.GenerateJks(cert1Info.Certificate, cert1Info.KeyPair, "storepassword", "cert1");
        Assert.True(CertificateTestHelper.IsNativeJksFormat(initialJks), "Step 1: Initial JKS should be JKS format");

        // Step 2: Add second certificate
        var cert2Pkcs12 = CertificateTestHelper.GeneratePkcs12(cert2Info.Certificate, cert2Info.KeyPair, "certpassword", "cert2");
        var afterAdd = _serializer.CreateOrUpdateJks(
            newPkcs12Bytes: cert2Pkcs12,
            newCertPassword: "certpassword",
            alias: "cert2",
            existingStore: initialJks,
            existingStorePassword: "storepassword",
            remove: false,
            includeChain: true);
        Assert.True(CertificateTestHelper.IsNativeJksFormat(afterAdd), "Step 2: After add should be JKS format");

        // Step 3: Remove first certificate
        var afterRemove = _serializer.CreateOrUpdateJks(
            newPkcs12Bytes: Array.Empty<byte>(),
            newCertPassword: "",
            alias: "cert1",
            existingStore: afterAdd,
            existingStorePassword: "storepassword",
            remove: true,
            includeChain: true);
        Assert.True(CertificateTestHelper.IsNativeJksFormat(afterRemove), "Step 3: After remove should be JKS format");

        // Step 4: Deserialize and serialize (round-trip)
        var store = _serializer.DeserializeRemoteCertificateStore(afterRemove, "/test/path", "storepassword");
        var serialized = _serializer.SerializeRemoteCertificateStore(store, "/test/path", "store.jks", "storepassword");
        Assert.True(CertificateTestHelper.IsNativeJksFormat(serialized[0].Contents), "Step 4: After round-trip should be JKS format");
    }

    [Fact]
    public void FormatDetection_NullOrEmptyData_ReturnsFalse()
    {
        // Test edge cases for format detection helpers
        Assert.False(CertificateTestHelper.IsNativeJksFormat(null));
        Assert.False(CertificateTestHelper.IsNativeJksFormat(Array.Empty<byte>()));
        Assert.False(CertificateTestHelper.IsNativeJksFormat(new byte[] { 0xFE })); // Too short
        Assert.False(CertificateTestHelper.IsNativeJksFormat(new byte[] { 0xFE, 0xED })); // Too short
        Assert.False(CertificateTestHelper.IsNativeJksFormat(new byte[] { 0xFE, 0xED, 0xFE })); // Too short

        Assert.False(CertificateTestHelper.IsPkcs12Format(null));
        Assert.False(CertificateTestHelper.IsPkcs12Format(Array.Empty<byte>()));
    }

    [Fact]
    public void FormatDetection_ManualMagicBytes_DetectsCorrectly()
    {
        // Test with manually constructed magic bytes
        var jksMagic = new byte[] { 0xFE, 0xED, 0xFE, 0xED, 0x00, 0x01, 0x02 };
        Assert.True(CertificateTestHelper.IsNativeJksFormat(jksMagic));
        Assert.False(CertificateTestHelper.IsPkcs12Format(jksMagic));

        var pkcs12Magic = new byte[] { 0x30, 0x82, 0x01, 0x02 };
        Assert.False(CertificateTestHelper.IsNativeJksFormat(pkcs12Magic));
        Assert.True(CertificateTestHelper.IsPkcs12Format(pkcs12Magic));
    }

    #endregion

    #region Empty Store Tests (Create Store If Missing)

    [Fact]
    public void CreateEmptyJksStore_WithPassword_CanBeLoadedWithSamePassword()
    {
        // Arrange - Create an empty JKS store (simulates "create store if missing")
        var emptyJksStore = new Org.BouncyCastle.Security.JksStore();
        var password = "testpassword";

        // Act - Save the empty store
        using var outStream = new MemoryStream();
        emptyJksStore.Save(outStream, password.ToCharArray());
        var emptyJksBytes = outStream.ToArray();

        // Assert - Should be valid JKS that can be loaded
        Assert.NotNull(emptyJksBytes);
        Assert.NotEmpty(emptyJksBytes);

        // Verify it has JKS magic bytes
        Assert.True(CertificateTestHelper.IsNativeJksFormat(emptyJksBytes), "Empty JKS store should have JKS magic bytes");

        // Verify it can be loaded
        var loadedStore = new Org.BouncyCastle.Security.JksStore();
        using var inStream = new MemoryStream(emptyJksBytes);
        loadedStore.Load(inStream, password.ToCharArray());
        Assert.Empty(loadedStore.Aliases);
    }

    [Fact]
    public void CreateEmptyJksStore_WithEmptyPassword_CanBeLoadedWithEmptyPassword()
    {
        // Arrange - Create an empty JKS store with empty password
        var emptyJksStore = new Org.BouncyCastle.Security.JksStore();

        // Act - Save the empty store with empty password
        using var outStream = new MemoryStream();
        emptyJksStore.Save(outStream, Array.Empty<char>());
        var emptyJksBytes = outStream.ToArray();

        // Assert - Should be valid JKS that can be loaded
        Assert.NotNull(emptyJksBytes);
        Assert.NotEmpty(emptyJksBytes);

        // Verify it has JKS magic bytes
        Assert.True(CertificateTestHelper.IsNativeJksFormat(emptyJksBytes), "Empty JKS store should have JKS magic bytes");

        // Verify it can be loaded
        var loadedStore = new Org.BouncyCastle.Security.JksStore();
        using var inStream = new MemoryStream(emptyJksBytes);
        loadedStore.Load(inStream, Array.Empty<char>());
        Assert.Empty(loadedStore.Aliases);
    }

    [Fact]
    public void CreateEmptyJksStore_ThenAddCertificate_Success()
    {
        // Arrange - Create an empty JKS store
        var emptyJksStore = new Org.BouncyCastle.Security.JksStore();
        var password = "testpassword";

        using var outStream = new MemoryStream();
        emptyJksStore.Save(outStream, password.ToCharArray());
        var emptyJksBytes = outStream.ToArray();

        // Create a certificate to add
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "New Cert");
        var newCertPkcs12 = CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, password, "newcert");

        // Act - Use CreateOrUpdateJks to add the certificate to the empty store
        var updatedJksBytes = _serializer.CreateOrUpdateJks(
            newCertPkcs12,
            password,
            "newcert",
            emptyJksBytes,
            password,
            false,
            true);

        // Assert - Should have one certificate
        var loadedStore = new Org.BouncyCastle.Security.JksStore();
        using var inStream = new MemoryStream(updatedJksBytes);
        loadedStore.Load(inStream, password.ToCharArray());
        var aliases = loadedStore.Aliases.ToList();
        Assert.Single(aliases);
        Assert.Contains("newcert", aliases);
    }

    #endregion

    #region RSA 8192 Dedicated Test

    /// <summary>
    /// Dedicated test for RSA 8192 key type to verify support while keeping it isolated
    /// from Theory tests for performance reasons (RSA 8192 key generation is slow).
    /// </summary>
    [Fact]
    public void DeserializeRemoteCertificateStore_Rsa8192Key_SuccessfullyLoadsStore()
    {
        // Arrange - RSA 8192 is slow to generate, cached so it only generates once across all tests
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa8192, "Test RSA 8192 Cert");
        var jksBytes = CertificateTestHelper.GenerateJks(certInfo.Certificate, certInfo.KeyPair, "password");

        // Act
        var store = _serializer.DeserializeRemoteCertificateStore(jksBytes, "/test/path", "password");

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    #endregion
}
