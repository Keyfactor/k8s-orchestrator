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
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Test PKCS12 Cert");
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
        var certInfo = CertificateTestHelper.GenerateCertificate();
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
        var certInfo = CertificateTestHelper.GenerateCertificate();
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
        var certInfo = CertificateTestHelper.GenerateCertificate();
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
    [InlineData(KeyType.Rsa8192)]
    public void DeserializeRemoteCertificateStore_RsaKeys_SuccessfullyLoadsStore(KeyType keyType)
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Test {keyType} Cert");
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
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Test {keyType} Cert");
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
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Test {keyType} Cert");
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
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Test {keyType} Cert");
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
        var certInfo = CertificateTestHelper.GenerateCertificate();
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
        var certInfo = CertificateTestHelper.GenerateCertificate();
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
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048, "Leaf", "Intermediate", "Root");
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
        var certInfo = CertificateTestHelper.GenerateCertificate();
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
        var cert1Info = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Cert 1");
        var cert2Info = CertificateTestHelper.GenerateCertificate(KeyType.EcP256, "Cert 2");
        var cert3Info = CertificateTestHelper.GenerateCertificate(KeyType.Rsa4096, "Cert 3");

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
        var certInfo = CertificateTestHelper.GenerateCertificate();
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
        var certInfo = CertificateTestHelper.GenerateCertificate();
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
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
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
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
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
        var chain = CertificateTestHelper.GenerateCertificateChain(keyType);
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
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
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
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
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

    #region Edge Case Tests

    [Fact]
    public void DeserializeRemoteCertificateStore_PartiallyCorruptedData_ThrowsException()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
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
        var certInfo = CertificateTestHelper.GenerateCertificate();
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
        var certInfo = CertificateTestHelper.GenerateCertificate();
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
}
