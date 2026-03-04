// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.IO;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Clients;

public class KeystoreManagerTests
{
    private readonly KeystoreManager _manager = new();

    #region Test Certificate Generation

    private static (X509Certificate cert, AsymmetricCipherKeyPair keyPair) GenerateTestCertificate(
        string subjectCn = "Test Certificate")
    {
        var random = new SecureRandom();
        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(new KeyGenerationParameters(random, 2048));
        var keyPair = keyPairGenerator.GenerateKeyPair();

        var certGen = new X509V3CertificateGenerator();
        var subjectDN = new X509Name($"CN={subjectCn}");

        certGen.SetSerialNumber(BigInteger.ProbablePrime(120, random));
        certGen.SetIssuerDN(subjectDN);
        certGen.SetSubjectDN(subjectDN);
        certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGen.SetPublicKey(keyPair.Public);

        var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private, random);
        var certificate = certGen.Generate(signatureFactory);

        return (certificate, keyPair);
    }

    private static byte[] GeneratePkcs12(
        X509Certificate cert,
        AsymmetricCipherKeyPair keyPair,
        string password = "password",
        string alias = "testcert")
    {
        var store = new Pkcs12StoreBuilder().Build();
        var certEntry = new X509CertificateEntry(cert);
        var certChain = new X509CertificateEntry[] { certEntry };

        store.SetKeyEntry(alias, new AsymmetricKeyEntry(keyPair.Private), certChain);

        using var ms = new MemoryStream();
        store.Save(ms, password.ToCharArray(), new SecureRandom());
        return ms.ToArray();
    }

    #endregion

    #region LoadPkcs12Store Tests

    [Fact]
    public void LoadPkcs12Store_ValidData_ReturnsStore()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair);

        // Act
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Assert
        Assert.NotNull(store);
        Assert.True(store.Count > 0);
    }

    [Fact]
    public void LoadPkcs12Store_NullBytes_ReturnsNull()
    {
        // Act
        var store = _manager.LoadPkcs12Store(null, "password");

        // Assert
        Assert.Null(store);
    }

    [Fact]
    public void LoadPkcs12Store_EmptyBytes_ReturnsNull()
    {
        // Act
        var store = _manager.LoadPkcs12Store(Array.Empty<byte>(), "password");

        // Assert
        Assert.Null(store);
    }

    [Fact]
    public void LoadPkcs12Store_NullPassword_LoadsWithEmptyPassword()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, password: "");

        // Act
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, null);

        // Assert
        Assert.NotNull(store);
    }

    #endregion

    #region SavePkcs12Store Tests

    [Fact]
    public void SavePkcs12Store_ValidStore_ReturnsByteArray()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair);
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var savedBytes = _manager.SavePkcs12Store(store, "newpassword");

        // Assert
        Assert.NotNull(savedBytes);
        Assert.NotEmpty(savedBytes);
    }

    [Fact]
    public void SavePkcs12Store_NullStore_ReturnsEmptyArray()
    {
        // Act
        var savedBytes = _manager.SavePkcs12Store(null, "password");

        // Assert
        Assert.NotNull(savedBytes);
        Assert.Empty(savedBytes);
    }

    [Fact]
    public void SavePkcs12Store_RoundTrip_PreservesData()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate("RoundTrip Test");
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, password: "original", alias: "roundtrip");
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "original");

        // Act
        var savedBytes = _manager.SavePkcs12Store(store, "newpassword");
        var reloadedStore = _manager.LoadPkcs12Store(savedBytes, "newpassword");

        // Assert
        Assert.NotNull(reloadedStore);
        Assert.True(reloadedStore.ContainsAlias("roundtrip"));
    }

    #endregion

    #region CreateEmptyStore Tests

    [Fact]
    public void CreateEmptyStore_ReturnsEmptyStore()
    {
        // Act
        var store = _manager.CreateEmptyStore();

        // Assert
        Assert.NotNull(store);
        Assert.Equal(0, store.Count);
    }

    #endregion

    #region FindAliasByCn Tests

    [Fact]
    public void FindAliasByCn_MatchingCn_ReturnsAlias()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate("Find Me");
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, alias: "myalias");
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var foundAlias = _manager.FindAliasByCn(store, "Find Me");

        // Assert
        Assert.Equal("myalias", foundAlias);
    }

    [Fact]
    public void FindAliasByCn_NonMatchingCn_ReturnsNull()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate("Different CN");
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, alias: "myalias");
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var foundAlias = _manager.FindAliasByCn(store, "Not Found");

        // Assert
        Assert.Null(foundAlias);
    }

    [Fact]
    public void FindAliasByCn_CaseInsensitive_ReturnsAlias()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate("Case Test");
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, alias: "myalias");
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var foundAlias = _manager.FindAliasByCn(store, "CASE TEST");

        // Assert
        Assert.Equal("myalias", foundAlias);
    }

    [Fact]
    public void FindAliasByCn_NullStore_ReturnsNull()
    {
        // Act
        var foundAlias = _manager.FindAliasByCn(null, "Test");

        // Assert
        Assert.Null(foundAlias);
    }

    [Fact]
    public void FindAliasByCn_NullCn_ReturnsNull()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair);
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var foundAlias = _manager.FindAliasByCn(store, null);

        // Assert
        Assert.Null(foundAlias);
    }

    #endregion

    #region FindAliasByThumbprint Tests

    [Fact]
    public void FindAliasByThumbprint_MatchingThumbprint_ReturnsAlias()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate("Thumbprint Test");
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, alias: "thumbprintalias");
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Calculate the thumbprint
        var certBytes = cert.GetEncoded();
        using var sha1 = System.Security.Cryptography.SHA1.Create();
        var hash = sha1.ComputeHash(certBytes);
        var thumbprint = BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();

        // Act
        var foundAlias = _manager.FindAliasByThumbprint(store, thumbprint);

        // Assert
        Assert.Equal("thumbprintalias", foundAlias);
    }

    [Fact]
    public void FindAliasByThumbprint_NonMatchingThumbprint_ReturnsNull()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair);
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var foundAlias = _manager.FindAliasByThumbprint(store, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        // Assert
        Assert.Null(foundAlias);
    }

    [Fact]
    public void FindAliasByThumbprint_NullStore_ReturnsNull()
    {
        // Act
        var foundAlias = _manager.FindAliasByThumbprint(null, "AAAA");

        // Assert
        Assert.Null(foundAlias);
    }

    #endregion

    #region FindAliasByName Tests

    [Fact]
    public void FindAliasByName_ExactMatch_ReturnsAlias()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, alias: "exactalias");
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var foundAlias = _manager.FindAliasByName(store, "exactalias");

        // Assert
        Assert.Equal("exactalias", foundAlias);
    }

    [Fact]
    public void FindAliasByName_CaseInsensitiveMatch_ReturnsActualAlias()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, alias: "CaseSensitive");
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var foundAlias = _manager.FindAliasByName(store, "CASESENSITIVE");

        // Assert - The case-insensitive search returns the actual alias from the store
        // Note: The actual casing depends on how BouncyCastle stores aliases
        Assert.NotNull(foundAlias);
        Assert.True(foundAlias.Equals("CaseSensitive", System.StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void FindAliasByName_FallbackToCn_ReturnsAlias()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate("Search By CN");
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, alias: "differentalias");
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var foundAlias = _manager.FindAliasByName(store, "Search By CN");

        // Assert
        Assert.Equal("differentalias", foundAlias);
    }

    [Fact]
    public void FindAliasByName_NullStore_ReturnsNull()
    {
        // Act
        var foundAlias = _manager.FindAliasByName(null, "test");

        // Assert
        Assert.Null(foundAlias);
    }

    [Fact]
    public void FindAliasByName_NullSearch_ReturnsNull()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair);
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var foundAlias = _manager.FindAliasByName(store, null);

        // Assert
        Assert.Null(foundAlias);
    }

    #endregion

    #region DeleteEntry Tests

    [Fact]
    public void DeleteEntry_ExistingAlias_ReturnsTrue()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, alias: "deleteme");
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var result = _manager.DeleteEntry(store, "deleteme");

        // Assert
        Assert.True(result);
        Assert.False(store.ContainsAlias("deleteme"));
    }

    [Fact]
    public void DeleteEntry_NonExistingAlias_ReturnsFalse()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, alias: "existing");
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var result = _manager.DeleteEntry(store, "nonexistent");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void DeleteEntry_NullStore_ReturnsFalse()
    {
        // Act
        var result = _manager.DeleteEntry(null, "test");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void DeleteEntry_NullAlias_ReturnsFalse()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair);
        var store = _manager.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var result = _manager.DeleteEntry(store, null);

        // Assert
        Assert.False(result);
    }

    #endregion
}
