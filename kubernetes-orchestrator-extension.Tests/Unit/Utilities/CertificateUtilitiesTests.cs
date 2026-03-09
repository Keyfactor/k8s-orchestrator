// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Keyfactor.PKI.PEM;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Utilities;

public class CertificateUtilitiesTests
{
    #region ParseCertificate Tests

    [Fact]
    public void ParseCertificate_NullData_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => CertificateUtilities.ParseCertificate(null));
    }

    [Fact]
    public void ParseCertificate_EmptyData_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => CertificateUtilities.ParseCertificate(Array.Empty<byte>()));
    }

    [Fact]
    public void ParseCertificate_PemFormat_ReturnsCertificate()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "ParseCert PEM Test");
        var pem = PemUtilities.DERToPEM(certInfo.Certificate.GetEncoded(), PemUtilities.PemObjectType.Certificate);
        var pemBytes = Encoding.UTF8.GetBytes(pem);

        var result = CertificateUtilities.ParseCertificate(pemBytes);

        Assert.NotNull(result);
        Assert.Contains("ParseCert PEM Test", result.SubjectDN.ToString());
    }

    [Fact]
    public void ParseCertificate_DerFormat_ReturnsCertificate()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "ParseCert DER Test");
        var derBytes = certInfo.Certificate.GetEncoded();

        var result = CertificateUtilities.ParseCertificate(derBytes);

        Assert.NotNull(result);
        Assert.Contains("ParseCert DER Test", result.SubjectDN.ToString());
    }

    [Fact]
    public void ParseCertificate_ExplicitPemFormat_ReturnsCertificate()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "ParseCert Explicit PEM");
        var pem = PemUtilities.DERToPEM(certInfo.Certificate.GetEncoded(), PemUtilities.PemObjectType.Certificate);
        var pemBytes = Encoding.UTF8.GetBytes(pem);

        var result = CertificateUtilities.ParseCertificate(pemBytes, CertificateFormat.Pem);

        Assert.NotNull(result);
    }

    [Fact]
    public void ParseCertificate_ExplicitDerFormat_ReturnsCertificate()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "ParseCert Explicit DER");
        var derBytes = certInfo.Certificate.GetEncoded();

        var result = CertificateUtilities.ParseCertificate(derBytes, CertificateFormat.Der);

        Assert.NotNull(result);
    }

    [Fact]
    public void ParseCertificate_Pkcs12Format_ThrowsArgumentException()
    {
        var pkcs12 = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.EcP256);

        Assert.Throws<ArgumentException>(() =>
            CertificateUtilities.ParseCertificate(pkcs12, CertificateFormat.Pkcs12));
    }

    #endregion

    #region ParseCertificateFromDer Tests

    [Fact]
    public void ParseCertificateFromDer_NullBytes_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => CertificateUtilities.ParseCertificateFromDer(null));
    }

    [Fact]
    public void ParseCertificateFromDer_EmptyBytes_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => CertificateUtilities.ParseCertificateFromDer(Array.Empty<byte>()));
    }

    [Fact]
    public void ParseCertificateFromDer_ValidDer_ReturnsCert()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "DER Valid Test");
        var derBytes = certInfo.Certificate.GetEncoded();

        var result = CertificateUtilities.ParseCertificateFromDer(derBytes);

        Assert.NotNull(result);
        Assert.Contains("DER Valid Test", result.SubjectDN.ToString());
    }

    #endregion

    #region ParseCertificateFromPkcs12 Tests

    [Fact]
    public void ParseCertificateFromPkcs12_NullBytes_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            CertificateUtilities.ParseCertificateFromPkcs12(null, "pass"));
    }

    [Fact]
    public void ParseCertificateFromPkcs12_EmptyBytes_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            CertificateUtilities.ParseCertificateFromPkcs12(Array.Empty<byte>(), "pass"));
    }

    [Fact]
    public void ParseCertificateFromPkcs12_ValidStore_ReturnsCertificate()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "PKCS12 Parse Test");
        var pkcs12 = GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "testpass", "myalias");

        var result = CertificateUtilities.ParseCertificateFromPkcs12(pkcs12, "testpass");

        Assert.NotNull(result);
        Assert.Contains("PKCS12 Parse Test", result.SubjectDN.ToString());
    }

    [Fact]
    public void ParseCertificateFromPkcs12_WithSpecificAlias_ReturnsCertificate()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "PKCS12 Alias Test");
        var pkcs12 = GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "testpass", "myalias");

        var result = CertificateUtilities.ParseCertificateFromPkcs12(pkcs12, "testpass", "myalias");

        Assert.NotNull(result);
    }

    [Fact]
    public void ParseCertificateFromPkcs12_NoKeyEntry_ThrowsArgumentException()
    {
        // Create a PKCS12 store with only a trusted cert entry (no key entry)
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "No Key Entry");
        var store = new Pkcs12StoreBuilder().Build();
        store.SetCertificateEntry("trustedcert", new X509CertificateEntry(certInfo.Certificate));

        using var ms = new System.IO.MemoryStream();
        store.Save(ms, "pass".ToCharArray(), new Org.BouncyCastle.Security.SecureRandom());
        var pkcs12Bytes = ms.ToArray();

        Assert.Throws<ArgumentException>(() =>
            CertificateUtilities.ParseCertificateFromPkcs12(pkcs12Bytes, "pass"));
    }

    #endregion

    #region Certificate Property Tests

    [Fact]
    public void GetSubjectDN_NullCert_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.GetSubjectDN(null));
    }

    [Fact]
    public void GetSubjectDN_ValidCert_ReturnsDN()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "SubjectDN Test");
        var result = CertificateUtilities.GetSubjectDN(certInfo.Certificate);
        Assert.Contains("SubjectDN Test", result);
    }

    [Fact]
    public void GetIssuerCN_NullCert_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.GetIssuerCN(null));
    }

    [Fact]
    public void GetIssuerCN_ValidCert_ReturnsCN()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "IssuerCN Test");
        var result = CertificateUtilities.GetIssuerCN(certInfo.Certificate);
        Assert.NotNull(result);
    }

    [Fact]
    public void GetIssuerDN_NullCert_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.GetIssuerDN(null));
    }

    [Fact]
    public void GetNotBefore_NullCert_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.GetNotBefore(null));
    }

    [Fact]
    public void GetNotBefore_ValidCert_ReturnsDate()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "NotBefore Test");
        var result = CertificateUtilities.GetNotBefore(certInfo.Certificate);
        Assert.True(result <= DateTime.UtcNow.AddMinutes(1));
    }

    [Fact]
    public void GetNotAfter_NullCert_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.GetNotAfter(null));
    }

    [Fact]
    public void GetNotAfter_ValidCert_ReturnsDate()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "NotAfter Test");
        var result = CertificateUtilities.GetNotAfter(certInfo.Certificate);
        Assert.True(result > DateTime.UtcNow);
    }

    [Fact]
    public void GetKeyAlgorithm_NullCert_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.GetKeyAlgorithm(null));
    }

    [Fact]
    public void GetKeyAlgorithm_RsaCert_ReturnsRSA()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "RSA Algo Test");
        var result = CertificateUtilities.GetKeyAlgorithm(certInfo.Certificate);
        Assert.Equal("RSA", result);
    }

    [Fact]
    public void GetKeyAlgorithm_EcdsaCert_ReturnsECDSA()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "ECDSA Algo Test");
        var result = CertificateUtilities.GetKeyAlgorithm(certInfo.Certificate);
        Assert.Equal("ECDSA", result);
    }

    [Fact]
    public void GetPublicKey_NullCert_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.GetPublicKey(null));
    }

    [Fact]
    public void GetPublicKey_ValidCert_ReturnsBytes()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "PublicKey Test");
        var result = CertificateUtilities.GetPublicKey(certInfo.Certificate);
        Assert.NotNull(result);
        Assert.True(result.Length > 0);
    }

    #endregion

    #region ExtractPrivateKey Tests

    [Fact]
    public void ExtractPrivateKey_NullStore_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.ExtractPrivateKey(null));
    }

    [Fact]
    public void ExtractPrivateKey_ValidStore_ReturnsKey()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "ExtractKey Test");
        var pkcs12 = GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "pass", "testalias");
        var store = CertificateUtilities.LoadPkcs12Store(pkcs12, "pass");

        var result = CertificateUtilities.ExtractPrivateKey(store);

        Assert.NotNull(result);
        Assert.True(result.IsPrivate);
    }

    [Fact]
    public void ExtractPrivateKey_WithSpecificAlias_ReturnsKey()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "ExtractKey Alias Test");
        var pkcs12 = GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "pass", "myalias");
        var store = CertificateUtilities.LoadPkcs12Store(pkcs12, "pass");

        var result = CertificateUtilities.ExtractPrivateKey(store, "myalias");

        Assert.NotNull(result);
    }

    [Fact]
    public void ExtractPrivateKey_NonKeyAlias_ThrowsArgumentException()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "NonKey Alias");
        var store = new Pkcs12StoreBuilder().Build();
        store.SetCertificateEntry("certonly", new X509CertificateEntry(certInfo.Certificate));

        Assert.Throws<ArgumentException>(() =>
            CertificateUtilities.ExtractPrivateKey(store, "certonly"));
    }

    [Fact]
    public void ExtractPrivateKey_NoKeyEntries_ThrowsArgumentException()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "No Keys");
        var store = new Pkcs12StoreBuilder().Build();
        store.SetCertificateEntry("certonly", new X509CertificateEntry(certInfo.Certificate));

        Assert.Throws<ArgumentException>(() => CertificateUtilities.ExtractPrivateKey(store));
    }

    #endregion

    #region ExtractPrivateKeyAsPem Tests

    [Fact]
    public void ExtractPrivateKeyAsPem_NullKey_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.ExtractPrivateKeyAsPem(null));
    }

    [Fact]
    public void ExtractPrivateKeyAsPem_RsaKey_ReturnsPem()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "RSA PEM Key");
        var result = CertificateUtilities.ExtractPrivateKeyAsPem(certInfo.KeyPair.Private);

        Assert.Contains("-----BEGIN RSA PRIVATE KEY-----", result);
        Assert.Contains("-----END RSA PRIVATE KEY-----", result);
    }

    [Fact]
    public void ExtractPrivateKeyAsPem_EcKey_ReturnsPem()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "EC PEM Key");
        var result = CertificateUtilities.ExtractPrivateKeyAsPem(certInfo.KeyPair.Private);

        Assert.Contains("-----BEGIN EC PRIVATE KEY-----", result);
        Assert.Contains("-----END EC PRIVATE KEY-----", result);
    }

    [Fact]
    public void ExtractPrivateKeyAsPem_ExplicitKeyType_UsesProvidedType()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Explicit KeyType");
        var result = CertificateUtilities.ExtractPrivateKeyAsPem(certInfo.KeyPair.Private, "PRIVATE KEY");

        Assert.Contains("-----BEGIN PRIVATE KEY-----", result);
    }

    #endregion

    #region ExportPrivateKeyPkcs8 Tests

    [Fact]
    public void ExportPrivateKeyPkcs8_NullKey_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.ExportPrivateKeyPkcs8(null));
    }

    [Fact]
    public void ExportPrivateKeyPkcs8_ValidKey_ReturnsBytes()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "PKCS8 Export");
        var result = CertificateUtilities.ExportPrivateKeyPkcs8(certInfo.KeyPair.Private);

        Assert.NotNull(result);
        Assert.True(result.Length > 0);
    }

    #endregion

    #region GetPrivateKeyType Tests

    [Fact]
    public void GetPrivateKeyType_NullKey_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.GetPrivateKeyType(null));
    }

    [Fact]
    public void GetPrivateKeyType_RsaKey_ReturnsRSA()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "RSA Type");
        Assert.Equal("RSA", CertificateUtilities.GetPrivateKeyType(certInfo.KeyPair.Private));
    }

    [Fact]
    public void GetPrivateKeyType_EcKey_ReturnsEC()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "EC Type");
        Assert.Equal("EC", CertificateUtilities.GetPrivateKeyType(certInfo.KeyPair.Private));
    }

    #endregion

    #region Chain Operations Tests

    [Fact]
    public void LoadCertificateChain_NullData_ReturnsEmptyList()
    {
        var result = CertificateUtilities.LoadCertificateChain(null);
        Assert.Empty(result);
    }

    [Fact]
    public void LoadCertificateChain_EmptyData_ReturnsEmptyList()
    {
        var result = CertificateUtilities.LoadCertificateChain("");
        Assert.Empty(result);
    }

    [Fact]
    public void LoadCertificateChain_ValidChainPem_ReturnsCertificates()
    {
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.EcP256, "Chain Load Test");
        var sb = new StringBuilder();
        foreach (var ci in chain)
        {
            sb.AppendLine(PemUtilities.DERToPEM(ci.Certificate.GetEncoded(), PemUtilities.PemObjectType.Certificate));
        }

        var result = CertificateUtilities.LoadCertificateChain(sb.ToString());

        Assert.Equal(chain.Count, result.Count);
    }

    [Fact]
    public void LoadCertificateChain_SingleCert_ReturnsOne()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Single Chain Cert");
        var pem = PemUtilities.DERToPEM(certInfo.Certificate.GetEncoded(), PemUtilities.PemObjectType.Certificate);

        var result = CertificateUtilities.LoadCertificateChain(pem);

        Assert.Single(result);
    }

    [Fact]
    public void ExtractChainFromPkcs12_NullBytes_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            CertificateUtilities.ExtractChainFromPkcs12(null, "pass"));
    }

    [Fact]
    public void ExtractChainFromPkcs12_ValidStore_ReturnsChain()
    {
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.EcP256, "Chain Extract");
        var leafInfo = chain[0];
        var chainCerts = new X509Certificate[chain.Count - 1];
        for (int i = 1; i < chain.Count; i++)
            chainCerts[i - 1] = chain[i].Certificate;

        var pkcs12 = GeneratePkcs12WithChain(
            leafInfo.Certificate, leafInfo.KeyPair.Private, chainCerts, "pass", "leaf");

        var result = CertificateUtilities.ExtractChainFromPkcs12(pkcs12, "pass", "leaf");

        Assert.NotNull(result);
        Assert.True(result.Count >= 1);
    }

    [Fact]
    public void ExtractChainFromPkcs12_NoKeyEntry_ReturnsEmptyList()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "No Key Chain");
        var store = new Pkcs12StoreBuilder().Build();
        store.SetCertificateEntry("certonly", new X509CertificateEntry(certInfo.Certificate));

        using var ms = new System.IO.MemoryStream();
        store.Save(ms, "pass".ToCharArray(), new Org.BouncyCastle.Security.SecureRandom());

        var result = CertificateUtilities.ExtractChainFromPkcs12(ms.ToArray(), "pass");
        Assert.Empty(result);
    }

    #endregion

    #region DetectFormat Tests

    [Fact]
    public void DetectFormat_NullData_ReturnsUnknown()
    {
        Assert.Equal(CertificateFormat.Unknown, CertificateUtilities.DetectFormat(null));
    }

    [Fact]
    public void DetectFormat_EmptyData_ReturnsUnknown()
    {
        Assert.Equal(CertificateFormat.Unknown, CertificateUtilities.DetectFormat(Array.Empty<byte>()));
    }

    [Fact]
    public void DetectFormat_PemData_ReturnsPem()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Detect PEM");
        var pem = PemUtilities.DERToPEM(certInfo.Certificate.GetEncoded(), PemUtilities.PemObjectType.Certificate);
        Assert.Equal(CertificateFormat.Pem, CertificateUtilities.DetectFormat(Encoding.UTF8.GetBytes(pem)));
    }

    [Fact]
    public void DetectFormat_DerData_ReturnsDer()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Detect DER");
        var der = certInfo.Certificate.GetEncoded();
        Assert.Equal(CertificateFormat.Der, CertificateUtilities.DetectFormat(der));
    }

    [Fact]
    public void DetectFormat_RandomData_ReturnsUnknown()
    {
        var randomData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        Assert.Equal(CertificateFormat.Unknown, CertificateUtilities.DetectFormat(randomData));
    }

    #endregion

    #region ConvertToPem/ConvertToDer Tests

    [Fact]
    public void ConvertToDer_NullCert_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.ConvertToDer(null));
    }

    [Fact]
    public void ConvertToDer_ValidCert_ReturnsBytes()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "Convert DER");
        var der = CertificateUtilities.ConvertToDer(certInfo.Certificate);
        Assert.NotNull(der);
        Assert.True(der.Length > 0);
    }

    #endregion

    #region LoadPkcs12Store Tests

    [Fact]
    public void LoadPkcs12Store_NullData_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => CertificateUtilities.LoadPkcs12Store(null, "pass"));
    }

    [Fact]
    public void LoadPkcs12Store_EmptyData_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => CertificateUtilities.LoadPkcs12Store(Array.Empty<byte>(), "pass"));
    }

    [Fact]
    public void LoadPkcs12Store_ValidData_ReturnsStore()
    {
        var pkcs12 = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.EcP256, "pass", "test");
        var store = CertificateUtilities.LoadPkcs12Store(pkcs12, "pass");
        Assert.NotNull(store);
        Assert.True(store.Aliases.Any());
    }

    [Fact]
    public void LoadPkcs12Store_WrongPassword_Throws()
    {
        var pkcs12 = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.EcP256, "correctpass", "test");
        Assert.ThrowsAny<Exception>(() => CertificateUtilities.LoadPkcs12Store(pkcs12, "wrongpass"));
    }

    #endregion

    #region IsDerFormat Tests

    [Fact]
    public void IsDerFormat_ValidDer_ReturnsTrue()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "IsDer Test");
        Assert.True(CertificateUtilities.IsDerFormat(certInfo.Certificate.GetEncoded()));
    }

    [Fact]
    public void IsDerFormat_InvalidData_ReturnsFalse()
    {
        Assert.False(CertificateUtilities.IsDerFormat(new byte[] { 0x01, 0x02, 0x03 }));
    }

    [Fact]
    public void IsDerFormat_NullData_ReturnsFalse()
    {
        Assert.False(CertificateUtilities.IsDerFormat(null));
    }

    #endregion
}
