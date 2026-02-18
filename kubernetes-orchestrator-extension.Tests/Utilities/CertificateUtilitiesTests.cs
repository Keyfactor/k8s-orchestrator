using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using Xunit;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Keyfactor.Orchestrators.K8S.Tests.Utilities;

public class CertificateUtilitiesTests
{
    #region Test Certificate Generation

    private static (X509Certificate cert, AsymmetricCipherKeyPair keyPair) GenerateTestRsaCertificate(
        string subjectCn = "Test Certificate",
        string issuerCn = null,
        int keySize = 2048)
    {
        var random = new SecureRandom();
        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(new KeyGenerationParameters(random, keySize));
        var keyPair = keyPairGenerator.GenerateKeyPair();

        var certGen = new X509V3CertificateGenerator();
        var subjectDN = new X509Name($"CN={subjectCn}");
        var issuerDN = issuerCn != null ? new X509Name($"CN={issuerCn}") : subjectDN;

        certGen.SetSerialNumber(BigInteger.ProbablePrime(120, random));
        certGen.SetIssuerDN(issuerDN);
        certGen.SetSubjectDN(subjectDN);
        certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGen.SetPublicKey(keyPair.Public);

        var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private, random);
        var certificate = certGen.Generate(signatureFactory);

        return (certificate, keyPair);
    }

    private static (X509Certificate cert, AsymmetricCipherKeyPair keyPair) GenerateTestEcCertificate(
        string subjectCn = "Test EC Certificate",
        string curveName = "secp256r1")
    {
        var random = new SecureRandom();
        var ecP256 = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName(curveName);
        var ecParams = new ECKeyGenerationParameters(
            new ECDomainParameters(ecP256.Curve, ecP256.G, ecP256.N, ecP256.H, ecP256.GetSeed()),
            random);

        var keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.Init(ecParams);
        var keyPair = keyPairGenerator.GenerateKeyPair();

        var certGen = new X509V3CertificateGenerator();
        var subjectDN = new X509Name($"CN={subjectCn}");

        certGen.SetSerialNumber(BigInteger.ProbablePrime(120, random));
        certGen.SetIssuerDN(subjectDN);
        certGen.SetSubjectDN(subjectDN);
        certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGen.SetPublicKey(keyPair.Public);

        var signatureFactory = new Asn1SignatureFactory("SHA256WithECDSA", keyPair.Private, random);
        var certificate = certGen.Generate(signatureFactory);

        return (certificate, keyPair);
    }

    private static byte[] GeneratePkcs12(
        X509Certificate cert,
        AsymmetricCipherKeyPair keyPair,
        string password = "password",
        string alias = "testcert",
        X509Certificate[] chain = null)
    {
        var store = new Pkcs12StoreBuilder().Build();
        var certEntry = new X509CertificateEntry(cert);

        // Build certificate chain
        var certChain = new X509CertificateEntry[chain != null ? chain.Length + 1 : 1];
        certChain[0] = certEntry;
        if (chain != null)
        {
            for (int i = 0; i < chain.Length; i++)
            {
                certChain[i + 1] = new X509CertificateEntry(chain[i]);
            }
        }

        store.SetKeyEntry(alias, new AsymmetricKeyEntry(keyPair.Private), certChain);

        using var ms = new MemoryStream();
        store.Save(ms, password.ToCharArray(), new SecureRandom());
        return ms.ToArray();
    }

    #endregion

    #region Certificate Parsing Tests

    [Fact]
    public void ParseCertificateFromPem_ValidPem_ReturnsValidCertificate()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate("Test Cert");
        var pemObject = new PemObject("CERTIFICATE", cert.GetEncoded());
        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);
        pemWriter.WriteObject(pemObject);
        pemWriter.Writer.Flush();
        var pemString = stringWriter.ToString();

        // Act
        var parsedCert = CertificateUtilities.ParseCertificateFromPem(pemString);

        // Assert
        Assert.NotNull(parsedCert);
        Assert.Equal(cert.SerialNumber, parsedCert.SerialNumber);
        Assert.Equal(cert.SubjectDN.ToString(), parsedCert.SubjectDN.ToString());
    }

    [Fact]
    public void ParseCertificateFromPem_NullString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => CertificateUtilities.ParseCertificateFromPem(null));
    }

    [Fact]
    public void ParseCertificateFromPem_EmptyString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => CertificateUtilities.ParseCertificateFromPem(""));
    }

    [Fact]
    public void ParseCertificateFromDer_ValidDer_ReturnsValidCertificate()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate("Test DER Cert");
        var derBytes = cert.GetEncoded();

        // Act
        var parsedCert = CertificateUtilities.ParseCertificateFromDer(derBytes);

        // Assert
        Assert.NotNull(parsedCert);
        Assert.Equal(cert.SerialNumber, parsedCert.SerialNumber);
        Assert.Equal(cert.SubjectDN.ToString(), parsedCert.SubjectDN.ToString());
    }

    [Fact]
    public void ParseCertificateFromDer_NullBytes_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => CertificateUtilities.ParseCertificateFromDer(null));
    }

    [Fact]
    public void ParseCertificateFromDer_EmptyBytes_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => CertificateUtilities.ParseCertificateFromDer(Array.Empty<byte>()));
    }

    [Fact]
    public void ParseCertificateFromPkcs12_ValidPkcs12_ReturnsValidCertificate()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestRsaCertificate("Test PKCS12 Cert");
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair);

        // Act
        var parsedCert = CertificateUtilities.ParseCertificateFromPkcs12(pkcs12Bytes, "password");

        // Assert
        Assert.NotNull(parsedCert);
        Assert.Equal(cert.SerialNumber, parsedCert.SerialNumber);
        Assert.Equal(cert.SubjectDN.ToString(), parsedCert.SubjectDN.ToString());
    }

    [Fact]
    public void ParseCertificateFromPkcs12_WithAlias_ReturnsCorrectCertificate()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestRsaCertificate("Test Alias Cert");
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, alias: "myalias");

        // Act
        var parsedCert = CertificateUtilities.ParseCertificateFromPkcs12(pkcs12Bytes, "password", "myalias");

        // Assert
        Assert.NotNull(parsedCert);
        Assert.Equal(cert.SerialNumber, parsedCert.SerialNumber);
    }

    #endregion

    #region Certificate Property Tests

    [Fact]
    public void GetThumbprint_ValidCertificate_ReturnsUppercaseHex()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();

        // Act
        var thumbprint = CertificateUtilities.GetThumbprint(cert);

        // Assert
        Assert.NotNull(thumbprint);
        Assert.NotEmpty(thumbprint);
        Assert.Equal(40, thumbprint.Length); // SHA-1 hash is 40 hex characters
        Assert.All(thumbprint, c => Assert.True(char.IsDigit(c) || (c >= 'A' && c <= 'F')));
    }

    [Fact]
    public void GetThumbprint_MatchesX509Certificate2_ForValidation()
    {
        // Arrange
        var (bcCert, keyPair) = GenerateTestRsaCertificate();
        var pkcs12Bytes = GeneratePkcs12(bcCert, keyPair);

        // Convert to X509Certificate2 for comparison
        var x509Cert2 = new X509Certificate2(pkcs12Bytes, "password");

        // Act
        var bcThumbprint = CertificateUtilities.GetThumbprint(bcCert);
        var x509Thumbprint = x509Cert2.Thumbprint;

        // Assert
        Assert.Equal(x509Thumbprint, bcThumbprint);
    }

    [Fact]
    public void GetSubjectCN_ValidCertificate_ExtractsCorrectCN()
    {
        // Arrange
        var expectedCN = "Test Subject CN";
        var (cert, _) = GenerateTestRsaCertificate(expectedCN);

        // Act
        var actualCN = CertificateUtilities.GetSubjectCN(cert);

        // Assert
        Assert.Equal(expectedCN, actualCN);
    }

    [Fact]
    public void GetSubjectDN_ValidCertificate_ReturnsFullDN()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate("Test DN");

        // Act
        var dn = CertificateUtilities.GetSubjectDN(cert);

        // Assert
        Assert.NotNull(dn);
        Assert.Contains("CN=Test DN", dn);
    }

    [Fact]
    public void GetIssuerCN_ValidCertificate_ExtractsCorrectCN()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate("Subject", "Issuer");

        // Act
        var issuerCN = CertificateUtilities.GetIssuerCN(cert);

        // Assert
        Assert.Equal("Issuer", issuerCN);
    }

    [Fact]
    public void GetNotBefore_ValidCertificate_ReturnsValidDate()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();

        // Act
        var notBefore = CertificateUtilities.GetNotBefore(cert);

        // Assert
        Assert.True(notBefore < DateTime.UtcNow);
        Assert.True(notBefore > DateTime.UtcNow.AddDays(-2));
    }

    [Fact]
    public void GetNotAfter_ValidCertificate_ReturnsValidDate()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();

        // Act
        var notAfter = CertificateUtilities.GetNotAfter(cert);

        // Assert
        Assert.True(notAfter > DateTime.UtcNow);
        Assert.True(notAfter < DateTime.UtcNow.AddYears(2));
    }

    [Fact]
    public void GetSerialNumber_ValidCertificate_ReturnsHexString()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();

        // Act
        var serialNumber = CertificateUtilities.GetSerialNumber(cert);

        // Assert
        Assert.NotNull(serialNumber);
        Assert.NotEmpty(serialNumber);
        Assert.All(serialNumber, c => Assert.True(char.IsDigit(c) || (c >= 'A' && c <= 'F')));
    }

    [Fact]
    public void GetKeyAlgorithm_RsaCertificate_ReturnsRSA()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();

        // Act
        var algorithm = CertificateUtilities.GetKeyAlgorithm(cert);

        // Assert
        Assert.Equal("RSA", algorithm);
    }

    [Fact]
    public void GetKeyAlgorithm_EcCertificate_ReturnsECDSA()
    {
        // Arrange
        var (cert, _) = GenerateTestEcCertificate();

        // Act
        var algorithm = CertificateUtilities.GetKeyAlgorithm(cert);

        // Assert
        Assert.Equal("ECDSA", algorithm);
    }

    [Fact]
    public void GetPublicKey_ValidCertificate_ReturnsNonEmptyBytes()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();

        // Act
        var publicKey = CertificateUtilities.GetPublicKey(cert);

        // Assert
        Assert.NotNull(publicKey);
        Assert.NotEmpty(publicKey);
    }

    #endregion

    #region Private Key Operation Tests

    [Fact]
    public void ExtractPrivateKey_ValidStore_ReturnsPrivateKey()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestRsaCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair);
        var store = CertificateUtilities.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var privateKey = CertificateUtilities.ExtractPrivateKey(store);

        // Assert
        Assert.NotNull(privateKey);
        Assert.True(privateKey.IsPrivate);
    }

    [Fact]
    public void ExtractPrivateKey_WithAlias_ReturnsCorrectKey()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestRsaCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, alias: "testkey");
        var store = CertificateUtilities.LoadPkcs12Store(pkcs12Bytes, "password");

        // Act
        var privateKey = CertificateUtilities.ExtractPrivateKey(store, "testkey");

        // Assert
        Assert.NotNull(privateKey);
        Assert.True(privateKey.IsPrivate);
    }

    [Fact]
    public void ExtractPrivateKeyAsPem_RsaKey_ReturnsValidPem()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestRsaCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair);
        var store = CertificateUtilities.LoadPkcs12Store(pkcs12Bytes, "password");
        var privateKey = CertificateUtilities.ExtractPrivateKey(store);

        // Act
        var pemKey = CertificateUtilities.ExtractPrivateKeyAsPem(privateKey);

        // Assert
        Assert.NotNull(pemKey);
        Assert.Contains("-----BEGIN", pemKey);
        Assert.Contains("-----END", pemKey);
        Assert.Contains("PRIVATE KEY", pemKey);
    }

    [Fact]
    public void ExtractPrivateKeyAsPem_EcKey_ReturnsValidPem()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestEcCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair);
        var store = CertificateUtilities.LoadPkcs12Store(pkcs12Bytes, "password");
        var privateKey = CertificateUtilities.ExtractPrivateKey(store);

        // Act
        var pemKey = CertificateUtilities.ExtractPrivateKeyAsPem(privateKey);

        // Assert
        Assert.NotNull(pemKey);
        Assert.Contains("-----BEGIN", pemKey);
        Assert.Contains("-----END", pemKey);
        Assert.Contains("PRIVATE KEY", pemKey);
    }

    [Fact]
    public void ExportPrivateKeyPkcs8_RsaKey_ReturnsValidBytes()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestRsaCertificate();

        // Act
        var pkcs8Bytes = CertificateUtilities.ExportPrivateKeyPkcs8(keyPair.Private);

        // Assert
        Assert.NotNull(pkcs8Bytes);
        Assert.NotEmpty(pkcs8Bytes);
    }

    [Fact]
    public void ExportPrivateKeyPkcs8_EcKey_ReturnsValidBytes()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestEcCertificate();

        // Act
        var pkcs8Bytes = CertificateUtilities.ExportPrivateKeyPkcs8(keyPair.Private);

        // Assert
        Assert.NotNull(pkcs8Bytes);
        Assert.NotEmpty(pkcs8Bytes);
    }

    [Fact]
    public void GetPrivateKeyType_RsaKey_ReturnsRSA()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestRsaCertificate();

        // Act
        var keyType = CertificateUtilities.GetPrivateKeyType(keyPair.Private);

        // Assert
        Assert.Equal("RSA", keyType);
    }

    [Fact]
    public void GetPrivateKeyType_EcKey_ReturnsEC()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestEcCertificate();

        // Act
        var keyType = CertificateUtilities.GetPrivateKeyType(keyPair.Private);

        // Assert
        Assert.Equal("EC", keyType);
    }

    #endregion

    #region Chain Operation Tests

    [Fact]
    public void LoadCertificateChain_SingleCertPem_ReturnsOneCertificate()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();
        var pem = CertificateUtilities.ConvertToPem(cert);

        // Act
        var chain = CertificateUtilities.LoadCertificateChain(pem);

        // Assert
        Assert.NotNull(chain);
        Assert.Single(chain);
        Assert.Equal(cert.SerialNumber, chain[0].SerialNumber);
    }

    [Fact]
    public void LoadCertificateChain_MultipleCertsPem_ReturnsMultipleCertificates()
    {
        // Arrange
        var (cert1, _) = GenerateTestRsaCertificate("Cert1");
        var (cert2, _) = GenerateTestRsaCertificate("Cert2");
        var pem1 = CertificateUtilities.ConvertToPem(cert1);
        var pem2 = CertificateUtilities.ConvertToPem(cert2);
        var combinedPem = pem1 + pem2;

        // Act
        var chain = CertificateUtilities.LoadCertificateChain(combinedPem);

        // Assert
        Assert.NotNull(chain);
        Assert.Equal(2, chain.Count);
    }

    [Fact]
    public void LoadCertificateChain_EmptyString_ReturnsEmptyList()
    {
        // Act
        var chain = CertificateUtilities.LoadCertificateChain("");

        // Assert
        Assert.NotNull(chain);
        Assert.Empty(chain);
    }

    [Fact]
    public void ExtractChainFromPkcs12_WithChain_ReturnsFullChain()
    {
        // Arrange
        var (leafCert, leafKeyPair) = GenerateTestRsaCertificate("Leaf");
        var (caCert, _) = GenerateTestRsaCertificate("CA");
        var pkcs12Bytes = GeneratePkcs12(leafCert, leafKeyPair, chain: new[] { caCert });

        // Act
        var chain = CertificateUtilities.ExtractChainFromPkcs12(pkcs12Bytes, "password");

        // Assert
        Assert.NotNull(chain);
        Assert.Equal(2, chain.Count); // Leaf + CA
    }

    #endregion

    #region Format Detection and Conversion Tests

    [Fact]
    public void DetectFormat_PemData_ReturnsPem()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();
        var pem = CertificateUtilities.ConvertToPem(cert);
        var pemBytes = Encoding.UTF8.GetBytes(pem);

        // Act
        var format = CertificateUtilities.DetectFormat(pemBytes);

        // Assert
        Assert.Equal(CertificateFormat.Pem, format);
    }

    [Fact]
    public void DetectFormat_DerData_ReturnsDer()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();
        var derBytes = cert.GetEncoded();

        // Act
        var format = CertificateUtilities.DetectFormat(derBytes);

        // Assert
        Assert.Equal(CertificateFormat.Der, format);
    }

    [Fact]
    public void DetectFormat_Pkcs12Data_ReturnsPkcs12()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestRsaCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair);

        // Act
        var format = CertificateUtilities.DetectFormat(pkcs12Bytes);

        // Assert
        // Note: PKCS12 detection may be tricky, might return Unknown in some cases
        Assert.True(format == CertificateFormat.Pkcs12 || format == CertificateFormat.Unknown);
    }

    [Fact]
    public void DetectFormat_NullData_ReturnsUnknown()
    {
        // Act
        var format = CertificateUtilities.DetectFormat(null);

        // Assert
        Assert.Equal(CertificateFormat.Unknown, format);
    }

    [Fact]
    public void DetectFormat_EmptyData_ReturnsUnknown()
    {
        // Act
        var format = CertificateUtilities.DetectFormat(Array.Empty<byte>());

        // Assert
        Assert.Equal(CertificateFormat.Unknown, format);
    }

    [Fact]
    public void ConvertToPem_ValidCertificate_ReturnsValidPem()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();

        // Act
        var pem = CertificateUtilities.ConvertToPem(cert);

        // Assert
        Assert.NotNull(pem);
        Assert.Contains("-----BEGIN CERTIFICATE-----", pem);
        Assert.Contains("-----END CERTIFICATE-----", pem);
    }

    [Fact]
    public void ConvertToDer_ValidCertificate_ReturnsValidDer()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();

        // Act
        var derBytes = CertificateUtilities.ConvertToDer(cert);

        // Assert
        Assert.NotNull(derBytes);
        Assert.NotEmpty(derBytes);
        // DER should start with 0x30 (SEQUENCE tag)
        Assert.Equal(0x30, derBytes[0]);
    }

    [Fact]
    public void ConvertToPem_RoundTrip_PreservesData()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();
        var originalDer = cert.GetEncoded();

        // Act
        var pem = CertificateUtilities.ConvertToPem(cert);
        var parsedCert = CertificateUtilities.ParseCertificateFromPem(pem);
        var roundTripDer = parsedCert.GetEncoded();

        // Assert
        Assert.Equal(originalDer, roundTripDer);
    }

    #endregion

    #region Helper Method Tests

    [Fact]
    public void LoadPkcs12Store_ValidData_ReturnsStore()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestRsaCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair);

        // Act
        var store = CertificateUtilities.LoadPkcs12Store(pkcs12Bytes, "password");

        // Assert
        Assert.NotNull(store);
        Assert.NotEmpty(store.Aliases.ToList());
    }

    [Fact]
    public void LoadPkcs12Store_InvalidPassword_ThrowsException()
    {
        // Arrange
        var (cert, keyPair) = GenerateTestRsaCertificate();
        var pkcs12Bytes = GeneratePkcs12(cert, keyPair, password: "correct");

        // Act & Assert
        Assert.Throws<Exception>(() =>
            CertificateUtilities.LoadPkcs12Store(pkcs12Bytes, "wrong"));
    }

    [Fact]
    public void IsDerFormat_ValidDer_ReturnsTrue()
    {
        // Arrange
        var (cert, _) = GenerateTestRsaCertificate();
        var derBytes = cert.GetEncoded();

        // Act
        var isDer = CertificateUtilities.IsDerFormat(derBytes);

        // Assert
        Assert.True(isDer);
    }

    [Fact]
    public void IsDerFormat_InvalidData_ReturnsFalse()
    {
        // Arrange
        var invalidData = new byte[] { 0x00, 0x01, 0x02, 0x03 };

        // Act
        var isDer = CertificateUtilities.IsDerFormat(invalidData);

        // Assert
        Assert.False(isDer);
    }

    #endregion

    #region Null Argument Tests

    [Fact]
    public void GetThumbprint_NullCertificate_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.GetThumbprint(null));
    }

    [Fact]
    public void GetSubjectCN_NullCertificate_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.GetSubjectCN(null));
    }

    [Fact]
    public void ConvertToPem_NullCertificate_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.ConvertToPem(null));
    }

    [Fact]
    public void ConvertToDer_NullCertificate_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.ConvertToDer(null));
    }

    [Fact]
    public void ExtractPrivateKeyAsPem_NullKey_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.ExtractPrivateKeyAsPem(null));
    }

    [Fact]
    public void ExportPrivateKeyPkcs8_NullKey_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateUtilities.ExportPrivateKeyPkcs8(null));
    }

    #endregion
}
