// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Keyfactor.Orchestrators.K8S.Tests.Helpers;

/// <summary>
/// Comprehensive test helper for generating certificates with various key types, sizes, and configurations.
/// Supports RSA, EC, DSA, Ed25519, and Ed448 key types for comprehensive testing.
/// </summary>
public static class CertificateTestHelper
{
    private static readonly SecureRandom Random = new SecureRandom();

    public enum KeyType
    {
        Rsa1024,
        Rsa2048,
        Rsa4096,
        Rsa8192,
        EcP256,    // secp256r1 / prime256v1
        EcP384,    // secp384r1
        EcP521,    // secp521r1
        Dsa1024,
        Dsa2048,
        Ed25519,
        Ed448
    }

    public class CertificateInfo
    {
        public X509Certificate Certificate { get; set; }
        public AsymmetricCipherKeyPair KeyPair { get; set; }
        public KeyType KeyType { get; set; }
        public string SubjectCN { get; set; }
        public string IssuerCN { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
    }

    #region Key Pair Generation

    /// <summary>
    /// Generates an RSA key pair with the specified key size.
    /// </summary>
    public static AsymmetricCipherKeyPair GenerateRsaKeyPair(int keySize)
    {
        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(new KeyGenerationParameters(Random, keySize));
        return keyPairGenerator.GenerateKeyPair();
    }

    /// <summary>
    /// Generates an EC key pair with the specified curve.
    /// </summary>
    public static AsymmetricCipherKeyPair GenerateEcKeyPair(string curveName)
    {
        var ecParams = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName(curveName);
        var domainParams = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());
        var keyGenParams = new ECKeyGenerationParameters(domainParams, Random);

        var keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.Init(keyGenParams);
        return keyPairGenerator.GenerateKeyPair();
    }

    /// <summary>
    /// Generates a DSA key pair with the specified key size.
    /// For key sizes > 1024 bits, uses FIPS 186-3/4 style generation with SHA-256.
    /// </summary>
    public static AsymmetricCipherKeyPair GenerateDsaKeyPair(int keySize)
    {
        DsaParametersGenerator paramGen;

        if (keySize <= 1024)
        {
            // Legacy DSA (FIPS 186-2): must use SHA-1 for key size 512-1024
            paramGen = new DsaParametersGenerator();
            paramGen.Init(keySize, 80, Random);
        }
        else
        {
            // FIPS 186-3/4 style: use SHA-256 for larger keys
            // For 2048-bit keys, use 256-bit q (N) per FIPS 186-3
            paramGen = new DsaParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
            var dsaParamGenParams = new DsaParameterGenerationParameters(
                keySize, 256, 80, Random);
            paramGen.Init(dsaParamGenParams);
        }

        var dsaParams = paramGen.GenerateParameters();

        var keyGenParams = new DsaKeyGenerationParameters(Random, dsaParams);
        var keyPairGenerator = new DsaKeyPairGenerator();
        keyPairGenerator.Init(keyGenParams);
        return keyPairGenerator.GenerateKeyPair();
    }

    /// <summary>
    /// Generates an Ed25519 key pair.
    /// </summary>
    public static AsymmetricCipherKeyPair GenerateEd25519KeyPair()
    {
        var keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.Init(new Ed25519KeyGenerationParameters(Random));
        return keyPairGenerator.GenerateKeyPair();
    }

    /// <summary>
    /// Generates an Ed448 key pair.
    /// </summary>
    public static AsymmetricCipherKeyPair GenerateEd448KeyPair()
    {
        var keyPairGenerator = new Ed448KeyPairGenerator();
        keyPairGenerator.Init(new Ed448KeyGenerationParameters(Random));
        return keyPairGenerator.GenerateKeyPair();
    }

    /// <summary>
    /// Generates a key pair based on the specified key type.
    /// </summary>
    public static AsymmetricCipherKeyPair GenerateKeyPair(KeyType keyType)
    {
        return keyType switch
        {
            KeyType.Rsa1024 => GenerateRsaKeyPair(1024),
            KeyType.Rsa2048 => GenerateRsaKeyPair(2048),
            KeyType.Rsa4096 => GenerateRsaKeyPair(4096),
            KeyType.Rsa8192 => GenerateRsaKeyPair(8192),
            KeyType.EcP256 => GenerateEcKeyPair("secp256r1"),
            KeyType.EcP384 => GenerateEcKeyPair("secp384r1"),
            KeyType.EcP521 => GenerateEcKeyPair("secp521r1"),
            KeyType.Dsa1024 => GenerateDsaKeyPair(1024),
            KeyType.Dsa2048 => GenerateDsaKeyPair(2048),
            KeyType.Ed25519 => GenerateEd25519KeyPair(),
            KeyType.Ed448 => GenerateEd448KeyPair(),
            _ => throw new ArgumentException($"Unsupported key type: {keyType}")
        };
    }

    #endregion

    #region Certificate Generation

    /// <summary>
    /// Gets the appropriate signature algorithm for the given key type.
    /// </summary>
    private static string GetSignatureAlgorithm(KeyType keyType)
    {
        return keyType switch
        {
            KeyType.Rsa1024 or KeyType.Rsa2048 or KeyType.Rsa4096 or KeyType.Rsa8192 => "SHA256WithRSA",
            KeyType.EcP256 or KeyType.EcP384 or KeyType.EcP521 => "SHA256WithECDSA",
            KeyType.Dsa1024 or KeyType.Dsa2048 => "SHA256WithDSA",
            KeyType.Ed25519 => "Ed25519",
            KeyType.Ed448 => "Ed448",
            _ => throw new ArgumentException($"Unsupported key type: {keyType}")
        };
    }

    /// <summary>
    /// Generates a test certificate with the specified parameters.
    /// </summary>
    public static CertificateInfo GenerateCertificate(
        KeyType keyType = KeyType.Rsa2048,
        string subjectCN = "Test Certificate",
        string issuerCN = null,
        DateTime? notBefore = null,
        DateTime? notAfter = null,
        AsymmetricCipherKeyPair signingKeyPair = null)
    {
        var keyPair = GenerateKeyPair(keyType);
        var actualIssuerCN = issuerCN ?? subjectCN;
        var actualNotBefore = notBefore ?? DateTime.UtcNow.AddDays(-1);
        var actualNotAfter = notAfter ?? DateTime.UtcNow.AddYears(1);

        var certGen = new X509V3CertificateGenerator();
        var subjectDN = new X509Name($"CN={subjectCN}");
        var issuerDN = new X509Name($"CN={actualIssuerCN}");

        certGen.SetSerialNumber(BigInteger.ProbablePrime(120, Random));
        certGen.SetIssuerDN(issuerDN);
        certGen.SetSubjectDN(subjectDN);
        certGen.SetNotBefore(actualNotBefore);
        certGen.SetNotAfter(actualNotAfter);
        certGen.SetPublicKey(keyPair.Public);

        // Use signing key pair if provided (for CA-signed certs), otherwise self-sign
        var signingKey = signingKeyPair?.Private ?? keyPair.Private;
        var signatureAlgorithm = GetSignatureAlgorithm(keyType);
        var signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, signingKey, Random);
        var certificate = certGen.Generate(signatureFactory);

        return new CertificateInfo
        {
            Certificate = certificate,
            KeyPair = keyPair,
            KeyType = keyType,
            SubjectCN = subjectCN,
            IssuerCN = actualIssuerCN,
            NotBefore = actualNotBefore,
            NotAfter = actualNotAfter
        };
    }

    /// <summary>
    /// Generates a certificate chain (leaf -> intermediate -> root).
    /// </summary>
    public static List<CertificateInfo> GenerateCertificateChain(
        KeyType keyType = KeyType.Rsa2048,
        string leafCN = "Leaf Certificate",
        string intermediateCN = "Intermediate CA",
        string rootCN = "Root CA")
    {
        // Generate root CA (self-signed)
        var rootInfo = GenerateCertificate(
            keyType: keyType,
            subjectCN: rootCN,
            issuerCN: rootCN);

        // Generate intermediate CA (signed by root)
        var intermediateInfo = GenerateCertificate(
            keyType: keyType,
            subjectCN: intermediateCN,
            issuerCN: rootCN,
            signingKeyPair: rootInfo.KeyPair);

        // Generate leaf certificate (signed by intermediate)
        var leafInfo = GenerateCertificate(
            keyType: keyType,
            subjectCN: leafCN,
            issuerCN: intermediateCN,
            signingKeyPair: intermediateInfo.KeyPair);

        return new List<CertificateInfo> { leafInfo, intermediateInfo, rootInfo };
    }

    #endregion

    #region PKCS12 Generation

    /// <summary>
    /// Generates a PKCS12/PFX store with the specified certificate and options.
    /// </summary>
    public static byte[] GeneratePkcs12(
        X509Certificate certificate,
        AsymmetricCipherKeyPair keyPair,
        string password = "password",
        string alias = "testcert",
        X509Certificate[] chain = null)
    {
        var store = new Pkcs12StoreBuilder().Build();
        var certEntry = new X509CertificateEntry(certificate);

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
        store.Save(ms, password.ToCharArray(), Random);
        return ms.ToArray();
    }

    /// <summary>
    /// Generates a PKCS12 store with multiple certificates/aliases.
    /// </summary>
    public static byte[] GeneratePkcs12WithMultipleEntries(
        Dictionary<string, (X509Certificate cert, AsymmetricCipherKeyPair keyPair)> entries,
        string password = "password")
    {
        var store = new Pkcs12StoreBuilder().Build();

        foreach (var kvp in entries)
        {
            var alias = kvp.Key;
            var (cert, keyPair) = kvp.Value;

            var certEntry = new X509CertificateEntry(cert);
            var certChain = new[] { certEntry };

            store.SetKeyEntry(alias, new AsymmetricKeyEntry(keyPair.Private), certChain);
        }

        using var ms = new MemoryStream();
        store.Save(ms, password.ToCharArray(), Random);
        return ms.ToArray();
    }

    /// <summary>
    /// Generates a PKCS12 with a certificate chain.
    /// Convenience wrapper for GeneratePkcs12 with explicit chain parameter.
    /// </summary>
    public static byte[] GeneratePkcs12WithChain(
        X509Certificate leafCertificate,
        AsymmetricKeyParameter privateKey,
        X509Certificate[] chain,
        string password = "password",
        string alias = "testcert")
    {
        // Create key pair from private key (public key is in the certificate)
        var keyPair = new AsymmetricCipherKeyPair(leafCertificate.GetPublicKey(), privateKey);
        return GeneratePkcs12(leafCertificate, keyPair, password, alias, chain);
    }

    #endregion

    #region JKS Generation

    /// <summary>
    /// Generates a JKS keystore with the specified certificate and options.
    /// Uses BouncyCastle's JksStore implementation.
    /// </summary>
    public static byte[] GenerateJks(
        X509Certificate certificate,
        AsymmetricCipherKeyPair keyPair,
        string password = "password",
        string alias = "testcert",
        X509Certificate[] chain = null)
    {
        var jksStore = new Org.BouncyCastle.Security.JksStore();

        // Build certificate chain
        var certChain = new X509Certificate[chain != null ? chain.Length + 1 : 1];
        certChain[0] = certificate;
        if (chain != null)
        {
            Array.Copy(chain, 0, certChain, 1, chain.Length);
        }

        jksStore.SetKeyEntry(alias, keyPair.Private, password.ToCharArray(), certChain);

        using var ms = new MemoryStream();
        jksStore.Save(ms, password.ToCharArray());
        return ms.ToArray();
    }

    /// <summary>
    /// Generates a JKS keystore with multiple certificates/aliases.
    /// Uses BouncyCastle's JksStore implementation.
    /// </summary>
    public static byte[] GenerateJksWithMultipleEntries(
        Dictionary<string, (X509Certificate cert, AsymmetricCipherKeyPair keyPair)> entries,
        string password = "password")
    {
        var jksStore = new Org.BouncyCastle.Security.JksStore();

        foreach (var kvp in entries)
        {
            var alias = kvp.Key;
            var (cert, keyPair) = kvp.Value;

            jksStore.SetKeyEntry(alias, keyPair.Private, password.ToCharArray(), new[] { cert });
        }

        using var ms = new MemoryStream();
        jksStore.Save(ms, password.ToCharArray());
        return ms.ToArray();
    }

    #endregion

    #region PEM Conversion

    /// <summary>
    /// Converts a certificate to PEM format.
    /// </summary>
    public static string ConvertCertificateToPem(X509Certificate certificate)
    {
        using var stringWriter = new StringWriter();
        var pemWriter = new Org.BouncyCastle.Utilities.IO.Pem.PemWriter(stringWriter);
        pemWriter.WriteObject(new PemObject("CERTIFICATE", certificate.GetEncoded()));
        pemWriter.Writer.Flush();
        return stringWriter.ToString();
    }

    /// <summary>
    /// Converts a private key to PEM format (PKCS#8).
    /// </summary>
    public static string ConvertPrivateKeyToPem(AsymmetricKeyParameter privateKey)
    {
        using var stringWriter = new StringWriter();
        var pemWriter = new Org.BouncyCastle.Utilities.IO.Pem.PemWriter(stringWriter);

        var pkcs8 = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
        pemWriter.WriteObject(new PemObject("PRIVATE KEY", pkcs8.GetEncoded()));
        pemWriter.Writer.Flush();
        return stringWriter.ToString();
    }

    /// <summary>
    /// Generates a PKCS#10 Certificate Signing Request (CSR) in PEM format using .NET CertificateRequest.
    /// This produces CSRs that are compatible with Kubernetes API server validation.
    /// </summary>
    public static string GenerateCertificateRequest(KeyType keyType, string subjectName)
    {
        // Generate key pair using BouncyCastle
        var keyInfo = GenerateKeyPair(keyType);

        // Convert to .NET types and create CSR
        byte[] csrDer;

        switch (keyType)
        {
            case KeyType.Rsa1024:
            case KeyType.Rsa2048:
            case KeyType.Rsa4096:
            case KeyType.Rsa8192:
                // Convert BouncyCastle RSA key to .NET RSA
                var rsaParams = (RsaPrivateCrtKeyParameters)keyInfo.Private;
                using (var rsa = RSA.Create())
                {
                    rsa.ImportParameters(new RSAParameters
                    {
                        Modulus = rsaParams.Modulus.ToByteArrayUnsigned(),
                        Exponent = rsaParams.PublicExponent.ToByteArrayUnsigned(),
                        D = rsaParams.Exponent.ToByteArrayUnsigned(),
                        P = rsaParams.P.ToByteArrayUnsigned(),
                        Q = rsaParams.Q.ToByteArrayUnsigned(),
                        DP = rsaParams.DP.ToByteArrayUnsigned(),
                        DQ = rsaParams.DQ.ToByteArrayUnsigned(),
                        InverseQ = rsaParams.QInv.ToByteArrayUnsigned()
                    });

                    // Create certificate request
                    var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                        $"CN={subjectName}",
                        rsa,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                    csrDer = request.CreateSigningRequest();
                }
                break;

            case KeyType.EcP256:
            case KeyType.EcP384:
            case KeyType.EcP521:
                // Convert BouncyCastle EC key to .NET ECDsa
                var ecParams = (ECPrivateKeyParameters)keyInfo.Private;
                using (var ecdsa = ECDsa.Create())
                {
                    // Map curve
                    ECCurve curve = keyType switch
                    {
                        KeyType.EcP256 => ECCurve.NamedCurves.nistP256,
                        KeyType.EcP384 => ECCurve.NamedCurves.nistP384,
                        KeyType.EcP521 => ECCurve.NamedCurves.nistP521,
                        _ => throw new NotSupportedException($"Unsupported EC curve: {keyType}")
                    };

                    var ecPoint = ((ECPublicKeyParameters)keyInfo.Public).Q;
                    ecdsa.ImportParameters(new ECParameters
                    {
                        Curve = curve,
                        D = ecParams.D.ToByteArrayUnsigned(),
                        Q = new ECPoint
                        {
                            X = ecPoint.AffineXCoord.ToBigInteger().ToByteArrayUnsigned(),
                            Y = ecPoint.AffineYCoord.ToBigInteger().ToByteArrayUnsigned()
                        }
                    });

                    var hashAlgorithm = keyType switch
                    {
                        KeyType.EcP256 => HashAlgorithmName.SHA256,
                        KeyType.EcP384 => HashAlgorithmName.SHA384,
                        KeyType.EcP521 => HashAlgorithmName.SHA512,
                        _ => HashAlgorithmName.SHA256
                    };

                    var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                        $"CN={subjectName}",
                        ecdsa,
                        hashAlgorithm);

                    csrDer = request.CreateSigningRequest();
                }
                break;

            default:
                throw new NotSupportedException($"CSR generation not implemented for key type: {keyType}. Use RSA or EC keys.");
        }

        // Convert DER to PEM
        var base64 = Convert.ToBase64String(csrDer);
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");
        for (int i = 0; i < base64.Length; i += 64)
        {
            sb.AppendLine(base64.Substring(i, Math.Min(64, base64.Length - i)));
        }
        sb.AppendLine("-----END CERTIFICATE REQUEST-----");
        return sb.ToString();
    }

    #endregion

    #region Password Scenarios

    /// <summary>
    /// Gets a variety of password test cases.
    /// </summary>
    public static List<string> GetPasswordTestCases()
    {
        return new List<string>
        {
            "",                                           // Empty
            "password",                                   // Simple ASCII
            "P@ssw0rd!",                                  // Special characters
            "密码",                                        // Unicode (Chinese)
            "пароль",                                     // Unicode (Russian)
            "🔐🔑",                                        // Emoji
            "a",                                          // Single character
            new string('x', 100),                         // Long password (100 chars)
            new string('y', 1000),                        // Very long password (1000 chars)
            "pass word",                                  // With space
            "pass\tword",                                 // With tab
            "pass\nword",                                 // With newline (common kubectl issue)
            "pass\r\nword",                               // With CRLF
            "\"quoted\"",                                 // With quotes
            "'single'",                                   // With single quotes
            "`backtick`",                                 // With backtick
            "$VAR",                                       // Shell-like variable
            "$(cmd)",                                     // Shell-like command substitution
            "<xml>test</xml>",                            // XML-like
            "{\"key\":\"value\"}",                        // JSON-like
            "C:\\Windows\\Path",                          // Windows path
            "/usr/local/bin",                             // Unix path
        };
    }

    #endregion

    #region Corrupt Data Generation

    /// <summary>
    /// Generates corrupted/invalid certificate data for negative testing.
    /// </summary>
    public static byte[] GenerateCorruptedData(int size = 100)
    {
        var data = new byte[size];
        Random.NextBytes(data);
        return data;
    }

    /// <summary>
    /// Corrupts valid certificate data by modifying random bytes.
    /// </summary>
    public static byte[] CorruptData(byte[] validData, int bytesToCorrupt = 5)
    {
        var corrupted = new byte[validData.Length];
        Array.Copy(validData, corrupted, validData.Length);

        for (int i = 0; i < bytesToCorrupt; i++)
        {
            var index = Random.Next(corrupted.Length);
            corrupted[index] = (byte)~corrupted[index]; // Flip all bits
        }

        return corrupted;
    }

    #endregion
}
