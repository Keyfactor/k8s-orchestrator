// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Keyfactor.PKI.PEM;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Utilities;

/// <summary>
/// Tests for LoggingUtilities - safe logging of sensitive data by redaction.
/// </summary>
public class LoggingUtilitiesTests
{
    #region RedactPassword Tests

    [Fact]
    public void RedactPassword_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.RedactPassword(null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void RedactPassword_EmptyInput_ReturnsEmpty()
    {
        // Act
        var result = LoggingUtilities.RedactPassword("");

        // Assert
        Assert.Equal("EMPTY", result);
    }

    [Fact]
    public void RedactPassword_ValidInput_ReturnsRedacted()
    {
        // Arrange
        var password = "mySecretPassword123";

        // Act
        var result = LoggingUtilities.RedactPassword(password);

        // Assert
        Assert.Equal("***REDACTED***", result);
        Assert.DoesNotContain(password.Length.ToString(), result);
    }

    [Theory]
    [InlineData("a")]
    [InlineData("password")]
    [InlineData("verylongpassword1234567890")]
    public void RedactPassword_VariousInputs_DoesNotRevealLength(string password)
    {
        // Act
        var result = LoggingUtilities.RedactPassword(password);

        // Assert
        Assert.Equal("***REDACTED***", result);
        Assert.DoesNotContain(password.Length.ToString(), result);
    }

    #endregion

    #region RedactPrivateKeyPem Tests

    [Fact]
    public void RedactPrivateKeyPem_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.RedactPrivateKeyPem(null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void RedactPrivateKeyPem_EmptyInput_ReturnsEmpty()
    {
        // Act
        var result = LoggingUtilities.RedactPrivateKeyPem("");

        // Assert
        Assert.Equal("EMPTY", result);
    }

    [Fact]
    public void RedactPrivateKeyPem_RsaKey_ReturnsRsaType()
    {
        // Arrange
        var rsaKeyPem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";

        // Act
        var result = LoggingUtilities.RedactPrivateKeyPem(rsaKeyPem);

        // Assert
        Assert.Contains("***REDACTED_PRIVATE_KEY***", result);
        Assert.Contains("type: RSA", result);
        Assert.Contains($"length: {rsaKeyPem.Length}", result);
    }

    [Fact]
    public void RedactPrivateKeyPem_EcKey_ReturnsEcType()
    {
        // Arrange
        var ecKeyPem = "-----BEGIN EC PRIVATE KEY-----\nMHQC...\n-----END EC PRIVATE KEY-----";

        // Act
        var result = LoggingUtilities.RedactPrivateKeyPem(ecKeyPem);

        // Assert
        Assert.Contains("type: EC", result);
    }

    [Fact]
    public void RedactPrivateKeyPem_Pkcs8Key_ReturnsPkcs8Type()
    {
        // Arrange
        var pkcs8KeyPem = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----";

        // Act
        var result = LoggingUtilities.RedactPrivateKeyPem(pkcs8KeyPem);

        // Assert
        Assert.Contains("type: PKCS8", result);
    }

    [Fact]
    public void RedactPrivateKeyPem_EncryptedPkcs8Key_ReturnsEncryptedType()
    {
        // Arrange
        var encryptedKeyPem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIE...\n-----END ENCRYPTED PRIVATE KEY-----";

        // Act
        var result = LoggingUtilities.RedactPrivateKeyPem(encryptedKeyPem);

        // Assert
        Assert.Contains("type: ENCRYPTED_PKCS8", result);
    }

    [Fact]
    public void RedactPrivateKeyPem_UnknownFormat_ReturnsUnknownType()
    {
        // Arrange
        var unknownKeyPem = "some random key data without proper headers";

        // Act
        var result = LoggingUtilities.RedactPrivateKeyPem(unknownKeyPem);

        // Assert
        Assert.Contains("type: UNKNOWN", result);
    }

    #endregion

    #region RedactPrivateKeyBytes Tests

    [Fact]
    public void RedactPrivateKeyBytes_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.RedactPrivateKeyBytes(null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void RedactPrivateKeyBytes_EmptyInput_ReturnsEmpty()
    {
        // Act
        var result = LoggingUtilities.RedactPrivateKeyBytes(Array.Empty<byte>());

        // Assert
        Assert.Equal("EMPTY", result);
    }

    [Fact]
    public void RedactPrivateKeyBytes_ValidInput_ReturnsRedactedWithCount()
    {
        // Arrange
        var keyBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        // Act
        var result = LoggingUtilities.RedactPrivateKeyBytes(keyBytes);

        // Assert
        Assert.Contains("***REDACTED_PRIVATE_KEY_BYTES***", result);
        Assert.Contains("count: 8", result);
    }

    #endregion

    #region RedactPrivateKey (AsymmetricKeyParameter) Tests

    [Fact]
    public void RedactPrivateKey_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.RedactPrivateKey(null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void RedactPrivateKey_ValidRsaKey_ReturnsRedactedWithType()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test RedactPrivateKey");
        var privateKey = certInfo.KeyPair.Private;

        // Act
        var result = LoggingUtilities.RedactPrivateKey(privateKey);

        // Assert
        Assert.Contains("***REDACTED_PRIVATE_KEY***", result);
        Assert.Contains("isPrivate: True", result);
    }

    #endregion

    #region GetCertificateSummary (System.Security.X509Certificate2) Tests

    [Fact]
    public void GetCertificateSummary_X509Certificate2_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.GetCertificateSummary((System.Security.Cryptography.X509Certificates.X509Certificate2)null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void GetCertificateSummary_X509Certificate2_ValidCertificate_ReturnsSummary()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test Summary X509");
        var x509Cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(certInfo.Certificate.GetEncoded());

        // Act
        var result = LoggingUtilities.GetCertificateSummary(x509Cert);

        // Assert
        Assert.Contains("Subject:", result);
        Assert.Contains("Thumbprint:", result);
        Assert.Contains("Valid:", result);
    }

    #endregion

    #region GetCertificateSummary (BouncyCastle X509Certificate) Tests

    [Fact]
    public void GetCertificateSummary_BouncyCastle_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.GetCertificateSummary((Org.BouncyCastle.X509.X509Certificate)null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void GetCertificateSummary_BouncyCastle_ValidCertificate_ReturnsSummary()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test Summary BC");

        // Act
        var result = LoggingUtilities.GetCertificateSummary(certInfo.Certificate);

        // Assert
        Assert.Contains("Subject:", result);
        Assert.Contains("Thumbprint:", result);
        Assert.Contains("Valid:", result);
    }

    #endregion

    #region GetCertificateSummaryFromPem Tests

    [Fact]
    public void GetCertificateSummaryFromPem_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.GetCertificateSummaryFromPem(null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void GetCertificateSummaryFromPem_EmptyInput_ReturnsEmpty()
    {
        // Act
        var result = LoggingUtilities.GetCertificateSummaryFromPem("");

        // Assert
        Assert.Equal("EMPTY", result);
    }

    [Fact]
    public void GetCertificateSummaryFromPem_ValidPem_ReturnsSummary()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test Summary PEM");
        var pem = PemUtilities.DERToPEM(certInfo.Certificate.GetEncoded(), PemUtilities.PemObjectType.Certificate);

        // Act
        var result = LoggingUtilities.GetCertificateSummaryFromPem(pem);

        // Assert
        Assert.Contains("Subject:", result);
        Assert.Contains("Thumbprint:", result);
    }

    [Fact]
    public void GetCertificateSummaryFromPem_InvalidPem_ReturnsError()
    {
        // Arrange
        var invalidPem = "-----BEGIN CERTIFICATE-----\nnotvalid\n-----END CERTIFICATE-----";

        // Act
        var result = LoggingUtilities.GetCertificateSummaryFromPem(invalidPem);

        // Assert
        Assert.Contains("ERROR_PARSING_CERTIFICATE:", result);
    }

    #endregion

    #region RedactCertificatePem Tests

    [Fact]
    public void RedactCertificatePem_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.RedactCertificatePem(null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void RedactCertificatePem_EmptyInput_ReturnsEmpty()
    {
        // Act
        var result = LoggingUtilities.RedactCertificatePem("");

        // Assert
        Assert.Equal("EMPTY", result);
    }

    [Fact]
    public void RedactCertificatePem_ValidInput_ReturnsRedactedWithLength()
    {
        // Arrange
        var certPem = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----";

        // Act
        var result = LoggingUtilities.RedactCertificatePem(certPem);

        // Assert
        Assert.Contains("***REDACTED_CERTIFICATE_PEM***", result);
        Assert.Contains($"length: {certPem.Length}", result);
    }

    #endregion

    #region RedactPkcs12Bytes Tests

    [Fact]
    public void RedactPkcs12Bytes_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.RedactPkcs12Bytes(null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void RedactPkcs12Bytes_EmptyInput_ReturnsEmpty()
    {
        // Act
        var result = LoggingUtilities.RedactPkcs12Bytes(Array.Empty<byte>());

        // Assert
        Assert.Equal("EMPTY", result);
    }

    [Fact]
    public void RedactPkcs12Bytes_ValidInput_ReturnsRedactedWithBytes()
    {
        // Arrange
        var pkcs12Data = new byte[1024];

        // Act
        var result = LoggingUtilities.RedactPkcs12Bytes(pkcs12Data);

        // Assert
        Assert.Contains("***REDACTED_PKCS12***", result);
        Assert.Contains("bytes: 1024", result);
    }

    #endregion

    #region GetSecretSummary Tests

    [Fact]
    public void GetSecretSummary_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.GetSecretSummary(null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void GetSecretSummary_OpaqueSecret_ReturnsFormattedSummary()
    {
        // Arrange
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "test-secret",
                NamespaceProperty = "default"
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "username", new byte[] { 1, 2, 3 } },
                { "password", new byte[] { 4, 5, 6 } }
            }
        };

        // Act
        var result = LoggingUtilities.GetSecretSummary(secret);

        // Assert
        Assert.Contains("Name: test-secret", result);
        Assert.Contains("Namespace: default", result);
        Assert.Contains("Type: Opaque", result);
        Assert.Contains("username", result);
        Assert.Contains("password", result);
        Assert.Contains("count: 2", result);
    }

    [Fact]
    public void GetSecretSummary_TlsSecret_ReturnsFormattedSummary()
    {
        // Arrange
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "tls-cert",
                NamespaceProperty = "kube-system"
            },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", new byte[] { 1, 2, 3 } },
                { "tls.key", new byte[] { 4, 5, 6 } }
            }
        };

        // Act
        var result = LoggingUtilities.GetSecretSummary(secret);

        // Assert
        Assert.Contains("Name: tls-cert", result);
        Assert.Contains("Type: kubernetes.io/tls", result);
        Assert.Contains("tls.crt", result);
        Assert.Contains("tls.key", result);
    }

    [Fact]
    public void GetSecretSummary_SecretWithNullData_HandlesGracefully()
    {
        // Arrange
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "empty-secret",
                NamespaceProperty = "default"
            },
            Type = "Opaque",
            Data = null
        };

        // Act
        var result = LoggingUtilities.GetSecretSummary(secret);

        // Assert
        Assert.Contains("Name: empty-secret", result);
        Assert.Contains("DataKeys: [NONE]", result);
        Assert.Contains("count: 0", result);
    }

    #endregion

    #region GetSecretDataKeysSummary Tests

    [Fact]
    public void GetSecretDataKeysSummary_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.GetSecretDataKeysSummary(null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void GetSecretDataKeysSummary_EmptyDictionary_ReturnsEmpty()
    {
        // Act
        var result = LoggingUtilities.GetSecretDataKeysSummary(new Dictionary<string, byte[]>());

        // Assert
        Assert.Equal("EMPTY", result);
    }

    [Fact]
    public void GetSecretDataKeysSummary_ValidData_ReturnsCommaSeparatedKeys()
    {
        // Arrange
        var data = new Dictionary<string, byte[]>
        {
            { "key1", new byte[] { 1 } },
            { "key2", new byte[] { 2 } },
            { "key3", new byte[] { 3 } }
        };

        // Act
        var result = LoggingUtilities.GetSecretDataKeysSummary(data);

        // Assert
        Assert.Contains("key1", result);
        Assert.Contains("key2", result);
        Assert.Contains("key3", result);
    }

    #endregion

    #region RedactKubeconfig Tests

    [Fact]
    public void RedactKubeconfig_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.RedactKubeconfig(null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void RedactKubeconfig_EmptyInput_ReturnsEmpty()
    {
        // Act
        var result = LoggingUtilities.RedactKubeconfig("");

        // Assert
        Assert.Equal("EMPTY", result);
    }

    [Fact]
    public void RedactKubeconfig_ValidInput_ReturnsRedactedWithStructure()
    {
        // Arrange
        var kubeconfigJson = @"{
            ""clusters"": [{""cluster"": {""server"": ""https://k8s.example.com""}}],
            ""users"": [{""user"": {""token"": ""secret-token""}}],
            ""contexts"": [{""context"": {""cluster"": ""my-cluster""}}]
        }";

        // Act
        var result = LoggingUtilities.RedactKubeconfig(kubeconfigJson);

        // Assert
        Assert.Contains("***REDACTED_KUBECONFIG***", result);
        Assert.Contains("length:", result);
        Assert.Contains("clusters:", result);
        Assert.Contains("users:", result);
        Assert.Contains("contexts:", result);
    }

    #endregion

    #region GetFieldPresence (string) Tests

    [Fact]
    public void GetFieldPresence_String_NullValue_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.GetFieldPresence("password", (string)null);

        // Assert
        Assert.Equal("password: NULL", result);
    }

    [Fact]
    public void GetFieldPresence_String_EmptyValue_ReturnsEmpty()
    {
        // Act
        var result = LoggingUtilities.GetFieldPresence("token", "");

        // Assert
        Assert.Equal("token: EMPTY", result);
    }

    [Fact]
    public void GetFieldPresence_String_ValidValue_ReturnsPresent()
    {
        // Act
        var result = LoggingUtilities.GetFieldPresence("apiKey", "some-value");

        // Assert
        Assert.Equal("apiKey: PRESENT", result);
    }

    #endregion

    #region GetFieldPresence (byte[]) Tests

    [Fact]
    public void GetFieldPresence_Bytes_NullValue_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.GetFieldPresence("certificate", (byte[])null);

        // Assert
        Assert.Equal("certificate: NULL", result);
    }

    [Fact]
    public void GetFieldPresence_Bytes_EmptyValue_ReturnsEmpty()
    {
        // Act
        var result = LoggingUtilities.GetFieldPresence("key", Array.Empty<byte>());

        // Assert
        Assert.Equal("key: EMPTY", result);
    }

    [Fact]
    public void GetFieldPresence_Bytes_ValidValue_ReturnsPresentWithCount()
    {
        // Arrange
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        var result = LoggingUtilities.GetFieldPresence("payload", data);

        // Assert
        Assert.Equal("payload: PRESENT (count: 5)", result);
    }

    #endregion

    #region RedactToken Tests

    [Fact]
    public void RedactToken_NullInput_ReturnsNull()
    {
        // Act
        var result = LoggingUtilities.RedactToken(null);

        // Assert
        Assert.Equal("NULL", result);
    }

    [Fact]
    public void RedactToken_EmptyInput_ReturnsEmpty()
    {
        // Act
        var result = LoggingUtilities.RedactToken("");

        // Assert
        Assert.Equal("EMPTY", result);
    }

    [Fact]
    public void RedactToken_ShortToken_ReturnsFullRedactionWithLength()
    {
        // Arrange - token of 12 characters or less should not show prefix/suffix
        var shortToken = "abc123456";

        // Act
        var result = LoggingUtilities.RedactToken(shortToken);

        // Assert
        Assert.Contains("***REDACTED_TOKEN***", result);
        Assert.Contains($"length: {shortToken.Length}", result);
        Assert.DoesNotContain("...", result);
    }

    [Fact]
    public void RedactToken_LongToken_ReturnsPartialWithPrefixSuffix()
    {
        // Arrange - token longer than 12 characters should show prefix/suffix
        var longToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrOHMifQ.signature";

        // Act
        var result = LoggingUtilities.RedactToken(longToken);

        // Assert
        Assert.Contains("***REDACTED_TOKEN***", result);
        Assert.Contains("eyJh", result); // First 4 chars
        Assert.Contains("ture", result); // Last 4 chars
        Assert.Contains("...", result);
        Assert.Contains($"length: {longToken.Length}", result);
    }

    [Theory]
    [InlineData("a", 1)]
    [InlineData("123456789012", 12)]
    [InlineData("1234567890123", 13)]
    public void RedactToken_VariousLengths_ReturnsCorrectFormat(string token, int expectedLength)
    {
        // Act
        var result = LoggingUtilities.RedactToken(token);

        // Assert
        Assert.Contains($"length: {expectedLength}", result);

        // Only tokens > 12 should have the prefix/suffix format
        if (expectedLength > 12)
        {
            Assert.Contains("...", result);
        }
        else
        {
            Assert.DoesNotContain("...", result);
        }
    }

    #endregion
}
