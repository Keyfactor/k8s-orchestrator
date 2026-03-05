// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Org.BouncyCastle.Crypto;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Utilities;

/// <summary>
/// Unit tests for PrivateKeyFormatUtilities - format detection, PKCS1 support checking,
/// and PEM export functionality.
/// </summary>
public class PrivateKeyFormatUtilitiesTests
{
    #region Format Detection Tests

    [Fact]
    public void DetectFormat_Pkcs8Header_ReturnsPkcs8()
    {
        var pemData = @"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7...
-----END PRIVATE KEY-----";

        var result = PrivateKeyFormatUtilities.DetectFormat(pemData);

        Assert.Equal(PrivateKeyFormat.Pkcs8, result);
    }

    [Fact]
    public void DetectFormat_EncryptedPkcs8Header_ReturnsPkcs8()
    {
        var pemData = @"-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI...
-----END ENCRYPTED PRIVATE KEY-----";

        var result = PrivateKeyFormatUtilities.DetectFormat(pemData);

        Assert.Equal(PrivateKeyFormat.Pkcs8, result);
    }

    [Fact]
    public void DetectFormat_RsaPkcs1Header_ReturnsPkcs1()
    {
        var pemData = @"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz...
-----END RSA PRIVATE KEY-----";

        var result = PrivateKeyFormatUtilities.DetectFormat(pemData);

        Assert.Equal(PrivateKeyFormat.Pkcs1, result);
    }

    [Fact]
    public void DetectFormat_EcPkcs1Header_ReturnsPkcs1()
    {
        var pemData = @"-----BEGIN EC PRIVATE KEY-----
MHQCAQEEICXNdFAO5...
-----END EC PRIVATE KEY-----";

        var result = PrivateKeyFormatUtilities.DetectFormat(pemData);

        Assert.Equal(PrivateKeyFormat.Pkcs1, result);
    }

    [Fact]
    public void DetectFormat_DsaPkcs1Header_ReturnsPkcs1()
    {
        var pemData = @"-----BEGIN DSA PRIVATE KEY-----
MIIDVgIBAAKCAQEA...
-----END DSA PRIVATE KEY-----";

        var result = PrivateKeyFormatUtilities.DetectFormat(pemData);

        Assert.Equal(PrivateKeyFormat.Pkcs1, result);
    }

    [Fact]
    public void DetectFormat_EmptyString_ReturnsPkcs8Default()
    {
        var result = PrivateKeyFormatUtilities.DetectFormat("");

        Assert.Equal(PrivateKeyFormat.Pkcs8, result);
    }

    [Fact]
    public void DetectFormat_NullString_ReturnsPkcs8Default()
    {
        var result = PrivateKeyFormatUtilities.DetectFormat(null);

        Assert.Equal(PrivateKeyFormat.Pkcs8, result);
    }

    [Fact]
    public void DetectFormat_UnknownFormat_ReturnsPkcs8Default()
    {
        var pemData = "some random data without PEM headers";

        var result = PrivateKeyFormatUtilities.DetectFormat(pemData);

        Assert.Equal(PrivateKeyFormat.Pkcs8, result);
    }

    #endregion

    #region SupportsPkcs1 Tests

    [Theory]
    [InlineData(CertificateTestHelper.KeyType.Rsa2048)]
    [InlineData(CertificateTestHelper.KeyType.Rsa4096)]
    public void SupportsPkcs1_RsaKey_ReturnsTrue(CertificateTestHelper.KeyType keyType)
    {
        var keyPair = CertificateTestHelper.GenerateKeyPair(keyType);

        var result = PrivateKeyFormatUtilities.SupportsPkcs1(keyPair.Private);

        Assert.True(result);
    }

    [Theory]
    [InlineData(CertificateTestHelper.KeyType.EcP256)]
    [InlineData(CertificateTestHelper.KeyType.EcP384)]
    public void SupportsPkcs1_EcKey_ReturnsTrue(CertificateTestHelper.KeyType keyType)
    {
        var keyPair = CertificateTestHelper.GenerateKeyPair(keyType);

        var result = PrivateKeyFormatUtilities.SupportsPkcs1(keyPair.Private);

        Assert.True(result);
    }

    [Fact]
    public void SupportsPkcs1_DsaKey_ReturnsTrue()
    {
        var keyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.Dsa2048);

        var result = PrivateKeyFormatUtilities.SupportsPkcs1(keyPair.Private);

        Assert.True(result);
    }

    [Fact]
    public void SupportsPkcs1_Ed25519Key_ReturnsFalse()
    {
        var keyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.Ed25519);

        var result = PrivateKeyFormatUtilities.SupportsPkcs1(keyPair.Private);

        Assert.False(result);
    }

    [Fact]
    public void SupportsPkcs1_Ed448Key_ReturnsFalse()
    {
        var keyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.Ed448);

        var result = PrivateKeyFormatUtilities.SupportsPkcs1(keyPair.Private);

        Assert.False(result);
    }

    [Fact]
    public void SupportsPkcs1_NullKey_ReturnsFalse()
    {
        var result = PrivateKeyFormatUtilities.SupportsPkcs1(null);

        Assert.False(result);
    }

    #endregion

    #region GetAlgorithmName Tests

    [Theory]
    [InlineData(CertificateTestHelper.KeyType.Rsa2048, "RSA")]
    [InlineData(CertificateTestHelper.KeyType.EcP256, "EC")]
    [InlineData(CertificateTestHelper.KeyType.Dsa2048, "DSA")]
    [InlineData(CertificateTestHelper.KeyType.Ed25519, "Ed25519")]
    [InlineData(CertificateTestHelper.KeyType.Ed448, "Ed448")]
    public void GetAlgorithmName_ReturnsCorrectName(CertificateTestHelper.KeyType keyType, string expectedName)
    {
        var keyPair = CertificateTestHelper.GenerateKeyPair(keyType);

        var result = PrivateKeyFormatUtilities.GetAlgorithmName(keyPair.Private);

        Assert.Equal(expectedName, result);
    }

    #endregion

    #region ExportAsPkcs1Pem Tests

    [Theory]
    [InlineData(CertificateTestHelper.KeyType.Rsa2048, "-----BEGIN RSA PRIVATE KEY-----")]
    [InlineData(CertificateTestHelper.KeyType.EcP256, "-----BEGIN EC PRIVATE KEY-----")]
    public void ExportAsPkcs1Pem_SupportedKeyType_HasCorrectHeader(
        CertificateTestHelper.KeyType keyType, string expectedHeader)
    {
        var keyPair = CertificateTestHelper.GenerateKeyPair(keyType);

        var result = PrivateKeyFormatUtilities.ExportAsPkcs1Pem(keyPair.Private);

        Assert.Contains(expectedHeader, result);
    }

    [Fact]
    public void ExportAsPkcs1Pem_Ed25519Key_ThrowsNotSupportedException()
    {
        var keyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.Ed25519);

        Assert.Throws<NotSupportedException>(() =>
            PrivateKeyFormatUtilities.ExportAsPkcs1Pem(keyPair.Private));
    }

    [Fact]
    public void ExportAsPkcs1Pem_Ed448Key_ThrowsNotSupportedException()
    {
        var keyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.Ed448);

        Assert.Throws<NotSupportedException>(() =>
            PrivateKeyFormatUtilities.ExportAsPkcs1Pem(keyPair.Private));
    }

    [Fact]
    public void ExportAsPkcs1Pem_NullKey_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            PrivateKeyFormatUtilities.ExportAsPkcs1Pem(null));
    }

    #endregion

    #region ExportAsPkcs8Pem Tests

    [Theory]
    [InlineData(CertificateTestHelper.KeyType.Rsa2048)]
    [InlineData(CertificateTestHelper.KeyType.EcP256)]
    [InlineData(CertificateTestHelper.KeyType.Dsa2048)]
    [InlineData(CertificateTestHelper.KeyType.Ed25519)]
    [InlineData(CertificateTestHelper.KeyType.Ed448)]
    public void ExportAsPkcs8Pem_AnyKeyType_HasCorrectHeader(CertificateTestHelper.KeyType keyType)
    {
        var keyPair = CertificateTestHelper.GenerateKeyPair(keyType);

        var result = PrivateKeyFormatUtilities.ExportAsPkcs8Pem(keyPair.Private);

        Assert.Contains("-----BEGIN PRIVATE KEY-----", result);
        Assert.Contains("-----END PRIVATE KEY-----", result);
    }

    [Fact]
    public void ExportAsPkcs8Pem_NullKey_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            PrivateKeyFormatUtilities.ExportAsPkcs8Pem(null));
    }

    #endregion

    #region ExportPrivateKeyAsPem Tests

    [Theory]
    [InlineData(CertificateTestHelper.KeyType.Rsa2048, PrivateKeyFormat.Pkcs1, "-----BEGIN RSA PRIVATE KEY-----")]
    [InlineData(CertificateTestHelper.KeyType.Rsa2048, PrivateKeyFormat.Pkcs8, "-----BEGIN PRIVATE KEY-----")]
    [InlineData(CertificateTestHelper.KeyType.EcP256, PrivateKeyFormat.Pkcs1, "-----BEGIN EC PRIVATE KEY-----")]
    [InlineData(CertificateTestHelper.KeyType.EcP256, PrivateKeyFormat.Pkcs8, "-----BEGIN PRIVATE KEY-----")]
    public void ExportPrivateKeyAsPem_RequestedFormat_ProducesCorrectOutput(
        CertificateTestHelper.KeyType keyType, PrivateKeyFormat format, string expectedHeader)
    {
        var keyPair = CertificateTestHelper.GenerateKeyPair(keyType);

        var result = PrivateKeyFormatUtilities.ExportPrivateKeyAsPem(keyPair.Private, format);

        Assert.Contains(expectedHeader, result);
    }

    [Fact]
    public void ExportPrivateKeyAsPem_Ed25519WithPkcs1_FallsBackToPkcs8()
    {
        // Ed25519 doesn't support PKCS1, so it should fall back to PKCS8
        var keyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.Ed25519);

        var result = PrivateKeyFormatUtilities.ExportPrivateKeyAsPem(keyPair.Private, PrivateKeyFormat.Pkcs1);

        // Should NOT contain RSA/EC header since Ed25519 doesn't support PKCS1
        Assert.DoesNotContain("-----BEGIN RSA PRIVATE KEY-----", result);
        Assert.DoesNotContain("-----BEGIN EC PRIVATE KEY-----", result);
        // Should contain PKCS8 header
        Assert.Contains("-----BEGIN PRIVATE KEY-----", result);
    }

    [Fact]
    public void ExportPrivateKeyAsPem_Ed448WithPkcs1_FallsBackToPkcs8()
    {
        // Ed448 doesn't support PKCS1, so it should fall back to PKCS8
        var keyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.Ed448);

        var result = PrivateKeyFormatUtilities.ExportPrivateKeyAsPem(keyPair.Private, PrivateKeyFormat.Pkcs1);

        // Should NOT contain RSA/EC header since Ed448 doesn't support PKCS1
        Assert.DoesNotContain("-----BEGIN RSA PRIVATE KEY-----", result);
        Assert.DoesNotContain("-----BEGIN EC PRIVATE KEY-----", result);
        // Should contain PKCS8 header
        Assert.Contains("-----BEGIN PRIVATE KEY-----", result);
    }

    [Fact]
    public void ExportPrivateKeyAsPem_NullKey_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            PrivateKeyFormatUtilities.ExportPrivateKeyAsPem(null, PrivateKeyFormat.Pkcs8));
    }

    #endregion

    #region ParseFormat Tests

    [Theory]
    [InlineData("PKCS1", PrivateKeyFormat.Pkcs1)]
    [InlineData("pkcs1", PrivateKeyFormat.Pkcs1)]
    [InlineData("Pkcs1", PrivateKeyFormat.Pkcs1)]
    [InlineData("PKCS8", PrivateKeyFormat.Pkcs8)]
    [InlineData("pkcs8", PrivateKeyFormat.Pkcs8)]
    [InlineData("Pkcs8", PrivateKeyFormat.Pkcs8)]
    public void ParseFormat_ValidInput_ReturnsCorrectFormat(string input, PrivateKeyFormat expected)
    {
        var result = PrivateKeyFormatUtilities.ParseFormat(input);

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("invalid")]
    [InlineData("RSA")]
    public void ParseFormat_InvalidOrEmpty_ReturnsPkcs8Default(string input)
    {
        var result = PrivateKeyFormatUtilities.ParseFormat(input);

        Assert.Equal(PrivateKeyFormat.Pkcs8, result);
    }

    [Fact]
    public void ParseFormat_Null_ReturnsPkcs8Default()
    {
        var result = PrivateKeyFormatUtilities.ParseFormat(null);

        Assert.Equal(PrivateKeyFormat.Pkcs8, result);
    }

    #endregion

    #region Algorithm Switch Tests (RSA->Ed25519 scenario)

    [Fact]
    public void AlgorithmSwitch_RsaThenEd25519_FormatChangesToPkcs8()
    {
        // Scenario: Existing secret has RSA key in PKCS1 format
        // New certificate has Ed25519 key
        // Result: Format should change to PKCS8 because Ed25519 doesn't support PKCS1

        // 1. Simulate existing RSA key in PKCS1 format
        var rsaKeyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.Rsa2048);
        var existingKeyPem = PrivateKeyFormatUtilities.ExportAsPkcs1Pem(rsaKeyPair.Private);
        var detectedFormat = PrivateKeyFormatUtilities.DetectFormat(existingKeyPem);
        Assert.Equal(PrivateKeyFormat.Pkcs1, detectedFormat);

        // 2. New Ed25519 key
        var ed25519KeyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.Ed25519);

        // 3. Try to export in the detected format (PKCS1)
        var newKeyPem = PrivateKeyFormatUtilities.ExportPrivateKeyAsPem(ed25519KeyPair.Private, detectedFormat);

        // 4. Verify it fell back to PKCS8
        var newFormat = PrivateKeyFormatUtilities.DetectFormat(newKeyPem);
        Assert.Equal(PrivateKeyFormat.Pkcs8, newFormat);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", newKeyPem);
    }

    [Fact]
    public void AlgorithmSwitch_EcThenRsa_FormatPreserved()
    {
        // Scenario: Existing secret has EC key in PKCS1 format
        // New certificate has RSA key (also supports PKCS1)
        // Result: Format should be preserved as PKCS1

        // 1. Simulate existing EC key in PKCS1 format
        var ecKeyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.EcP256);
        var existingKeyPem = PrivateKeyFormatUtilities.ExportAsPkcs1Pem(ecKeyPair.Private);
        var detectedFormat = PrivateKeyFormatUtilities.DetectFormat(existingKeyPem);
        Assert.Equal(PrivateKeyFormat.Pkcs1, detectedFormat);

        // 2. New RSA key
        var rsaKeyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.Rsa2048);

        // 3. Export in the detected format (PKCS1)
        var newKeyPem = PrivateKeyFormatUtilities.ExportPrivateKeyAsPem(rsaKeyPair.Private, detectedFormat);

        // 4. Verify format was preserved as PKCS1
        var newFormat = PrivateKeyFormatUtilities.DetectFormat(newKeyPem);
        Assert.Equal(PrivateKeyFormat.Pkcs1, newFormat);
        Assert.Contains("-----BEGIN RSA PRIVATE KEY-----", newKeyPem);
    }

    [Fact]
    public void AlgorithmSwitch_RsaPkcs8ThenEc_FormatPreserved()
    {
        // Scenario: Existing secret has RSA key in PKCS8 format
        // New certificate has EC key
        // Result: Format should be preserved as PKCS8

        // 1. Simulate existing RSA key in PKCS8 format
        var rsaKeyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.Rsa2048);
        var existingKeyPem = PrivateKeyFormatUtilities.ExportAsPkcs8Pem(rsaKeyPair.Private);
        var detectedFormat = PrivateKeyFormatUtilities.DetectFormat(existingKeyPem);
        Assert.Equal(PrivateKeyFormat.Pkcs8, detectedFormat);

        // 2. New EC key
        var ecKeyPair = CertificateTestHelper.GenerateKeyPair(CertificateTestHelper.KeyType.EcP256);

        // 3. Export in the detected format (PKCS8)
        var newKeyPem = PrivateKeyFormatUtilities.ExportPrivateKeyAsPem(ecKeyPair.Private, detectedFormat);

        // 4. Verify format was preserved as PKCS8
        var newFormat = PrivateKeyFormatUtilities.DetectFormat(newKeyPem);
        Assert.Equal(PrivateKeyFormat.Pkcs8, newFormat);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", newKeyPem);
    }

    #endregion

    #region Round-Trip Tests

    [Theory]
    [InlineData(CertificateTestHelper.KeyType.Rsa2048, PrivateKeyFormat.Pkcs1)]
    [InlineData(CertificateTestHelper.KeyType.Rsa2048, PrivateKeyFormat.Pkcs8)]
    [InlineData(CertificateTestHelper.KeyType.EcP256, PrivateKeyFormat.Pkcs1)]
    [InlineData(CertificateTestHelper.KeyType.EcP256, PrivateKeyFormat.Pkcs8)]
    [InlineData(CertificateTestHelper.KeyType.Ed25519, PrivateKeyFormat.Pkcs8)]
    [InlineData(CertificateTestHelper.KeyType.Ed448, PrivateKeyFormat.Pkcs8)]
    public void RoundTrip_ExportAndDetect_FormatMatches(CertificateTestHelper.KeyType keyType, PrivateKeyFormat format)
    {
        var keyPair = CertificateTestHelper.GenerateKeyPair(keyType);

        // Skip if the combination is invalid (Ed25519/Ed448 with PKCS1)
        if (!PrivateKeyFormatUtilities.SupportsPkcs1(keyPair.Private) && format == PrivateKeyFormat.Pkcs1)
        {
            // This would fall back to PKCS8, so we skip
            return;
        }

        var pem = PrivateKeyFormatUtilities.ExportPrivateKeyAsPem(keyPair.Private, format);
        var detected = PrivateKeyFormatUtilities.DetectFormat(pem);

        Assert.Equal(format, detected);
    }

    #endregion
}
