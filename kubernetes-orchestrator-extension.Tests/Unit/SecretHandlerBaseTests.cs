// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit;

/// <summary>
/// Regression tests for SecretHandlerBase shared logic.
/// Covers the empty-store implicit overwrite fix: a secret created via "create if missing"
/// (with no certificate data) should not block a subsequent management job that lacks overwrite=true.
/// </summary>
public class SecretHandlerBaseTests
{
    #region IsSecretEmpty - Null and missing data

    [Fact]
    public void IsSecretEmpty_NullSecret_ReturnsTrue()
    {
        Assert.True(SecretHandlerBase.IsSecretEmpty(null));
    }

    [Fact]
    public void IsSecretEmpty_NullData_ReturnsTrue()
    {
        var secret = new V1Secret { Data = null };
        Assert.True(SecretHandlerBase.IsSecretEmpty(secret));
    }

    [Fact]
    public void IsSecretEmpty_EmptyDataDictionary_ReturnsTrue()
    {
        var secret = new V1Secret { Data = new Dictionary<string, byte[]>() };
        Assert.True(SecretHandlerBase.IsSecretEmpty(secret));
    }

    #endregion

    #region IsSecretEmpty - Empty-value data (created via "create if missing")

    [Fact]
    public void IsSecretEmpty_TlsSecretWithEmptyFields_ReturnsTrue()
    {
        // Represents what CreateEmptyStore produces for K8STLSSecr
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", [] },
                { "tls.key", [] }
            }
        };
        Assert.True(SecretHandlerBase.IsSecretEmpty(secret));
    }

    [Fact]
    public void IsSecretEmpty_OpaqueSecretWithEmptyFields_ReturnsTrue()
    {
        // Represents what CreateEmptyStore produces for K8SSecret
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", [] }
            }
        };
        Assert.True(SecretHandlerBase.IsSecretEmpty(secret));
    }

    [Fact]
    public void IsSecretEmpty_AllNullValues_ReturnsTrue()
    {
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", null },
                { "tls.key", null }
            }
        };
        Assert.True(SecretHandlerBase.IsSecretEmpty(secret));
    }

    [Fact]
    public void IsSecretEmpty_MixedNullAndEmptyValues_ReturnsTrue()
    {
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", null },
                { "tls.key", [] }
            }
        };
        Assert.True(SecretHandlerBase.IsSecretEmpty(secret));
    }

    #endregion

    #region ParseKeystoreAliasCore

    [Fact]
    public void ParseKeystoreAliasCore_NoSeparator_FieldNameNullCertAliasIsFullAlias()
    {
        var (fieldName, certAlias, existingData, existingKeyName) =
            SecretHandlerBase.ParseKeystoreAliasCore("mycert", null, "keystore.jks");

        Assert.Null(fieldName);
        Assert.Equal("mycert", certAlias);
        Assert.Null(existingData);
        Assert.Equal("keystore.jks", existingKeyName);
    }

    [Fact]
    public void ParseKeystoreAliasCore_WithSeparator_SplitsCorrectly()
    {
        var (fieldName, certAlias, existingData, existingKeyName) =
            SecretHandlerBase.ParseKeystoreAliasCore("keystore.jks/mycert", null, "default.jks");

        Assert.Equal("keystore.jks", fieldName);
        Assert.Equal("mycert", certAlias);
        Assert.Null(existingData);
        Assert.Equal("keystore.jks", existingKeyName);
    }

    [Fact]
    public void ParseKeystoreAliasCore_FieldPresentInInventory_ReturnsExistingData()
    {
        var data = new byte[] { 1, 2, 3 };
        var inventory = new Dictionary<string, byte[]> { { "mystore.jks", data } };

        var (_, _, existingData, existingKeyName) =
            SecretHandlerBase.ParseKeystoreAliasCore("mystore.jks/alias1", inventory, "default.jks");

        Assert.Same(data, existingData);
        Assert.Equal("mystore.jks", existingKeyName);
    }

    [Fact]
    public void ParseKeystoreAliasCore_FieldNotInInventory_ExistingDataNull()
    {
        var inventory = new Dictionary<string, byte[]> { { "other.jks", new byte[] { 1 } } };

        var (_, certAlias, existingData, existingKeyName) =
            SecretHandlerBase.ParseKeystoreAliasCore("newfield.jks/alias1", inventory, "default.jks");

        Assert.Null(existingData);
        Assert.Equal("newfield.jks", existingKeyName);
        Assert.Equal("alias1", certAlias);
    }

    [Fact]
    public void ParseKeystoreAliasCore_NoSeparatorWithInventory_UsesFirstKey()
    {
        var data = new byte[] { 10, 20 };
        var inventory = new Dictionary<string, byte[]> { { "existing.jks", data } };

        var (fieldName, certAlias, existingData, existingKeyName) =
            SecretHandlerBase.ParseKeystoreAliasCore("mycert", inventory, "default.jks");

        Assert.Null(fieldName);
        Assert.Equal("mycert", certAlias);
        Assert.Same(data, existingData);
        Assert.Equal("existing.jks", existingKeyName);
    }

    [Fact]
    public void ParseKeystoreAliasCore_NoSeparatorEmptyInventory_UsesDefaultFieldName()
    {
        var inventory = new Dictionary<string, byte[]>();

        var (_, _, existingData, existingKeyName) =
            SecretHandlerBase.ParseKeystoreAliasCore("mycert", inventory, "keystore.pfx");

        Assert.Null(existingData);
        Assert.Equal("keystore.pfx", existingKeyName);
    }

    [Fact]
    public void ParseKeystoreAliasCore_NullInventory_UsesDefaultFieldName()
    {
        var (_, certAlias, existingData, existingKeyName) =
            SecretHandlerBase.ParseKeystoreAliasCore("mycert", null, "keystore.pfx");

        Assert.Equal("mycert", certAlias);
        Assert.Null(existingData);
        Assert.Equal("keystore.pfx", existingKeyName);
    }

    #endregion

    #region ValidateCertOnlyUpdateCore

    [Fact]
    public void ValidateCertOnlyUpdateCore_NullSecret_DoesNotThrow()
    {
        // Should be a no-op when secret is null
        SecretHandlerBase.ValidateCertOnlyUpdateCore(
            null, new[] { "tls.key" }, "tls", "my-secret", "default", null);
    }

    [Fact]
    public void ValidateCertOnlyUpdateCore_NullData_DoesNotThrow()
    {
        var secret = new V1Secret { Data = null };
        SecretHandlerBase.ValidateCertOnlyUpdateCore(
            secret, new[] { "tls.key" }, "tls", "my-secret", "default", null);
    }

    [Fact]
    public void ValidateCertOnlyUpdateCore_NoMatchingField_DoesNotThrow()
    {
        var keyBytes = Encoding.UTF8.GetBytes("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----");
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]> { { "other-field", keyBytes } }
        };
        // Field names don't include "other-field"
        SecretHandlerBase.ValidateCertOnlyUpdateCore(
            secret, new[] { "tls.key" }, "tls", "my-secret", "default", null);
    }

    [Fact]
    public void ValidateCertOnlyUpdateCore_FieldExistsButEmpty_DoesNotThrow()
    {
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]> { { "tls.key", Array.Empty<byte>() } }
        };
        SecretHandlerBase.ValidateCertOnlyUpdateCore(
            secret, new[] { "tls.key" }, "tls", "my-secret", "default", null);
    }

    [Fact]
    public void ValidateCertOnlyUpdateCore_FieldHasCertNotKey_DoesNotThrow()
    {
        // tls.key exists but contains a certificate, not a private key
        var certBytes = Encoding.UTF8.GetBytes("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----");
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]> { { "tls.key", certBytes } }
        };
        SecretHandlerBase.ValidateCertOnlyUpdateCore(
            secret, new[] { "tls.key" }, "tls", "my-secret", "default", null);
    }

    [Fact]
    public void ValidateCertOnlyUpdateCore_TlsKeyHasPrivateKey_Throws()
    {
        var keyBytes = Encoding.UTF8.GetBytes("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----");
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]> { { "tls.key", keyBytes } }
        };
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SecretHandlerBase.ValidateCertOnlyUpdateCore(
                secret, new[] { "tls.key" }, "tls", "my-secret", "default", null));

        Assert.Contains("tls.key", ex.Message);
        Assert.Contains("my-secret", ex.Message);
        Assert.Contains("default", ex.Message);
    }

    [Fact]
    public void ValidateCertOnlyUpdateCore_RsaPrivateKeyHeader_Throws()
    {
        // "BEGIN RSA PRIVATE KEY" also contains "PRIVATE KEY"
        var keyBytes = Encoding.UTF8.GetBytes("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----");
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]> { { "tls.key", keyBytes } }
        };
        Assert.Throws<InvalidOperationException>(() =>
            SecretHandlerBase.ValidateCertOnlyUpdateCore(
                secret, new[] { "tls.key" }, "tls", "my-secret", "default", null));
    }

    [Fact]
    public void ValidateCertOnlyUpdateCore_OpaqueKeyFields_ThrowsOnFirstMatch()
    {
        // Opaque secrets check multiple field names; should throw when "key" field has a private key
        var keyBytes = Encoding.UTF8.GetBytes("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----");
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]> { { "key", keyBytes } }
        };
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SecretHandlerBase.ValidateCertOnlyUpdateCore(
                secret,
                new[] { "tls.key", "key", "private-key", "key.pem", "private-key.pem" },
                "opaque", "my-secret", "default", null));

        Assert.Contains("key", ex.Message);
    }

    [Fact]
    public void ValidateCertOnlyUpdateCore_OpaqueKeyFields_AllEmpty_DoesNotThrow()
    {
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]>
            {
                { "tls.key", Array.Empty<byte>() },
                { "key", null },
                { "private-key", Array.Empty<byte>() }
            }
        };
        SecretHandlerBase.ValidateCertOnlyUpdateCore(
            secret,
            new[] { "tls.key", "key", "private-key", "key.pem", "private-key.pem" },
            "opaque", "my-secret", "default", null);
    }

    #endregion

    #region IsSecretEmpty - Non-empty secrets (should not be overwritten implicitly)

    [Fact]
    public void IsSecretEmpty_TlsSecretWithCert_ReturnsFalse()
    {
        var certBytes = Encoding.UTF8.GetBytes("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----");
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", certBytes },
                { "tls.key", [] }
            }
        };
        Assert.False(SecretHandlerBase.IsSecretEmpty(secret));
    }

    [Fact]
    public void IsSecretEmpty_TlsSecretWithBothFields_ReturnsFalse()
    {
        var certBytes = Encoding.UTF8.GetBytes("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----");
        var keyBytes = Encoding.UTF8.GetBytes("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----");
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", certBytes },
                { "tls.key", keyBytes }
            }
        };
        Assert.False(SecretHandlerBase.IsSecretEmpty(secret));
    }

    [Fact]
    public void IsSecretEmpty_OpaqueSecretWithCertData_ReturnsFalse()
    {
        var certBytes = Encoding.UTF8.GetBytes("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----");
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]>
            {
                { "certificate", certBytes }
            }
        };
        Assert.False(SecretHandlerBase.IsSecretEmpty(secret));
    }

    [Fact]
    public void IsSecretEmpty_SecretWithSingleByteValue_ReturnsFalse()
    {
        // Even a single non-empty byte makes the secret non-empty
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", new byte[] { 0x01 } }
            }
        };
        Assert.False(SecretHandlerBase.IsSecretEmpty(secret));
    }

    [Fact]
    public void IsSecretEmpty_OneEmptyOneNonEmpty_ReturnsFalse()
    {
        // If ANY field has data, the secret is not empty
        var certBytes = Encoding.UTF8.GetBytes("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----");
        var secret = new V1Secret
        {
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", certBytes },
                { "tls.key", [] }
            }
        };
        Assert.False(SecretHandlerBase.IsSecretEmpty(secret));
    }

    #endregion
}
