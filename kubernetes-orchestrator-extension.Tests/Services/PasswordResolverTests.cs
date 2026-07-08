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
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Services;

/// <summary>
/// Unit tests for the PasswordResolver service.
/// Tests password resolution from various sources: K8S secrets, direct values, and defaults.
/// </summary>
public class PasswordResolverTests
{
    private readonly PasswordResolver _resolver;

    public PasswordResolverTests()
    {
        _resolver = new PasswordResolver(null);
    }

    #region Direct Password Tests

    [Fact]
    public void ResolveStorePassword_DirectPassword_ReturnsPassword()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = false,
            StorePassword = "mypassword123"
        };

        // Act
        var result = _resolver.ResolveStorePassword(jobCert, "default");

        // Assert
        Assert.Equal("mypassword123", result.Value);
        Assert.Equal(Encoding.UTF8.GetBytes("mypassword123"), result.Bytes);
    }

    [Fact]
    public void ResolveStorePassword_DirectPassword_WithTrailingNewline_TrimsProperly()
    {
        // Arrange - Common kubectl issue where secrets have trailing newlines
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = false,
            StorePassword = "mypassword\n"
        };

        // Act
        var result = _resolver.ResolveStorePassword(jobCert, "default");

        // Assert
        Assert.Equal("mypassword", result.Value);
        Assert.DoesNotContain((byte)'\n', result.Bytes);
    }

    [Fact]
    public void ResolveStorePassword_DirectPassword_WithCarriageReturnNewline_TrimsProperly()
    {
        // Arrange - Windows-style line endings
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = false,
            StorePassword = "mypassword\r\n"
        };

        // Act
        var result = _resolver.ResolveStorePassword(jobCert, "default");

        // Assert
        Assert.Equal("mypassword", result.Value);
    }

    #endregion

    #region Default Password Tests

    [Fact]
    public void ResolveStorePassword_NoPasswordSet_ReturnsDefault()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = false,
            StorePassword = null
        };

        // Act
        var result = _resolver.ResolveStorePassword(jobCert, "defaultpwd");

        // Assert
        Assert.Equal("defaultpwd", result.Value);
    }

    [Fact]
    public void ResolveStorePassword_EmptyPassword_ReturnsDefault()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = false,
            StorePassword = ""
        };

        // Act
        var result = _resolver.ResolveStorePassword(jobCert, "defaultpwd");

        // Assert
        Assert.Equal("defaultpwd", result.Value);
    }

    [Fact]
    public void ResolveStorePassword_NullDefaultPassword_ReturnsEmptyString()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = false,
            StorePassword = null
        };

        // Act
        var result = _resolver.ResolveStorePassword(jobCert, null);

        // Assert
        Assert.Equal("", result.Value);
        Assert.Empty(result.Bytes);
    }

    #endregion

    #region K8S Secret Password Tests - Same Secret

    [Fact]
    public void ResolveStorePassword_FromSameSecret_ReturnsPassword()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = true,
            StorePasswordPath = null // No buddy secret path
        };

        var existingSecretData = new Dictionary<string, byte[]>
        {
            { "password", Encoding.UTF8.GetBytes("secretpassword") }
        };

        // Act
        var result = _resolver.ResolveStorePassword(
            jobCert,
            "default",
            existingSecretData,
            passwordFieldName: "password");

        // Assert
        Assert.Equal("secretpassword", result.Value);
    }

    [Fact]
    public void ResolveStorePassword_FromSameSecret_CustomFieldName_ReturnsPassword()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = true,
            StorePasswordPath = null
        };

        var existingSecretData = new Dictionary<string, byte[]>
        {
            { "keystorePass", Encoding.UTF8.GetBytes("customfieldpassword") }
        };

        // Act
        var result = _resolver.ResolveStorePassword(
            jobCert,
            "default",
            existingSecretData,
            passwordFieldName: "keystorePass");

        // Assert
        Assert.Equal("customfieldpassword", result.Value);
    }

    [Fact]
    public void ResolveStorePassword_FromSameSecret_FieldNotFound_ThrowsException()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = true,
            StorePasswordPath = null
        };

        var existingSecretData = new Dictionary<string, byte[]>
        {
            { "otherfield", Encoding.UTF8.GetBytes("somevalue") }
        };

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            _resolver.ResolveStorePassword(
                jobCert,
                "default",
                existingSecretData,
                passwordFieldName: "password"));

        Assert.Contains("password", ex.Message);
        Assert.Contains("not found", ex.Message);
    }

    [Fact]
    public void ResolveStorePassword_FromSameSecret_NullSecretData_ThrowsException()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = true,
            StorePasswordPath = null
        };

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() =>
            _resolver.ResolveStorePassword(
                jobCert,
                "default",
                existingSecretData: null,
                passwordFieldName: "password"));
    }

    #endregion

    #region K8S Secret Password Tests - Buddy Secret

    [Fact]
    public void ResolveStorePassword_FromBuddySecret_ReturnsPassword()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = true,
            StorePasswordPath = "mynamespace/mypasswordsecret"
        };

        var buddySecret = new V1Secret
        {
            Data = new Dictionary<string, byte[]>
            {
                { "password", Encoding.UTF8.GetBytes("buddypassword") }
            }
        };

        V1Secret BuddyReader(string name, string ns)
        {
            Assert.Equal("mypasswordsecret", name);
            Assert.Equal("mynamespace", ns);
            return buddySecret;
        }

        // Act
        var result = _resolver.ResolveStorePassword(
            jobCert,
            "default",
            existingSecretData: null,
            passwordFieldName: "password",
            buddySecretReader: BuddyReader);

        // Assert
        Assert.Equal("buddypassword", result.Value);
    }

    [Fact]
    public void ResolveStorePassword_FromBuddySecret_NoBuddyReader_ThrowsException()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = true,
            StorePasswordPath = "mynamespace/mypasswordsecret"
        };

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            _resolver.ResolveStorePassword(
                jobCert,
                "default",
                existingSecretData: null,
                passwordFieldName: "password",
                buddySecretReader: null));

        Assert.Contains("BuddySecretReader", ex.Message);
    }

    [Fact]
    public void ResolveStorePassword_FromBuddySecret_InvalidPathFormat_ThrowsException()
    {
        // Arrange - Single segment path is invalid
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = true,
            StorePasswordPath = "invalidpath" // Missing namespace/secretname format
        };

        V1Secret BuddyReader(string name, string ns) => null;

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            _resolver.ResolveStorePassword(
                jobCert,
                "default",
                existingSecretData: null,
                passwordFieldName: "password",
                buddySecretReader: BuddyReader));

        Assert.Contains("Invalid StorePasswordPath format", ex.Message);
    }

    [Fact]
    public void ResolveStorePassword_FromBuddySecret_FieldNotFound_ThrowsException()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = true,
            StorePasswordPath = "ns/secret"
        };

        var buddySecret = new V1Secret
        {
            Data = new Dictionary<string, byte[]>
            {
                { "wrongfield", Encoding.UTF8.GetBytes("value") }
            }
        };

        V1Secret BuddyReader(string name, string ns) => buddySecret;

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            _resolver.ResolveStorePassword(
                jobCert,
                "default",
                existingSecretData: null,
                passwordFieldName: "password",
                buddySecretReader: BuddyReader));

        Assert.Contains("password", ex.Message);
        Assert.Contains("not found", ex.Message);
    }

    [Fact]
    public void ResolveStorePassword_FromBuddySecret_NullBuddyData_ThrowsException()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = true,
            StorePasswordPath = "ns/secret"
        };

        var buddySecret = new V1Secret { Data = null };

        V1Secret BuddyReader(string name, string ns) => buddySecret;

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() =>
            _resolver.ResolveStorePassword(
                jobCert,
                "default",
                existingSecretData: null,
                passwordFieldName: "password",
                buddySecretReader: BuddyReader));
    }

    #endregion

    #region Unicode and Special Character Tests

    [Theory]
    [InlineData("password123")]
    [InlineData("P@ssw0rd!#$%")]
    [InlineData("密码测试")]
    [InlineData("пароль")]
    [InlineData("パスワード")]
    public void ResolveStorePassword_VariousCharacterSets_HandlesCorrectly(string password)
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = false,
            StorePassword = password
        };

        // Act
        var result = _resolver.ResolveStorePassword(jobCert, "default");

        // Assert
        Assert.Equal(password, result.Value);
        Assert.Equal(Encoding.UTF8.GetBytes(password), result.Bytes);
    }

    [Fact]
    public void ResolveStorePassword_VeryLongPassword_HandlesCorrectly()
    {
        // Arrange
        var longPassword = new string('x', 10000);
        var jobCert = new K8SJobCertificate
        {
            PasswordIsK8SSecret = false,
            StorePassword = longPassword
        };

        // Act
        var result = _resolver.ResolveStorePassword(jobCert, "default");

        // Assert
        Assert.Equal(longPassword, result.Value);
        Assert.Equal(10000, result.Value.Length);
    }

    #endregion
}
