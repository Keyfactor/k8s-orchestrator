// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Services;

public class StoreConfigurationParserTests
{
    private readonly StoreConfigurationParser _parser = new(null);

    #region GetPropertyOrDefault Tests - Boolean

    [Fact]
    public void GetPropertyOrDefault_BooleanPropertyExists_ReturnsValue()
    {
        // Arrange
        var properties = new Dictionary<string, object>
        {
            { "TestProperty", true }
        };

        // Act
        var result = _parser.GetPropertyOrDefault<bool>(properties, "TestProperty", false);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void GetPropertyOrDefault_BooleanPropertyNotExists_ReturnsDefault()
    {
        // Arrange
        var properties = new Dictionary<string, object>();

        // Act
        var result = _parser.GetPropertyOrDefault<bool>(properties, "MissingProperty", true);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void GetPropertyOrDefault_BooleanStringValue_ParsesCorrectly()
    {
        // Arrange
        var properties = new Dictionary<string, object>
        {
            { "TestProperty", "true" }
        };

        // Act
        var result = _parser.GetPropertyOrDefault<bool>(properties, "TestProperty", false);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void GetPropertyOrDefault_BooleanInvalidString_ReturnsDefault()
    {
        // Arrange
        var properties = new Dictionary<string, object>
        {
            { "TestProperty", "invalid" }
        };

        // Act
        var result = _parser.GetPropertyOrDefault<bool>(properties, "TestProperty", true);

        // Assert
        Assert.True(result);
    }

    #endregion

    #region GetPropertyOrDefault Tests - String

    [Fact]
    public void GetPropertyOrDefault_StringPropertyExists_ReturnsValue()
    {
        // Arrange
        var properties = new Dictionary<string, object>
        {
            { "TestProperty", "test value" }
        };

        // Act
        var result = _parser.GetPropertyOrDefault<string>(properties, "TestProperty", "default");

        // Assert
        Assert.Equal("test value", result);
    }

    [Fact]
    public void GetPropertyOrDefault_StringPropertyNotExists_ReturnsDefault()
    {
        // Arrange
        var properties = new Dictionary<string, object>();

        // Act
        var result = _parser.GetPropertyOrDefault<string>(properties, "MissingProperty", "default value");

        // Assert
        Assert.Equal("default value", result);
    }

    [Fact]
    public void GetPropertyOrDefault_StringEmptyValue_ReturnsEmpty()
    {
        // Arrange
        var properties = new Dictionary<string, object>
        {
            { "TestProperty", "" }
        };

        // Act
        var result = _parser.GetPropertyOrDefault<string>(properties, "TestProperty", "default");

        // Assert
        Assert.Equal("", result);
    }

    #endregion

    #region GetPropertyOrDefault Tests - Integer

    [Fact]
    public void GetPropertyOrDefault_IntPropertyExists_ReturnsValue()
    {
        // Arrange
        var properties = new Dictionary<string, object>
        {
            { "TestProperty", 42 }
        };

        // Act
        var result = _parser.GetPropertyOrDefault<int>(properties, "TestProperty", 0);

        // Assert
        Assert.Equal(42, result);
    }

    [Fact]
    public void GetPropertyOrDefault_IntPropertyNotExists_ReturnsDefault()
    {
        // Arrange
        var properties = new Dictionary<string, object>();

        // Act
        var result = _parser.GetPropertyOrDefault<int>(properties, "MissingProperty", 100);

        // Assert
        Assert.Equal(100, result);
    }

    // Note: Integer string parsing is not implemented in the current implementation
    // The GetPropertyOrDefault<int> only works with actual int values, not string representations

    #endregion

    #region GetPropertyOrDefault Tests - Null Properties

    [Fact]
    public void GetPropertyOrDefault_NullProperties_ReturnsDefault()
    {
        // Act
        var result = _parser.GetPropertyOrDefault<string>(null, "TestProperty", "default");

        // Assert
        Assert.Equal("default", result);
    }

    [Fact]
    public void GetPropertyOrDefault_NullPropertyValue_ReturnsDefault()
    {
        // Arrange
        var properties = new Dictionary<string, object>
        {
            { "TestProperty", null }
        };

        // Act
        var result = _parser.GetPropertyOrDefault<string>(properties, "TestProperty", "default");

        // Assert
        Assert.Equal("default", result);
    }

    #endregion

    #region Parse Tests

    [Fact]
    public void Parse_ValidProperties_ReturnsConfiguration()
    {
        // Arrange
        var properties = new Dictionary<string, object>
        {
            { "PasswordIsSeparateSecret", true },
            { "PasswordFieldName", "mypassword" },
            { "StorePasswordPath", "secret/path" },
            { "SeparateChain", true },
            { "IncludeCertChain", true } // Must be true when SeparateChain is true
        };

        // Act
        var config = _parser.Parse(properties);

        // Assert
        Assert.NotNull(config);
        Assert.True(config.PasswordIsSeparateSecret);
        Assert.Equal("mypassword", config.PasswordFieldName);
        Assert.Equal("secret/path", config.StorePasswordPath);
        Assert.True(config.SeparateChain);
        Assert.True(config.IncludeCertChain);
    }

    [Fact]
    public void Parse_EmptyProperties_ReturnsDefaults()
    {
        // Arrange
        var properties = new Dictionary<string, object>();

        // Act
        var config = _parser.Parse(properties);

        // Assert
        Assert.NotNull(config);
        Assert.False(config.PasswordIsSeparateSecret);
        Assert.Equal("password", config.PasswordFieldName); // Default is "password"
        Assert.Equal("", config.StorePasswordPath);
        Assert.False(config.SeparateChain);
        Assert.True(config.IncludeCertChain); // Default is true
    }

    [Fact]
    public void Parse_NullProperties_ReturnsDefaults()
    {
        // Act
        var config = _parser.Parse(null);

        // Assert
        Assert.NotNull(config);
        Assert.False(config.PasswordIsSeparateSecret);
    }

    [Fact]
    public void Parse_PartialProperties_ReturnsPartialConfiguration()
    {
        // Arrange
        var properties = new Dictionary<string, object>
        {
            { "PasswordIsSeparateSecret", true }
        };

        // Act
        var config = _parser.Parse(properties);

        // Assert
        Assert.NotNull(config);
        Assert.True(config.PasswordIsSeparateSecret);
        Assert.Equal("password", config.PasswordFieldName); // Default
        Assert.Equal("", config.StorePasswordPath); // Default
    }

    [Fact]
    public void Parse_SeparateChainWithoutIncludeCertChain_SetsWarningAndDisablesSeparateChain()
    {
        // Arrange - Invalid configuration: SeparateChain=true but IncludeCertChain=false
        var properties = new Dictionary<string, object>
        {
            { "SeparateChain", true },
            { "IncludeCertChain", false }
        };

        // Act
        var config = _parser.Parse(properties);

        // Assert - SeparateChain should be set to false due to the conflict
        Assert.False(config.SeparateChain);
        Assert.False(config.IncludeCertChain);
    }

    #endregion

    #region DeriveSecretTypeFromCapability Tests (via Parse)

    [Theory]
    [InlineData("CertStores.K8STLSSecr.Inventory", "tls_secret")]
    [InlineData("CertStores.K8STLSSecr.Management", "tls_secret")]
    [InlineData("CertStores.K8SSecret.Discovery", "secret")]
    [InlineData("CertStores.K8SSecret.Inventory", "secret")]
    [InlineData("CertStores.K8SJKS.Management", "jks")]
    [InlineData("CertStores.K8SJKS.Reenrollment", "jks")]
    [InlineData("CertStores.K8SPKCS12.Inventory", "pkcs12")]
    [InlineData("CertStores.K8SPKCS12.Management", "pkcs12")]
    [InlineData("CertStores.K8SCluster.Inventory", "cluster")]
    [InlineData("CertStores.K8SCluster.Discovery", "cluster")]
    [InlineData("CertStores.K8SNS.Inventory", "namespace")]
    [InlineData("CertStores.K8SNS.Management", "namespace")]
    [InlineData("CertStores.K8SCert.Discovery", "certificate")]
    [InlineData("CertStores.K8SCert.Inventory", "certificate")]
    public void Parse_WithCapability_DerivesSecretType(string capability, string expectedType)
    {
        // Arrange
        var properties = new Dictionary<string, object>();

        // Act
        var config = _parser.Parse(properties, capability);

        // Assert
        Assert.Equal(expectedType, config.KubeSecretType);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Parse_WithNullOrEmptyCapability_DoesNotDeriveSecretType(string? capability)
    {
        // Arrange
        var properties = new Dictionary<string, object>();

        // Act
        var config = _parser.Parse(properties, capability);

        // Assert - KubeSecretType remains empty string (default)
        Assert.True(string.IsNullOrEmpty(config.KubeSecretType));
    }

    [Fact]
    public void Parse_WithWhitespaceCapability_ReturnsNullSecretType()
    {
        // Arrange
        var properties = new Dictionary<string, object>();

        // Act
        var config = _parser.Parse(properties, "   ");

        // Assert - DeriveSecretTypeFromCapability returns null for unknown patterns
        Assert.Null(config.KubeSecretType);
    }

    [Fact]
    public void Parse_WithUnknownCapability_ReturnsNullSecretType()
    {
        // Arrange
        var properties = new Dictionary<string, object>();
        var unknownCapability = "CertStores.UnknownStore.Inventory";

        // Act
        var config = _parser.Parse(properties, unknownCapability);

        // Assert - DeriveSecretTypeFromCapability returns null for unknown patterns
        Assert.Null(config.KubeSecretType);
    }

    [Fact]
    public void Parse_CapabilityTakesPrecedenceOverProperty()
    {
        // Arrange - Both capability and property specify a type
        var properties = new Dictionary<string, object>
        {
            { "KubeSecretType", "manual_type" }
        };
        var capability = "CertStores.K8SJKS.Inventory";

        // Act
        var config = _parser.Parse(properties, capability);

        // Assert - Capability should take precedence
        Assert.Equal("jks", config.KubeSecretType);
    }

    [Fact]
    public void Parse_PropertyUsedWhenCapabilityNotRecognized()
    {
        // Arrange - Capability doesn't map to a type, but property specifies one
        var properties = new Dictionary<string, object>
        {
            { "KubeSecretType", "manual_type" }
        };
        var capability = "CertStores.UnknownStore.Inventory";

        // Act
        var config = _parser.Parse(properties, capability);

        // Assert - Should fall back to property
        Assert.Equal("manual_type", config.KubeSecretType);
    }

    #endregion

    #region ApplyKeystoreDefaults Tests

    [Fact]
    public void ApplyKeystoreDefaults_JksType_SetsCertificateDataFieldName()
    {
        // Arrange
        var config = new StoreConfiguration
        {
            KubeSecretType = "jks",
            CertificateDataFieldName = ""
        };
        var properties = new Dictionary<string, object>();

        // Act
        _parser.ApplyKeystoreDefaults(config, properties);

        // Assert
        Assert.Equal("jks", config.CertificateDataFieldName);
    }

    [Fact]
    public void ApplyKeystoreDefaults_Pkcs12Type_SetsCertificateDataFieldName()
    {
        // Arrange
        var config = new StoreConfiguration
        {
            KubeSecretType = "pkcs12",
            CertificateDataFieldName = ""
        };
        var properties = new Dictionary<string, object>();

        // Act
        _parser.ApplyKeystoreDefaults(config, properties);

        // Assert
        Assert.Equal("pfx", config.CertificateDataFieldName);
    }

    [Fact]
    public void ApplyKeystoreDefaults_PfxType_SetsCertificateDataFieldName()
    {
        // Arrange
        var config = new StoreConfiguration
        {
            KubeSecretType = "pfx",
            CertificateDataFieldName = ""
        };
        var properties = new Dictionary<string, object>();

        // Act
        _parser.ApplyKeystoreDefaults(config, properties);

        // Assert
        Assert.Equal("pfx", config.CertificateDataFieldName);
    }

    [Fact]
    public void ApplyKeystoreDefaults_OverwritesExistingFieldName()
    {
        // Arrange - ApplyKeystoreDefaults DOES overwrite CertificateDataFieldName
        var config = new StoreConfiguration
        {
            KubeSecretType = "jks",
            CertificateDataFieldName = "custom_field"
        };
        var properties = new Dictionary<string, object>();

        // Act
        _parser.ApplyKeystoreDefaults(config, properties);

        // Assert - The default is applied regardless of existing value
        Assert.Equal("jks", config.CertificateDataFieldName);
    }

    [Fact]
    public void ApplyKeystoreDefaults_NonKeystoreType_DoesNotSetFieldName()
    {
        // Arrange
        var config = new StoreConfiguration
        {
            KubeSecretType = "tls_secret",
            CertificateDataFieldName = ""
        };
        var properties = new Dictionary<string, object>();

        // Act
        _parser.ApplyKeystoreDefaults(config, properties);

        // Assert - Should not set a default for non-keystore types
        Assert.Equal("", config.CertificateDataFieldName);
    }

    [Fact]
    public void ApplyKeystoreDefaults_P12Type_SetsCertificateDataFieldName()
    {
        // Arrange
        var config = new StoreConfiguration
        {
            KubeSecretType = "p12",
            CertificateDataFieldName = ""
        };
        var properties = new Dictionary<string, object>();

        // Act
        _parser.ApplyKeystoreDefaults(config, properties);

        // Assert
        Assert.Equal("pfx", config.CertificateDataFieldName);
    }

    #endregion
}
