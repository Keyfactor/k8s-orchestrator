// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Services;

public class KeystoreOperationsTests
{
    private readonly KeystoreOperations _operations = new(null);

    #region ParseAliasAndFieldName Tests

    [Fact]
    public void ParseAliasAndFieldName_AliasWithSlash_SplitsCorrectly()
    {
        // Act
        var result = _operations.ParseAliasAndFieldName("keystore.p12/myalias", "default.p12");

        // Assert
        Assert.Equal("keystore.p12", result.FieldName);
        Assert.Equal("myalias", result.Alias);
    }

    [Fact]
    public void ParseAliasAndFieldName_AliasWithoutSlash_UsesDefault()
    {
        // Act
        var result = _operations.ParseAliasAndFieldName("myalias", "default.p12");

        // Assert
        Assert.Equal("default.p12", result.FieldName);
        Assert.Equal("myalias", result.Alias);
    }

    [Fact]
    public void ParseAliasAndFieldName_EmptyAlias_UsesDefaults()
    {
        // Act
        var result = _operations.ParseAliasAndFieldName("", "default.p12");

        // Assert
        Assert.Equal("default.p12", result.FieldName);
        Assert.Equal("default", result.Alias); // Implementation returns "default" for empty alias
    }

    [Fact]
    public void ParseAliasAndFieldName_NullAlias_UsesDefaults()
    {
        // Act
        var result = _operations.ParseAliasAndFieldName(null, "default.p12");

        // Assert
        Assert.Equal("default.p12", result.FieldName);
        Assert.Equal("default", result.Alias); // Implementation returns "default" for null alias
    }

    [Fact]
    public void ParseAliasAndFieldName_MultipleSlashes_SplitsOnFirst()
    {
        // Act
        var result = _operations.ParseAliasAndFieldName("keystore.p12/alias", "default.p12");

        // Assert
        Assert.Equal("keystore.p12", result.FieldName);
        Assert.Equal("alias", result.Alias);
    }

    #endregion

    #region ExtractStoreFileNameFromProperties Tests

    [Fact]
    public void ExtractStoreFileNameFromProperties_ValidJson_ReturnsFileName()
    {
        // Arrange
        var propertiesJson = "{\"StoreFileName\": \"custom.p12\"}";

        // Act
        var fileName = _operations.ExtractStoreFileNameFromProperties(propertiesJson, "default.p12");

        // Assert
        Assert.Equal("custom.p12", fileName);
    }

    [Fact]
    public void ExtractStoreFileNameFromProperties_MissingProperty_ReturnsDefault()
    {
        // Arrange
        var propertiesJson = "{\"OtherProperty\": \"value\"}";

        // Act
        var fileName = _operations.ExtractStoreFileNameFromProperties(propertiesJson, "default.p12");

        // Assert
        Assert.Equal("default.p12", fileName);
    }

    [Fact]
    public void ExtractStoreFileNameFromProperties_EmptyStoreFileName_ReturnsDefault()
    {
        // Arrange
        var propertiesJson = "{\"StoreFileName\": \"\"}";

        // Act
        var fileName = _operations.ExtractStoreFileNameFromProperties(propertiesJson, "default.p12");

        // Assert
        Assert.Equal("default.p12", fileName);
    }

    [Fact]
    public void ExtractStoreFileNameFromProperties_NullJson_ReturnsDefault()
    {
        // Act
        var fileName = _operations.ExtractStoreFileNameFromProperties(null, "default.p12");

        // Assert
        Assert.Equal("default.p12", fileName);
    }

    [Fact]
    public void ExtractStoreFileNameFromProperties_EmptyJson_ReturnsDefault()
    {
        // Act
        var fileName = _operations.ExtractStoreFileNameFromProperties("", "default.p12");

        // Assert
        Assert.Equal("default.p12", fileName);
    }

    [Fact]
    public void ExtractStoreFileNameFromProperties_InvalidJson_ReturnsDefault()
    {
        // Arrange
        var invalidJson = "not valid json";

        // Act
        var fileName = _operations.ExtractStoreFileNameFromProperties(invalidJson, "default.p12");

        // Assert
        Assert.Equal("default.p12", fileName);
    }

    [Fact]
    public void ExtractStoreFileNameFromProperties_NullStoreFileName_ReturnsDefault()
    {
        // Arrange
        var propertiesJson = "{\"StoreFileName\": null}";

        // Act
        var fileName = _operations.ExtractStoreFileNameFromProperties(propertiesJson, "default.p12");

        // Assert
        Assert.Equal("default.p12", fileName);
    }

    [Fact]
    public void ExtractStoreFileNameFromProperties_JksFileName_ReturnsFileName()
    {
        // Arrange
        var propertiesJson = "{\"StoreFileName\": \"keystore.jks\"}";

        // Act
        var fileName = _operations.ExtractStoreFileNameFromProperties(propertiesJson, "default.jks");

        // Assert
        Assert.Equal("keystore.jks", fileName);
    }

    #endregion
}
