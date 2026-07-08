// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Reflection;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Jobs;

/// <summary>
/// Tests for PAMUtilities - Privileged Access Management field resolution.
/// Uses reflection to access internal class and methods.
/// </summary>
public class PAMUtilitiesTests
{
    private readonly Mock<IPAMSecretResolver> _mockResolver;
    private readonly Mock<ILogger> _mockLogger;
    private readonly MethodInfo _resolvePamFieldMethod;

    public PAMUtilitiesTests()
    {
        _mockResolver = new Mock<IPAMSecretResolver>();
        _mockLogger = new Mock<ILogger>();

        // PAMUtilities is internal, so we need to use reflection
        var pamUtilitiesType = Type.GetType(
            "Keyfactor.Extensions.Orchestrator.K8S.Jobs.PAMUtilities, Keyfactor.Orchestrators.K8S");
        Assert.NotNull(pamUtilitiesType);

        _resolvePamFieldMethod = pamUtilitiesType.GetMethod(
            "ResolvePAMField",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(_resolvePamFieldMethod);
    }

    private string InvokeResolvePAMField(IPAMSecretResolver resolver, ILogger logger, string name, string key)
    {
        return (string)_resolvePamFieldMethod.Invoke(null, new object[] { resolver, logger, name, key });
    }

    #region Empty/Null Input Tests

    [Fact]
    public void ResolvePAMField_NullKey_ReturnsNull()
    {
        // Act
        var result = InvokeResolvePAMField(_mockResolver.Object, _mockLogger.Object, "TestField", null);

        // Assert
        Assert.Null(result);
        _mockResolver.Verify(r => r.Resolve(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public void ResolvePAMField_EmptyKey_ReturnsEmpty()
    {
        // Act
        var result = InvokeResolvePAMField(_mockResolver.Object, _mockLogger.Object, "TestField", "");

        // Assert
        Assert.Equal("", result);
        _mockResolver.Verify(r => r.Resolve(It.IsAny<string>()), Times.Never);
    }

    #endregion

    #region Non-JSON Input Tests

    [Theory]
    [InlineData("plaintext")]
    [InlineData("password123")]
    [InlineData("not a json string")]
    [InlineData("{incomplete")]
    [InlineData("incomplete}")]
    public void ResolvePAMField_NonJsonKey_ReturnsOriginalValue(string key)
    {
        // Act
        var result = InvokeResolvePAMField(_mockResolver.Object, _mockLogger.Object, "TestField", key);

        // Assert
        Assert.Equal(key, result);
        _mockResolver.Verify(r => r.Resolve(It.IsAny<string>()), Times.Never);
    }

    #endregion

    #region PAM Resolution Tests

    [Fact]
    public void ResolvePAMField_ValidJsonKey_CallsResolver()
    {
        // Arrange
        var pamReference = "{\"provider\":\"CyberArk\",\"key\":\"secret123\"}";
        var expectedValue = "resolved-secret-value";
        _mockResolver.Setup(r => r.Resolve(pamReference)).Returns(expectedValue);

        // Act
        var result = InvokeResolvePAMField(_mockResolver.Object, _mockLogger.Object, "Password", pamReference);

        // Assert
        Assert.Equal(expectedValue, result);
        _mockResolver.Verify(r => r.Resolve(pamReference), Times.Once);
    }

    [Fact]
    public void ResolvePAMField_SimpleJsonKey_CallsResolver()
    {
        // Arrange - Even minimal JSON triggers PAM resolution
        var pamReference = "{}";
        var expectedValue = "resolved-value";
        _mockResolver.Setup(r => r.Resolve(pamReference)).Returns(expectedValue);

        // Act
        var result = InvokeResolvePAMField(_mockResolver.Object, _mockLogger.Object, "ApiKey", pamReference);

        // Assert
        Assert.Equal(expectedValue, result);
        _mockResolver.Verify(r => r.Resolve(pamReference), Times.Once);
    }

    [Fact]
    public void ResolvePAMField_ResolverReturnsNull_ReturnsNull()
    {
        // Arrange
        var pamReference = "{\"provider\":\"vault\"}";
        _mockResolver.Setup(r => r.Resolve(pamReference)).Returns((string)null);

        // Act
        var result = InvokeResolvePAMField(_mockResolver.Object, _mockLogger.Object, "Secret", pamReference);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void ResolvePAMField_ResolverReturnsEmpty_ReturnsEmpty()
    {
        // Arrange
        var pamReference = "{\"provider\":\"vault\"}";
        _mockResolver.Setup(r => r.Resolve(pamReference)).Returns("");

        // Act
        var result = InvokeResolvePAMField(_mockResolver.Object, _mockLogger.Object, "Secret", pamReference);

        // Assert
        Assert.Equal("", result);
    }

    #endregion

    #region Exception Handling Tests

    [Fact]
    public void ResolvePAMField_ResolverThrowsException_ReturnsOriginalValue()
    {
        // Arrange
        var pamReference = "{\"provider\":\"failing\"}";
        _mockResolver.Setup(r => r.Resolve(pamReference)).Throws(new InvalidOperationException("PAM provider unavailable"));

        // Act
        var result = InvokeResolvePAMField(_mockResolver.Object, _mockLogger.Object, "Secret", pamReference);

        // Assert - Should return original value when resolution fails
        Assert.Equal(pamReference, result);
    }

    [Fact]
    public void ResolvePAMField_ResolverThrowsArgumentException_ReturnsOriginalValue()
    {
        // Arrange
        var pamReference = "{\"invalid\":\"reference\"}";
        _mockResolver.Setup(r => r.Resolve(pamReference)).Throws(new ArgumentException("Invalid PAM reference format"));

        // Act
        var result = InvokeResolvePAMField(_mockResolver.Object, _mockLogger.Object, "Secret", pamReference);

        // Assert
        Assert.Equal(pamReference, result);
    }

    #endregion
}
