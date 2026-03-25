// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Newtonsoft.Json;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Jobs;

/// <summary>
/// Tests for DiscoveryBase protected helper methods via a concrete test subclass.
/// </summary>
public class DiscoveryBaseTests
{
    /// <summary>
    /// Test-only concrete subclass of DiscoveryBase that exposes protected methods.
    /// </summary>
    private class TestableDiscovery : DiscoveryBase
    {
        public TestableDiscovery() : base(null)
        {
            Logger = LogHandler.GetClassLogger<TestableDiscovery>();
        }

        public string TestGetNamespacesToSearch(DiscoveryJobConfiguration config)
            => GetNamespacesToSearch(config);

        public string[] TestGetCustomAllowedKeys(DiscoveryJobConfiguration config)
            => GetCustomAllowedKeys(config);
    }

    /// <summary>
    /// Dictionary subclass whose ToString() returns JSON, matching
    /// how the Keyfactor framework populates JobProperties at runtime.
    /// </summary>
    private class JsonDictionary : Dictionary<string, object>
    {
        public override string ToString() => JsonConvert.SerializeObject(this);
    }

    private readonly TestableDiscovery _discovery = new();

    #region GetNamespacesToSearch Tests

    [Fact]
    public void GetNamespacesToSearch_NullJobProperties_ReturnsEmpty()
    {
        var config = new DiscoveryJobConfiguration { JobProperties = null };
        var result = _discovery.TestGetNamespacesToSearch(config);
        Assert.Equal("", result);
    }

    [Fact]
    public void GetNamespacesToSearch_WithDirectories_ReturnsValue()
    {
        var config = new DiscoveryJobConfiguration
        {
            JobProperties = new JsonDictionary
            {
                { "Directories", "namespace1,namespace2" }
            }
        };

        var result = _discovery.TestGetNamespacesToSearch(config);
        Assert.Equal("namespace1,namespace2", result);
    }

    [Fact]
    public void GetNamespacesToSearch_NoDirectoriesKey_ReturnsEmpty()
    {
        var config = new DiscoveryJobConfiguration
        {
            JobProperties = new JsonDictionary
            {
                { "SomeOtherKey", "value" }
            }
        };

        var result = _discovery.TestGetNamespacesToSearch(config);
        Assert.Equal("", result);
    }

    [Fact]
    public void GetNamespacesToSearch_NonJsonToString_ReturnsEmpty()
    {
        // A plain Dictionary<string, object> whose ToString() is not valid JSON
        // This exercises the catch block in GetNamespacesToSearch
        var config = new DiscoveryJobConfiguration
        {
            JobProperties = new Dictionary<string, object>
            {
                { "Directories", "namespace1" }
            }
        };

        var result = _discovery.TestGetNamespacesToSearch(config);
        Assert.Equal("", result);
    }

    #endregion

    #region GetCustomAllowedKeys Tests

    [Fact]
    public void GetCustomAllowedKeys_NullJobProperties_ReturnsNull()
    {
        var config = new DiscoveryJobConfiguration { JobProperties = null };
        var result = _discovery.TestGetCustomAllowedKeys(config);
        Assert.Null(result);
    }

    [Fact]
    public void GetCustomAllowedKeys_WithExtensions_ReturnsParsedArray()
    {
        var config = new DiscoveryJobConfiguration
        {
            JobProperties = new JsonDictionary
            {
                { "Extensions", ".crt,.key,.pem" }
            }
        };

        var result = _discovery.TestGetCustomAllowedKeys(config);
        Assert.NotNull(result);
        Assert.Equal(3, result.Length);
        Assert.Equal(".crt", result[0]);
        Assert.Equal(".key", result[1]);
        Assert.Equal(".pem", result[2]);
    }

    [Fact]
    public void GetCustomAllowedKeys_WithSemicolonSeparator_ReturnsParsedArray()
    {
        var config = new DiscoveryJobConfiguration
        {
            JobProperties = new JsonDictionary
            {
                { "Extensions", ".crt;.key" }
            }
        };

        var result = _discovery.TestGetCustomAllowedKeys(config);
        Assert.NotNull(result);
        Assert.Equal(2, result.Length);
    }

    [Fact]
    public void GetCustomAllowedKeys_EmptyExtensions_ReturnsNull()
    {
        var config = new DiscoveryJobConfiguration
        {
            JobProperties = new JsonDictionary
            {
                { "Extensions", "" }
            }
        };

        var result = _discovery.TestGetCustomAllowedKeys(config);
        Assert.Null(result);
    }

    [Fact]
    public void GetCustomAllowedKeys_NoExtensionsKey_ReturnsNull()
    {
        var config = new DiscoveryJobConfiguration
        {
            JobProperties = new JsonDictionary
            {
                { "SomeOtherKey", "value" }
            }
        };

        var result = _discovery.TestGetCustomAllowedKeys(config);
        Assert.Null(result);
    }

    [Fact]
    public void GetCustomAllowedKeys_NonJsonToString_ReturnsNull()
    {
        // Exercises the catch block when ToString() doesn't produce valid JSON
        var config = new DiscoveryJobConfiguration
        {
            JobProperties = new Dictionary<string, object>
            {
                { "Extensions", ".crt,.key" }
            }
        };

        var result = _discovery.TestGetCustomAllowedKeys(config);
        Assert.Null(result);
    }

    [Fact]
    public void GetCustomAllowedKeys_TrimsWhitespace()
    {
        var config = new DiscoveryJobConfiguration
        {
            JobProperties = new JsonDictionary
            {
                { "Extensions", " .crt , .key , .pem " }
            }
        };

        var result = _discovery.TestGetCustomAllowedKeys(config);
        Assert.NotNull(result);
        Assert.Equal(3, result.Length);
        Assert.Equal(".crt", result[0]);
        Assert.Equal(".key", result[1]);
        Assert.Equal(".pem", result[2]);
    }

    #endregion
}