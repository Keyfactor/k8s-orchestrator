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
using Newtonsoft.Json.Linq;
using Xunit;
using JksDiscovery = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SJKS.Discovery;
using Pkcs12Discovery = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SPKCS12.Discovery;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Jobs;

/// <summary>
/// Tests for DiscoveryBase protected helper methods via concrete test subclasses.
/// The Keyfactor framework supplies <c>DiscoveryJobConfiguration.JobProperties</c> as a plain
/// <c>Dictionary&lt;string, object&gt;</c> keyed by <c>dirs</c>, <c>extensions</c>, <c>ignoreddirs</c>
/// and <c>patterns</c>; these tests use exactly that shape.
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

    private class TestableJksDiscovery : JksDiscovery
    {
        public TestableJksDiscovery() : base(null) { }

        public string[] TestGetCustomAllowedKeys(DiscoveryJobConfiguration config)
            => GetCustomAllowedKeys(config);
    }

    private class TestablePkcs12Discovery : Pkcs12Discovery
    {
        public TestablePkcs12Discovery() : base(null) { }

        public string[] TestGetCustomAllowedKeys(DiscoveryJobConfiguration config)
            => GetCustomAllowedKeys(config);
    }

    private readonly TestableDiscovery _discovery = new();

    private static DiscoveryJobConfiguration ConfigWith(params (string Key, object Value)[] props)
    {
        var dict = new Dictionary<string, object>();
        foreach (var (key, value) in props) dict[key] = value;
        return new DiscoveryJobConfiguration { JobProperties = dict };
    }

    #region GetNamespacesToSearch Tests

    [Fact]
    public void GetNamespacesToSearch_NullJobProperties_FallsBackToDefault()
    {
        var config = new DiscoveryJobConfiguration { JobProperties = null };
        Assert.Equal("default", _discovery.TestGetNamespacesToSearch(config));
    }

    [Fact]
    public void GetNamespacesToSearch_NullConfig_FallsBackToDefault()
    {
        Assert.Equal("default", _discovery.TestGetNamespacesToSearch(null));
    }

    [Theory]
    [InlineData("all")]
    [InlineData("All")]
    [InlineData("ALL")]
    [InlineData(" all ")]
    public void GetNamespacesToSearch_All_IsCaseInsensitiveAndNormalised(string value)
    {
        var result = _discovery.TestGetNamespacesToSearch(ConfigWith(("dirs", value)));
        Assert.Equal("all", result);
    }

    [Fact]
    public void GetNamespacesToSearch_AllInsideList_ReturnsAll()
    {
        var result = _discovery.TestGetNamespacesToSearch(ConfigWith(("dirs", "kube-system, All")));
        Assert.Equal("all", result);
    }

    [Fact]
    public void GetNamespacesToSearch_PlainDictionary_RealKeyDirs_ReturnsValue()
    {
        // Regression: previously JsonConvert.DeserializeObject(JobProperties.ToString()) was used, which threw
        // "Unexpected character encountered while parsing value: S" for a plain Dictionary and returned "".
        var config = new DiscoveryJobConfiguration
        {
            JobProperties = new Dictionary<string, object>
            {
                { "dirs", "namespace1,namespace2" },
                { "extensions", "" },
                { "ignoreddirs", "" },
                { "patterns", "" }
            }
        };

        Assert.Equal("namespace1,namespace2", _discovery.TestGetNamespacesToSearch(config));
    }

    [Fact]
    public void GetNamespacesToSearch_CsvWithSpaces_IsTrimmed()
    {
        var result = _discovery.TestGetNamespacesToSearch(ConfigWith(("dirs", " ns1 , ns2 ,, ns3 ")));
        Assert.Equal("ns1,ns2,ns3", result);
    }

    [Fact]
    public void GetNamespacesToSearch_SingleNamespace_ReturnsIt()
    {
        Assert.Equal("kube-system", _discovery.TestGetNamespacesToSearch(ConfigWith(("dirs", "kube-system"))));
    }

    [Fact]
    public void GetNamespacesToSearch_DuplicateNamespaces_AreCollapsed()
    {
        Assert.Equal("a,b", _discovery.TestGetNamespacesToSearch(ConfigWith(("dirs", "a,b,a"))));
    }

    [Theory]
    [InlineData("dirs")]
    [InlineData("DIRS")]
    [InlineData("Directories")]
    [InlineData("directories")]
    public void GetNamespacesToSearch_KeyLookupIsCaseInsensitiveAndAcceptsAlias(string key)
    {
        Assert.Equal("ns1", _discovery.TestGetNamespacesToSearch(ConfigWith((key, "ns1"))));
    }

    [Fact]
    public void GetNamespacesToSearch_JValueString_ReturnsValue()
    {
        var result = _discovery.TestGetNamespacesToSearch(ConfigWith(("dirs", new JValue("ns1, ns2"))));
        Assert.Equal("ns1,ns2", result);
    }

    [Fact]
    public void GetNamespacesToSearch_JArrayValue_ReturnsJoined()
    {
        var result = _discovery.TestGetNamespacesToSearch(ConfigWith(("dirs", new JArray("ns1", "ns2"))));
        Assert.Equal("ns1,ns2", result);
    }

    [Fact]
    public void GetNamespacesToSearch_JValueAll_ReturnsAll()
    {
        Assert.Equal("all", _discovery.TestGetNamespacesToSearch(ConfigWith(("dirs", new JValue("All")))));
    }

    [Fact]
    public void GetNamespacesToSearch_NoDirsKey_FallsBackToDefault()
    {
        Assert.Equal("default", _discovery.TestGetNamespacesToSearch(ConfigWith(("SomeOtherKey", "value"))));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(" , ,")]
    public void GetNamespacesToSearch_EmptyValue_FallsBackToDefault(string value)
    {
        Assert.Equal("default", _discovery.TestGetNamespacesToSearch(ConfigWith(("dirs", value))));
    }

    [Fact]
    public void GetNamespacesToSearch_JNullValue_FallsBackToDefault()
    {
        Assert.Equal("default", _discovery.TestGetNamespacesToSearch(ConfigWith(("dirs", JValue.CreateNull()))));
    }

    #endregion

    #region GetCustomAllowedKeys Tests

    [Fact]
    public void GetCustomAllowedKeys_NullJobProperties_ReturnsNull()
    {
        var config = new DiscoveryJobConfiguration { JobProperties = null };
        Assert.Null(_discovery.TestGetCustomAllowedKeys(config));
    }

    [Fact]
    public void GetCustomAllowedKeys_PlainDictionary_Patterns_ReturnsParsedArray()
    {
        // Regression: plain Dictionary<string, object> must work (not just a JSON-ToString subclass).
        var config = new DiscoveryJobConfiguration
        {
            JobProperties = new Dictionary<string, object>
            {
                { "dirs", "all" },
                { "extensions", "" },
                { "ignoreddirs", "" },
                { "patterns", "tls.crt,mycert,other" }
            }
        };

        var result = _discovery.TestGetCustomAllowedKeys(config);
        Assert.Equal(new[] { "tls.crt", "mycert", "other" }, result);
    }

    [Fact]
    public void GetCustomAllowedKeys_SemicolonSeparator_ReturnsParsedArray()
    {
        var result = _discovery.TestGetCustomAllowedKeys(ConfigWith(("patterns", "a;b")));
        Assert.Equal(new[] { "a", "b" }, result);
    }

    [Fact]
    public void GetCustomAllowedKeys_TrimsWhitespaceAndDropsEmpty()
    {
        var result = _discovery.TestGetCustomAllowedKeys(ConfigWith(("patterns", " a , b ,, c ")));
        Assert.Equal(new[] { "a", "b", "c" }, result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void GetCustomAllowedKeys_EmptyPatterns_ReturnsNull(string value)
    {
        Assert.Null(_discovery.TestGetCustomAllowedKeys(ConfigWith(("patterns", value))));
    }

    [Fact]
    public void GetCustomAllowedKeys_NoPatternsKey_ReturnsNull()
    {
        Assert.Null(_discovery.TestGetCustomAllowedKeys(ConfigWith(("SomeOtherKey", "value"))));
    }

    [Fact]
    public void GetCustomAllowedKeys_JValuePatterns_ReturnsParsedArray()
    {
        var result = _discovery.TestGetCustomAllowedKeys(ConfigWith(("patterns", new JValue("a,b"))));
        Assert.Equal(new[] { "a", "b" }, result);
    }

    [Fact]
    public void GetCustomAllowedKeys_DefaultStoreTypes_IgnoreExtensions()
    {
        // 1.x only honoured `extensions` for the keystore store types.
        var result = _discovery.TestGetCustomAllowedKeys(ConfigWith(("extensions", "pem,crt")));
        Assert.Null(result);
    }

    [Fact]
    public void GetCustomAllowedKeys_Jks_CombinesPatternsAndExtensions()
    {
        var jks = new TestableJksDiscovery();
        var result = jks.TestGetCustomAllowedKeys(ConfigWith(("patterns", "mykeystore"), ("extensions", "jks, truststore")));
        Assert.Equal(new[] { "mykeystore", "jks", "truststore" }, result);
    }

    [Fact]
    public void GetCustomAllowedKeys_Pkcs12_CombinesPatternsAndExtensions_Distinct()
    {
        var p12 = new TestablePkcs12Discovery();
        var result = p12.TestGetCustomAllowedKeys(ConfigWith(("patterns", "pfx,p12"), ("extensions", "p12")));
        Assert.Equal(new[] { "pfx", "p12" }, result);
    }

    [Fact]
    public void GetCustomAllowedKeys_Jks_ExtensionsOnly_ReturnsExtensions()
    {
        var jks = new TestableJksDiscovery();
        Assert.Equal(new[] { "jks" }, jks.TestGetCustomAllowedKeys(ConfigWith(("extensions", "jks"))));
    }

    #endregion
}
