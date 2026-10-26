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

        public string[] TestGetIgnoredNamespaces(DiscoveryJobConfiguration config)
            => GetIgnoredNamespaces(config);

        public static string TestExtractNamespace(string location)
            => ExtractNamespace(location);

        public static List<string> TestFilter(IEnumerable<string> locations, IEnumerable<string> ignored,
            out List<string> dropped)
            => FilterIgnoredNamespaces(locations, ignored, out dropped);
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

    #region Ignored Directories Tests

    [Fact]
    public void GetIgnoredNamespaces_PlainDictionary_ReturnsTrimmedDistinctValues()
    {
        var result = _discovery.TestGetIgnoredNamespaces(ConfigWith(("ignoreddirs", " kube-system , KUBE-SYSTEM,cert-manager ")));
        Assert.Equal(new[] { "kube-system", "cert-manager" }, result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(" , ,")]
    public void GetIgnoredNamespaces_BlankValue_ReturnsEmpty(string value)
    {
        Assert.Empty(_discovery.TestGetIgnoredNamespaces(ConfigWith(("ignoreddirs", value))));
    }

    [Fact]
    public void GetIgnoredNamespaces_NullJobProperties_ReturnsEmpty()
    {
        Assert.Empty(_discovery.TestGetIgnoredNamespaces(new DiscoveryJobConfiguration { JobProperties = null }));
    }

    [Fact]
    public void GetIgnoredNamespaces_JArrayValue_ReturnsJoined()
    {
        var result = _discovery.TestGetIgnoredNamespaces(ConfigWith(("ignoreddirs", new JArray("a", "b"))));
        Assert.Equal(new[] { "a", "b" }, result);
    }

    [Theory]
    [InlineData("my-cluster/prod/secrets/web-tls", "prod")]
    [InlineData("10.0.0.1/kube-system/secrets/x", "kube-system")]
    [InlineData("my-cluster/namespace/prod", "prod")]
    [InlineData("my-cluster/namespace/secrets", "secrets")]              // namespace form, namespace literally called "secrets"
    [InlineData("my-cluster/namespace/secrets/x", "namespace")]          // secret form, namespace literally called "namespace"
    [InlineData("arn:aws:eks:us-east-1:123456789012:cluster/foo/prod/secrets/web-tls", "prod")] // cluster name contains '/'
    [InlineData("arn:aws:eks:us-east-1:123456789012:cluster/foo/namespace/prod", "prod")]
    [InlineData("  my-cluster/ prod /secrets/web-tls", "prod")]
    public void ExtractNamespace_KnownLocationFormats_ReturnsNamespace(string location, string expected)
    {
        Assert.Equal(expected, TestableDiscovery.TestExtractNamespace(location));
    }

    [Theory]
    [InlineData("my-cluster")]
    [InlineData("10.0.0.1")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("some/other/shape")]
    public void ExtractNamespace_NoNamespaceInLocation_ReturnsNull(string location)
    {
        Assert.Null(TestableDiscovery.TestExtractNamespace(location));
    }

    [Fact]
    public void FilterIgnoredNamespaces_DropsMatchingNamespaces_AllFormats()
    {
        var locations = new List<string>
        {
            "c/kube-system/secrets/a",
            "c/prod/secrets/b",
            "c/namespace/kube-system",
            "c/namespace/dev",
            "c"
        };

        var kept = TestableDiscovery.TestFilter(locations, new[] { "kube-system" }, out var dropped);

        Assert.Equal(new[] { "c/prod/secrets/b", "c/namespace/dev", "c" }, kept);
        Assert.Equal(new[] { "c/kube-system/secrets/a", "c/namespace/kube-system" }, dropped);
    }

    [Fact]
    public void FilterIgnoredNamespaces_IsCaseAndWhitespaceTolerant()
    {
        var kept = TestableDiscovery.TestFilter(
            new[] { "c/kube-system/secrets/a", "c/prod/secrets/b" },
            new[] { "  KUBE-System " }, out var dropped);

        Assert.Equal(new[] { "c/prod/secrets/b" }, kept);
        Assert.Single(dropped);
    }

    [Fact]
    public void FilterIgnoredNamespaces_AppliesToRealK8SNSDiscoveryOutput()
    {
        // K8SNS discovery (#102) emits "<cluster>/namespace/<ns>"; 'Directories to ignore' must drop those.
        var kube = Helpers.MockedKubeClientFactory.Create(
            System.Array.Empty<k8s.Models.V1Secret>(), new[] { "kube-system", "prod", "dev" });
        var handler = new Keyfactor.Extensions.Orchestrator.K8S.Handlers.NamespaceSecretHandler(
            kube.Client, new Moq.Mock<Microsoft.Extensions.Logging.ILogger>().Object,
            new Moq.Mock<Keyfactor.Extensions.Orchestrator.K8S.Handlers.ISecretOperationContext>().Object);

        var discovered = handler.DiscoverStores(null, "all");
        var kept = TestableDiscovery.TestFilter(discovered, new[] { "KUBE-SYSTEM", "dev" }, out var dropped);

        Assert.Equal(new[] { "test-cluster/namespace/prod" }, kept);
        Assert.Equal(2, dropped.Count);
    }

    [Fact]
    public void FilterIgnoredNamespaces_DoesNotMatchPartialNamespaceNames()
    {
        var kept = TestableDiscovery.TestFilter(
            new[] { "c/kube-system-extra/secrets/a", "c/my-kube-system/secrets/b" },
            new[] { "kube-system" }, out var dropped);

        Assert.Equal(2, kept.Count);
        Assert.Empty(dropped);
    }

    [Fact]
    public void FilterIgnoredNamespaces_NoIgnoredNamespaces_ReturnsAll()
    {
        var locations = new[] { "c/a/secrets/x", "c" };
        var kept = TestableDiscovery.TestFilter(locations, System.Array.Empty<string>(), out var dropped);

        Assert.Equal(locations, kept);
        Assert.Empty(dropped);
    }

    [Fact]
    public void FilterIgnoredNamespaces_NullInputs_AreTolerated()
    {
        var kept = TestableDiscovery.TestFilter(null, null, out var dropped);

        Assert.Empty(kept);
        Assert.Empty(dropped);
    }

    [Fact]
    public void FilterIgnoredNamespaces_EverythingIgnored_ReturnsEmpty()
    {
        var kept = TestableDiscovery.TestFilter(new[] { "c/a/secrets/x", "c/a/secrets/y" }, new[] { "a" }, out var dropped);

        Assert.Empty(kept);
        Assert.Equal(2, dropped.Count);
    }

    #endregion
}
