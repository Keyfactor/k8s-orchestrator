// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Linq;
using System.Text;
using k8s.Exceptions;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Newtonsoft.Json;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Clients;

public class KubeconfigParserTests
{
    private readonly KubeconfigParser _parser = new();

    private static string CreateMinimalKubeconfig(
        string clusterName = "test-cluster",
        string server = "https://127.0.0.1:6443",
        string userName = "test-user",
        string token = "test-token",
        string contextName = "test-context",
        string ns = "default")
    {
        // Build kubeconfig JSON manually to match exact key names expected by the parser
        var config = new Dictionary<string, object>
        {
            ["apiVersion"] = "v1",
            ["kind"] = "Config",
            ["current-context"] = contextName,
            ["clusters"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = clusterName,
                    ["cluster"] = new Dictionary<string, object>
                    {
                        ["server"] = server
                    }
                }
            },
            ["users"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = userName,
                    ["user"] = new Dictionary<string, object>
                    {
                        ["token"] = token
                    }
                }
            },
            ["contexts"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = contextName,
                    ["context"] = new Dictionary<string, object>
                    {
                        ["cluster"] = clusterName,
                        ["user"] = userName,
                        ["namespace"] = ns
                    }
                }
            }
        };
        return JsonConvert.SerializeObject(config);
    }

    [Fact]
    public void Parse_NullInput_ThrowsKubeConfigException()
    {
        Assert.Throws<KubeConfigException>(() => _parser.Parse(null));
    }

    [Fact]
    public void Parse_EmptyInput_ThrowsKubeConfigException()
    {
        Assert.Throws<KubeConfigException>(() => _parser.Parse(""));
    }

    [Fact]
    public void Parse_NonJsonInput_ThrowsKubeConfigException()
    {
        Assert.Throws<KubeConfigException>(() => _parser.Parse("this is not json"));
    }

    [Fact]
    public void Parse_ValidJson_ReturnsConfiguration()
    {
        var kubeconfig = CreateMinimalKubeconfig();

        var config = _parser.Parse(kubeconfig);

        Assert.NotNull(config);
        Assert.Equal("v1", config.ApiVersion);
        Assert.Equal("Config", config.Kind);
        Assert.Equal("test-context", config.CurrentContext);
    }

    [Fact]
    public void Parse_ParsesClusters()
    {
        var kubeconfig = CreateMinimalKubeconfig(server: "https://my-server:6443");

        var config = _parser.Parse(kubeconfig);

        Assert.Single(config.Clusters);
        Assert.Equal("test-cluster", config.Clusters.First().Name);
        Assert.Equal("https://my-server:6443", config.Clusters.First().ClusterEndpoint.Server);
    }

    [Fact]
    public void Parse_ParsesUsers()
    {
        var kubeconfig = CreateMinimalKubeconfig(token: "my-secret-token");

        var config = _parser.Parse(kubeconfig);

        Assert.Single(config.Users);
        Assert.Equal("test-user", config.Users.First().Name);
        Assert.Equal("my-secret-token", config.Users.First().UserCredentials.Token);
    }

    [Fact]
    public void Parse_ParsesContexts()
    {
        var kubeconfig = CreateMinimalKubeconfig(contextName: "my-context", ns: "my-ns");

        var config = _parser.Parse(kubeconfig);

        Assert.Single(config.Contexts);
        Assert.Equal("my-context", config.Contexts.First().Name);
        Assert.Equal("my-ns", config.Contexts.First().ContextDetails.Namespace);
        Assert.Equal("test-cluster", config.Contexts.First().ContextDetails.Cluster);
        Assert.Equal("test-user", config.Contexts.First().ContextDetails.User);
    }

    [Fact]
    public void Parse_WithSkipTlsVerify_SetsFlagOnClusters()
    {
        var kubeconfig = CreateMinimalKubeconfig();

        var config = _parser.Parse(kubeconfig, skipTlsVerify: true);

        Assert.True(config.Clusters.First().ClusterEndpoint.SkipTlsVerify);
    }

    [Fact]
    public void Parse_Base64EncodedInput_DecodesAndParses()
    {
        var kubeconfig = CreateMinimalKubeconfig();
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(kubeconfig));

        var config = _parser.Parse(base64);

        Assert.NotNull(config);
        Assert.Equal("v1", config.ApiVersion);
    }

    [Fact]
    public void Parse_EscapedJsonInput_NormalizesAndParses()
    {
        var kubeconfig = CreateMinimalKubeconfig();
        // Simulate escaped JSON (backslash-prefixed)
        var escaped = "\\" + kubeconfig.Replace("\"", "\\\"");

        var config = _parser.Parse(escaped);

        Assert.NotNull(config);
        Assert.Equal("v1", config.ApiVersion);
    }

    [Fact]
    public void Parse_EnvVarTlsOverride_SetsSkipTlsVerify()
    {
        var kubeconfig = CreateMinimalKubeconfig();

        try
        {
            Environment.SetEnvironmentVariable(KubeconfigParser.SkipTlsVerifyEnvVar, "true");

            var config = _parser.Parse(kubeconfig, skipTlsVerify: false);

            Assert.True(config.Clusters.First().ClusterEndpoint.SkipTlsVerify);
        }
        finally
        {
            Environment.SetEnvironmentVariable(KubeconfigParser.SkipTlsVerifyEnvVar, null);
        }
    }

    [Fact]
    public void Parse_EnvVarTlsOverride_NumericOne_SetsSkipTlsVerify()
    {
        var kubeconfig = CreateMinimalKubeconfig();

        try
        {
            Environment.SetEnvironmentVariable(KubeconfigParser.SkipTlsVerifyEnvVar, "1");

            var config = _parser.Parse(kubeconfig, skipTlsVerify: false);

            Assert.True(config.Clusters.First().ClusterEndpoint.SkipTlsVerify);
        }
        finally
        {
            Environment.SetEnvironmentVariable(KubeconfigParser.SkipTlsVerifyEnvVar, null);
        }
    }

    [Fact]
    public void Parse_EnvVarTlsFalse_DoesNotOverride()
    {
        var kubeconfig = CreateMinimalKubeconfig();

        try
        {
            Environment.SetEnvironmentVariable(KubeconfigParser.SkipTlsVerifyEnvVar, "false");

            var config = _parser.Parse(kubeconfig, skipTlsVerify: false);

            Assert.False(config.Clusters.First().ClusterEndpoint.SkipTlsVerify);
        }
        finally
        {
            Environment.SetEnvironmentVariable(KubeconfigParser.SkipTlsVerifyEnvVar, null);
        }
    }
}
