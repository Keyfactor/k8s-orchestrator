// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Newtonsoft.Json;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Clients;

/// <summary>
/// Unit tests for KubeCertificateManagerClient constructor and GetKubeClient paths.
/// These tests exercise GetKubeClient without requiring a live cluster.
/// </summary>
public class KubeCertificateManagerClientTests
{
    #region Kubeconfig Helpers

    private static string BuildKubeconfig(
        string clusterName = "test-cluster",
        string server = "https://127.0.0.1:6443",
        string userName = "test-user",
        string token = "test-token",
        string contextName = "test-context",
        string ns = "default",
        string caData = null)
    {
        var clusterDict = new Dictionary<string, object>
        {
            ["server"] = server
        };
        if (caData != null)
            clusterDict["certificate-authority-data"] = caData;

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
                    ["cluster"] = clusterDict
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

    #endregion

    #region Constructor — happy paths (exercises GetKubeClient main branch)

    [Fact]
    public void Constructor_WithValidTokenKubeconfig_Succeeds()
    {
        var kubeconfig = BuildKubeconfig();

        var client = new KubeCertificateManagerClient(kubeconfig);

        Assert.NotNull(client);
    }

    [Fact]
    public void Constructor_WithUseSSLFalse_Succeeds()
    {
        // useSSL=false → passes skipTlsVerify=true into KubeconfigParser
        var kubeconfig = BuildKubeconfig();

        var client = new KubeCertificateManagerClient(kubeconfig, useSSL: false);

        Assert.NotNull(client);
    }

    [Fact]
    public void Constructor_WithBase64EncodedKubeconfig_Succeeds()
    {
        var json = BuildKubeconfig(clusterName: "b64-cluster");
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

        var client = new KubeCertificateManagerClient(base64);

        Assert.NotNull(client);
    }

    [Fact]
    public void Constructor_WithInvalidCaCertData_FallsBackAndSucceeds()
    {
        // Invalid CA cert triggers catch in GetKubeClient → falls back to BuildDefaultConfig.
        // The test machine has a valid ~/.kube/config so BuildDefaultConfig succeeds.
        var invalidCaData = Convert.ToBase64String(Encoding.UTF8.GetBytes("not-a-certificate"));
        var kubeconfig = BuildKubeconfig(caData: invalidCaData);

        // Should not throw — the fallback path handles the bad CA gracefully
        var client = new KubeCertificateManagerClient(kubeconfig);

        Assert.NotNull(client);
    }

    #endregion

    #region Constructor — error paths

    [Fact]
    public void Constructor_WithNullKubeconfig_Throws()
    {
        Assert.ThrowsAny<Exception>(() => new KubeCertificateManagerClient(null));
    }

    [Fact]
    public void Constructor_WithEmptyKubeconfig_Throws()
    {
        Assert.ThrowsAny<Exception>(() => new KubeCertificateManagerClient(""));
    }

    [Fact]
    public void Constructor_WithNonJsonKubeconfig_Throws()
    {
        Assert.ThrowsAny<Exception>(() => new KubeCertificateManagerClient("not json at all"));
    }

    #endregion

    #region Post-construction accessors

    [Fact]
    public void GetHost_ReturnsServerUrl()
    {
        var kubeconfig = BuildKubeconfig(server: "https://my-api-server:6443");

        var client = new KubeCertificateManagerClient(kubeconfig);

        Assert.Contains("my-api-server", client.GetHost());
    }

    [Fact]
    public void GetClusterName_ReturnsClusterName()
    {
        var kubeconfig = BuildKubeconfig(clusterName: "my-unit-test-cluster");

        var client = new KubeCertificateManagerClient(kubeconfig);

        Assert.Equal("my-unit-test-cluster", client.GetClusterName());
    }

    #endregion
}
