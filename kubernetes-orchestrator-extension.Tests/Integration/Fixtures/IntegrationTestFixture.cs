// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using k8s;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Moq;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration.Fixtures;

/// <summary>
/// Shared fixture for integration tests. Provides kubeconfig loading and K8S client creation.
/// This fixture is initialized once per test collection, reducing duplication across test classes.
/// </summary>
public class IntegrationTestFixture : IAsyncLifetime
{
    /// <summary>
    /// The kubeconfig JSON string used for Kubernetes authentication.
    /// </summary>
    public string KubeconfigJson { get; private set; } = string.Empty;

    /// <summary>
    /// Whether integration tests are enabled (RUN_INTEGRATION_TESTS=true).
    /// </summary>
    public bool IsEnabled { get; private set; }

    /// <summary>
    /// Whether to skip cleanup of test resources (SKIP_INTEGRATION_TEST_CLEANUP=true).
    /// </summary>
    public bool SkipCleanup { get; private set; }

    /// <summary>
    /// Path to the kubeconfig file.
    /// </summary>
    public string KubeconfigPath { get; private set; } = string.Empty;

    /// <summary>
    /// The Kubernetes context to use.
    /// </summary>
    public string ClusterContext { get; private set; } = string.Empty;

    public Task InitializeAsync()
    {
        // Check if integration tests are enabled
        var runIntegrationTests = Environment.GetEnvironmentVariable("RUN_INTEGRATION_TESTS");
        IsEnabled = !string.IsNullOrEmpty(runIntegrationTests) &&
                    runIntegrationTests.Equals("true", StringComparison.OrdinalIgnoreCase);

        if (!IsEnabled)
        {
            return Task.CompletedTask;
        }

        // Check cleanup setting
        var skipCleanup = Environment.GetEnvironmentVariable("SKIP_INTEGRATION_TEST_CLEANUP");
        SkipCleanup = !string.IsNullOrEmpty(skipCleanup) &&
                      skipCleanup.Equals("true", StringComparison.OrdinalIgnoreCase);

        // Load kubeconfig path and context
        KubeconfigPath = (Environment.GetEnvironmentVariable("INTEGRATION_TEST_KUBECONFIG") ?? "~/.kube/config")
            .Replace("~", Environment.GetEnvironmentVariable("HOME") ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        ClusterContext = Environment.GetEnvironmentVariable("INTEGRATION_TEST_CONTEXT") ?? "kf-integrations";

        if (!File.Exists(KubeconfigPath))
        {
            throw new FileNotFoundException($"Kubeconfig not found at {KubeconfigPath}");
        }

        // Load and convert kubeconfig to JSON
        var kubeconfigContent = File.ReadAllText(KubeconfigPath);
        KubeconfigJson = ConvertKubeconfigToJson(kubeconfigContent);

        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        // No shared resources to dispose
        return Task.CompletedTask;
    }

    /// <summary>
    /// Creates a new Kubernetes client configured with the loaded kubeconfig.
    /// </summary>
    public Kubernetes CreateK8sClient()
    {
        if (!IsEnabled)
        {
            throw new InvalidOperationException("Integration tests are not enabled");
        }

        var config = KubernetesClientConfiguration.BuildConfigFromConfigFile(
            KubeconfigPath,
            currentContext: ClusterContext);
        config.HttpClientTimeout = TimeSpan.FromMinutes(5);
        return new Kubernetes(config);
    }

    /// <summary>
    /// Creates a mock PAM secret resolver that returns null for all password lookups.
    /// </summary>
    public Mock<IPAMSecretResolver> CreateMockPamResolver()
    {
        var mockPamResolver = new Mock<IPAMSecretResolver>();
        mockPamResolver.Setup(x => x.Resolve(It.IsAny<string>())).Returns((string)null!);
        return mockPamResolver;
    }

    /// <summary>
    /// Gets the kubeconfig JSON with the namespace field set to the specified namespace.
    /// </summary>
    public string GetKubeconfigJsonForNamespace(string targetNamespace)
    {
        if (!IsEnabled || string.IsNullOrEmpty(KubeconfigJson))
        {
            return string.Empty;
        }

        // Parse and modify the kubeconfig to use the specified namespace
        var kubeconfigPath = KubeconfigPath;
        var fileContent = File.ReadAllText(kubeconfigPath);

        // Detect if the file is already JSON
        if (fileContent.TrimStart().StartsWith("{"))
        {
            return fileContent;
        }

        // Rebuild with the specified namespace
        var config = KubernetesClientConfiguration.BuildConfigFromConfigFile(
            kubeconfigPath,
            currentContext: ClusterContext);

        var kubeconfigObj = new Dictionary<string, object>
        {
            ["kind"] = "Config",
            ["apiVersion"] = "v1",
            ["current-context"] = ClusterContext,
            ["clusters"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = ClusterContext,
                    ["cluster"] = new Dictionary<string, object>
                    {
                        ["server"] = config.Host,
                        ["certificate-authority-data"] = config.SslCaCerts?.Any() == true
                            ? Convert.ToBase64String(config.SslCaCerts.First().Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert))
                            : null!
                    }
                }
            },
            ["users"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = ClusterContext,
                    ["user"] = new Dictionary<string, object>
                    {
                        ["token"] = config.AccessToken!,
                        ["client-certificate-data"] = config.ClientCertificateData!,
                        ["client-key-data"] = config.ClientCertificateKeyData!
                    }
                }
            },
            ["contexts"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = ClusterContext,
                    ["context"] = new Dictionary<string, object>
                    {
                        ["cluster"] = ClusterContext,
                        ["user"] = ClusterContext,
                        ["namespace"] = targetNamespace
                    }
                }
            }
        };

        return JsonSerializer.Serialize(kubeconfigObj);
    }

    private string ConvertKubeconfigToJson(string kubeconfigContent)
    {
        var fileContent = File.ReadAllText(KubeconfigPath);

        // Detect if the file is already JSON (starts with '{')
        if (fileContent.TrimStart().StartsWith("{"))
        {
            return fileContent;
        }

        // File is YAML, convert using KubernetesClientConfiguration
        var config = KubernetesClientConfiguration.BuildConfigFromConfigFile(
            KubeconfigPath,
            currentContext: ClusterContext);

        var kubeconfigObj = new Dictionary<string, object>
        {
            ["kind"] = "Config",
            ["apiVersion"] = "v1",
            ["current-context"] = ClusterContext,
            ["clusters"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = ClusterContext,
                    ["cluster"] = new Dictionary<string, object>
                    {
                        ["server"] = config.Host,
                        ["certificate-authority-data"] = config.SslCaCerts?.Any() == true
                            ? Convert.ToBase64String(config.SslCaCerts.First().Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert))
                            : null!
                    }
                }
            },
            ["users"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = ClusterContext,
                    ["user"] = new Dictionary<string, object>
                    {
                        ["token"] = config.AccessToken!,
                        ["client-certificate-data"] = config.ClientCertificateData!,
                        ["client-key-data"] = config.ClientCertificateKeyData!
                    }
                }
            },
            ["contexts"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = ClusterContext,
                    ["context"] = new Dictionary<string, object>
                    {
                        ["cluster"] = ClusterContext,
                        ["user"] = ClusterContext,
                        ["namespace"] = "default"
                    }
                }
            }
        };

        return JsonSerializer.Serialize(kubeconfigObj);
    }
}
