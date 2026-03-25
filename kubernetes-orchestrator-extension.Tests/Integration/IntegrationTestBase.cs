// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using k8s;
using k8s.Models;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.Orchestrators.K8S.Tests.Integration.Fixtures;
using Moq;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration;

/// <summary>
/// Abstract base class for integration tests. Provides common setup/teardown logic
/// including namespace creation, secret tracking, and cleanup.
/// </summary>
public abstract class IntegrationTestBase : IAsyncLifetime
{
    /// <summary>
    /// Standard label used to identify secrets created by integration tests.
    /// </summary>
    protected const string TestManagedByLabel = "keyfactor-integration-tests";

    /// <summary>
    /// Label key for the managed-by label.
    /// </summary>
    protected const string ManagedByLabelKey = "app.kubernetes.io/managed-by";

    /// <summary>
    /// Label key for the test run ID.
    /// </summary>
    protected const string TestRunIdLabelKey = "keyfactor.com/test-run-id";

    protected readonly IntegrationTestFixture Fixture;
    protected Kubernetes K8sClient = null!;
    protected string KubeconfigJson = string.Empty;
    protected Mock<IPAMSecretResolver> MockPamResolver = null!;
    protected readonly List<string> CreatedSecrets = new();

    /// <summary>
    /// Unique ID for this test run, used for targeted cleanup.
    /// </summary>
    protected readonly string TestRunId = Guid.NewGuid().ToString("N")[..8];

    /// <summary>
    /// The .NET framework suffix for namespace isolation between parallel framework runs.
    /// Example: "net8" or "net10"
    /// </summary>
    protected static readonly string FrameworkSuffix = $"net{Environment.Version.Major}";

    /// <summary>
    /// The base Kubernetes namespace for this test class (without framework suffix).
    /// Each test class should return a unique base namespace.
    /// </summary>
    protected abstract string BaseTestNamespace { get; }

    /// <summary>
    /// The full Kubernetes namespace including framework suffix for test isolation.
    /// This ensures net8.0 and net10.0 tests don't interfere when running in parallel.
    /// </summary>
    protected virtual string TestNamespace => $"{BaseTestNamespace}-{FrameworkSuffix}";

    protected IntegrationTestBase(IntegrationTestFixture fixture)
    {
        Fixture = fixture;
    }

    public virtual async Task InitializeAsync()
    {
        if (!Fixture.IsEnabled)
        {
            return;
        }

        // Get kubeconfig JSON for this test's namespace
        KubeconfigJson = Fixture.GetKubeconfigJsonForNamespace(TestNamespace);

        // Create K8S client
        K8sClient = Fixture.CreateK8sClient();

        // Create mock PAM resolver
        MockPamResolver = Fixture.CreateMockPamResolver();

        // Create test namespace if it doesn't exist
        await CreateNamespaceIfNotExistsAsync();
    }

    public virtual async Task DisposeAsync()
    {
        if (!Fixture.IsEnabled)
        {
            return;
        }

        if (!Fixture.SkipCleanup)
        {
            await CleanupTestSecretsAsync();
        }

        K8sClient?.Dispose();
    }

    /// <summary>
    /// Cleans up test secrets using batch delete with label selectors.
    /// Falls back to individual deletion if batch delete fails.
    /// </summary>
    private async Task CleanupTestSecretsAsync()
    {
        try
        {
            // Try batch delete using label selector for this test run
            var labelSelector = $"{ManagedByLabelKey}={TestManagedByLabel},{TestRunIdLabelKey}={TestRunId}";

            await K8sClient.CoreV1.DeleteCollectionNamespacedSecretAsync(
                TestNamespace,
                labelSelector: labelSelector);
        }
        catch (Exception)
        {
            // Fall back to individual deletion if batch delete fails
            // (e.g., if K8s version doesn't support DeleteCollection well)
            foreach (var secretName in CreatedSecrets)
            {
                try
                {
                    await K8sClient.CoreV1.DeleteNamespacedSecretAsync(secretName, TestNamespace);
                }
                catch (Exception)
                {
                    // Ignore cleanup errors
                }
            }
        }
    }

    /// <summary>
    /// Creates the test namespace if it doesn't already exist.
    /// </summary>
    protected async Task CreateNamespaceIfNotExistsAsync()
    {
        try
        {
            await K8sClient.CoreV1.ReadNamespaceAsync(TestNamespace);
        }
        catch (k8s.Autorest.HttpOperationException ex) when (ex.Response.StatusCode == HttpStatusCode.NotFound)
        {
            var ns = new V1Namespace
            {
                Metadata = new V1ObjectMeta
                {
                    Name = TestNamespace,
                    Labels = new Dictionary<string, string>
                    {
                        { "purpose", "integration-tests" },
                        { "managed-by", "keyfactor-k8s-orchestrator-tests" }
                    }
                }
            };
            await K8sClient.CoreV1.CreateNamespaceAsync(ns);
        }
    }

    /// <summary>
    /// Tracks a secret name for cleanup during test disposal.
    /// </summary>
    protected void TrackSecret(string secretName)
    {
        CreatedSecrets.Add(secretName);
    }

    /// <summary>
    /// Gets standard labels for test-created secrets.
    /// These labels enable batch cleanup via label selectors.
    /// </summary>
    /// <returns>Dictionary of labels to apply to test secrets</returns>
    protected Dictionary<string, string> GetTestSecretLabels()
    {
        return new Dictionary<string, string>
        {
            { ManagedByLabelKey, TestManagedByLabel },
            { TestRunIdLabelKey, TestRunId }
        };
    }

    /// <summary>
    /// Creates a V1ObjectMeta with standard test labels already applied.
    /// </summary>
    /// <param name="name">The secret name</param>
    /// <param name="additionalLabels">Optional additional labels to merge</param>
    /// <returns>V1ObjectMeta with labels configured</returns>
    protected V1ObjectMeta CreateTestSecretMetadata(string name, Dictionary<string, string>? additionalLabels = null)
    {
        var labels = GetTestSecretLabels();
        if (additionalLabels != null)
        {
            foreach (var kvp in additionalLabels)
            {
                labels[kvp.Key] = kvp.Value;
            }
        }

        return new V1ObjectMeta
        {
            Name = name,
            NamespaceProperty = TestNamespace,
            Labels = labels
        };
    }
}
