// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SCluster;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Moq;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Jobs;

/// <summary>
/// Unit tests for JobBase store properties parsing logic — specifically the
/// SeparateChain / IncludeCertChain conflict resolution that runs before any
/// Kubernetes client is created.
/// </summary>
public class StorePropertiesParsingTests
{
    // Minimal concrete subclass to expose the protected members under test.
    // InitializeStore sets SeparateChain/IncludeCertChain *inside* the first
    // try/catch block (before the Kubernetes client is initialised), so we can
    // read the property values even when the method ultimately throws due to
    // the invalid/fake kubeconfig provided in these tests.
    private sealed class TestableInventory(IPAMSecretResolver resolver) : Inventory(resolver)
    {
        public bool PublicSeparateChain => SeparateChain;
        public bool PublicIncludeCertChain => IncludeCertChain;

        public void PublicInitializeStore(InventoryJobConfiguration config)
            => InitializeStore(config);
    }

    /// <summary>
    /// Builds a minimal InventoryJobConfiguration whose Properties JSON contains
    /// only the supplied chain-related flags.  ServerPassword is set to a
    /// non-empty string so the "no credentials" guard in InitializeProperties
    /// does not fire before we reach the SeparateChain validation logic.
    /// The method will still throw when it tries to build a real KubeClient from
    /// the fake credentials — that is expected and caught by the test.
    /// </summary>
    private static InventoryJobConfiguration BuildConfig(string propertiesJson) =>
        new()
        {
            Capability = "K8STLSSecr",
            CertificateStoreDetails = new CertificateStore
            {
                ClientMachine = "default",
                StorePath = "default/unit-test-secret",
                Properties = propertiesJson
            },
            ServerUsername = string.Empty,
            // Non-empty so KubeSvcCreds passes the null/empty guard.
            // KubeCertificateManagerClient will fail to parse this, which is fine.
            ServerPassword = "{\"fake\":\"kubeconfig\"}",
            UseSSL = true
        };

    private static TestableInventory CreateJob() =>
        new(new Mock<IPAMSecretResolver>().Object);

    // ------------------------------------------------------------------
    // Core customer scenario: SeparateChain=true while IncludeCertChain=false
    // ------------------------------------------------------------------

    [Fact]
    public void InitializeProperties_SeparateChainTrue_IncludeCertChainFalse_OverridesSeparateChainToFalse()
    {
        // Arrange
        var job = CreateJob();
        var config = BuildConfig("{\"SeparateChain\":true,\"IncludeCertChain\":false}");

        // Act — expected to throw when the KubeClient is created with fake creds,
        // but SeparateChain/IncludeCertChain are resolved before that point.
        try { job.PublicInitializeStore(config); } catch { /* expected */ }

        // Assert
        Assert.False(job.PublicSeparateChain,
            "SeparateChain should be overridden to false when IncludeCertChain=false — " +
            "there is no chain to separate");
        Assert.False(job.PublicIncludeCertChain,
            "IncludeCertChain=false should be preserved as specified");
    }

    // ------------------------------------------------------------------
    // Complementary cases to document the full matrix
    // ------------------------------------------------------------------

    [Fact]
    public void InitializeProperties_SeparateChainTrue_IncludeCertChainTrue_BothRemainTrue()
    {
        // Valid config: chain is included AND stored separately in ca.crt
        var job = CreateJob();
        var config = BuildConfig("{\"SeparateChain\":true,\"IncludeCertChain\":true}");

        try { job.PublicInitializeStore(config); } catch { /* expected */ }

        Assert.True(job.PublicSeparateChain,
            "SeparateChain=true should be preserved when IncludeCertChain=true");
        Assert.True(job.PublicIncludeCertChain,
            "IncludeCertChain=true should be preserved as specified");
    }

    [Fact]
    public void InitializeProperties_SeparateChainFalse_IncludeCertChainFalse_BothRemainFalse()
    {
        // Valid config: leaf-only deployment, no chain anywhere
        var job = CreateJob();
        var config = BuildConfig("{\"SeparateChain\":false,\"IncludeCertChain\":false}");

        try { job.PublicInitializeStore(config); } catch { /* expected */ }

        Assert.False(job.PublicSeparateChain,
            "SeparateChain=false should remain false");
        Assert.False(job.PublicIncludeCertChain,
            "IncludeCertChain=false should be preserved as specified");
    }

    [Fact]
    public void InitializeProperties_NeitherFlagSpecified_UsesDefaults()
    {
        // Defaults: SeparateChain=false, IncludeCertChain=true (chain bundled into tls.crt)
        var job = CreateJob();
        var config = BuildConfig("{}");

        try { job.PublicInitializeStore(config); } catch { /* expected */ }

        Assert.False(job.PublicSeparateChain,
            "SeparateChain should default to false");
        Assert.True(job.PublicIncludeCertChain,
            "IncludeCertChain should default to true");
    }
}
