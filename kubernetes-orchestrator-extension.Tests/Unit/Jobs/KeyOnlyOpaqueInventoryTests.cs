// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using SecretInventory = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SSecret.Inventory;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Jobs;

/// <summary>
/// Regression tests: an Opaque secret that holds only a private key (no certificate) must inventory as
/// "no certificates" (Success), not fail with "The input is not a valid Base-64 string...". 1.3.0 behaved this way;
/// 2.0.0 regressed because the DER fallback in <see cref="CertificateChainExtractor"/> let
/// <c>Convert.FromBase64String</c> throw on PEM key text.
/// </summary>
public class KeyOnlyOpaqueInventoryTests
{
    private const string Ns = "app-ns";

    private static CertificateTestHelper.CertificateInfo Cert() =>
        CachedCertificateProvider.GetOrCreate(CertificateTestHelper.KeyType.Rsa2048, "key-only-inventory");

    private static byte[] KeyPem() => Encoding.UTF8.GetBytes(
        CertificateTestHelper.ConvertPrivateKeyToPem(Cert().KeyPair.Private));

    private static byte[] CertPem() => Encoding.UTF8.GetBytes(
        CertificateTestHelper.ConvertCertificateToPem(Cert().Certificate));

    private static V1Secret Opaque(string name, Dictionary<string, byte[]> data) =>
        MockedKubeClientFactory.Secret(Ns, name, "Opaque", data);

    /// <summary>Real K8SSecret inventory job whose Kubernetes API is an in-memory fake.</summary>
    private sealed class FakeSecretInventory : SecretInventory
    {
        private readonly IEnumerable<V1Secret> _secrets;

        public FakeSecretInventory(IEnumerable<V1Secret> secrets) : base(new Mock<IPAMSecretResolver>().Object)
        {
            _secrets = secrets;
            Logger = new Mock<ILogger>().Object;
        }

        protected override List<InventoryEntry> GetInventoryEntries(long jobId)
        {
            MockedKubeClientFactory.Attach(KubeClient, _secrets);
            return base.GetInventoryEntries(jobId);
        }
    }

    private static InventoryJobConfiguration Config(string secretName) => new()
    {
        Capability = "K8SSecret",
        JobHistoryId = 7,
        CertificateStoreDetails = new CertificateStore
        {
            ClientMachine = "lab-cluster",
            StorePath = $"{Ns}/{secretName}",
            Properties = "{\"KubeSecretType\":\"secret\"}"
        },
        ServerUsername = string.Empty,
        ServerPassword = MockedKubeClientFactory.BuildKubeconfig(),
        UseSSL = true
    };

    [Theory]
    [InlineData("tls.key")]
    [InlineData("key")]
    [InlineData("private-key")]
    [InlineData("key.pem")]
    public void K8SSecret_Inventory_KeyOnlySecret_ReturnsSuccessWithNoCertificatesMessage(string keyField)
    {
        var job = new FakeSecretInventory(new[] { Opaque("key-only", new Dictionary<string, byte[]> { [keyField] = KeyPem() }) });
        var submitted = new List<CurrentInventoryItem>();

        var result = job.ProcessJob(Config("key-only"), items =>
        {
            submitted.AddRange(items);
            return true;
        });

        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}: {result.FailureMessage}");
        Assert.Contains("No certificates found", result.FailureMessage ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Empty(submitted);
    }

    [Fact]
    public void K8SSecret_Inventory_GarbageUnderCertKey_IsSkippedNotFailed()
    {
        var job = new FakeSecretInventory(new[]
        {
            Opaque("garbage", new Dictionary<string, byte[]> { ["tls.crt"] = Encoding.UTF8.GetBytes("this is !!! not a certificate @@@") })
        });

        var result = job.ProcessJob(Config("garbage"), _ => true);

        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}: {result.FailureMessage}");
        Assert.Contains("No certificates found", result.FailureMessage ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void K8SSecret_Inventory_CertAndKey_StillInventoriesCertificate()
    {
        var job = new FakeSecretInventory(new[]
        {
            Opaque("full", new Dictionary<string, byte[]> { ["tls.crt"] = CertPem(), ["tls.key"] = KeyPem() })
        });
        var submitted = new List<CurrentInventoryItem>();

        var result = job.ProcessJob(Config("full"), items =>
        {
            submitted.AddRange(items);
            return true;
        });

        Assert.Equal(OrchestratorJobStatusJobResult.Success, result.Result);
        Assert.Single(submitted);
        Assert.True(submitted[0].PrivateKeyEntry);
        Assert.DoesNotContain("No certificates found", result.FailureMessage ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExtractCertificates_PemPrivateKeyText_ReturnsEmptyAndDoesNotThrow()
    {
        var extractor = new CertificateChainExtractor(MockedKubeClientFactory.Create(Array.Empty<V1Secret>()).Client);

        var result = extractor.ExtractCertificates(Encoding.UTF8.GetString(KeyPem()), "key 'tls.key'");

        Assert.Empty(result);
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<string> Warnings { get; } = new();
        public IDisposable BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
            Func<TState, Exception, string> formatter)
        {
            if (logLevel >= LogLevel.Warning) Warnings.Add(formatter(state, exception));
        }
    }

    private static ISecretOperationContext Context()
    {
        var mock = new Mock<ISecretOperationContext>();
        mock.Setup(c => c.KubeNamespace).Returns(Ns);
        mock.Setup(c => c.KubeSecretName).Returns(string.Empty);
        mock.Setup(c => c.StorePath).Returns(Ns);
        mock.Setup(c => c.StorePassword).Returns(string.Empty);
        mock.Setup(c => c.PasswordSecretPath).Returns(string.Empty);
        mock.Setup(c => c.PasswordFieldName).Returns(string.Empty);
        mock.Setup(c => c.SeparateChain).Returns(false);
        mock.Setup(c => c.IncludeCertChain).Returns(false);
        mock.Setup(c => c.CertificateDataFieldName).Returns(string.Empty);
        return mock.Object;
    }

    private static MockedKubeClient MixedClient() => MockedKubeClientFactory.Create(new[]
    {
        Opaque("key-only", new Dictionary<string, byte[]> { ["tls.key"] = KeyPem() }),
        Opaque("good", new Dictionary<string, byte[]> { ["tls.crt"] = CertPem(), ["tls.key"] = KeyPem() })
    });

    [Fact]
    public void Namespace_Inventory_KeyOnlySecret_NoErrorAndOtherSecretsStillInventoried()
    {
        var log = new CapturingLogger();
        var handler = new NamespaceSecretHandler(MixedClient().Client, log, Context());

        var entries = handler.GetInventoryEntries(1);

        // A per-secret failure is only logged as "Errors processing N secrets"; a key-only secret must not cause one.
        Assert.DoesNotContain(log.Warnings, w => w.Contains("Errors processing"));

        Assert.Contains(entries, e => e.Alias == "opaque/good" && e.Certificates.Count == 1);
        Assert.Contains(entries, e => e.Alias == "opaque/key-only" && e.Certificates.Count == 0);
    }

    [Fact]
    public void Cluster_Inventory_KeyOnlySecret_NoErrorAndOtherSecretsStillInventoried()
    {
        var log = new CapturingLogger();
        var handler = new ClusterSecretHandler(MixedClient().Client, log, Context());

        var entries = handler.GetInventoryEntries(1);

        // A per-secret failure is only logged as "Errors processing N secrets"; a key-only secret must not cause one.
        Assert.DoesNotContain(log.Warnings, w => w.Contains("Errors processing"));

        Assert.Contains(entries, e => e.Alias == $"{Ns}/secrets/opaque/good" && e.Certificates.Count == 1);
        Assert.Contains(entries, e => e.Alias == $"{Ns}/secrets/opaque/key-only" && e.Certificates.Count == 0);
    }

    // A secret with no data at all (kubectl create secret generic x, or every field removed) is listed with Data == null.
    // K8SCluster/K8SNS inventory visits every Opaque secret, so this is ordinary there and must not be a Warning.
    public static IEnumerable<object[]> NoDataValues()
    {
        yield return new object[] { null };
        yield return new object[] { new Dictionary<string, byte[]>() };
    }

    private static MockedKubeClient NoDataClient(Dictionary<string, byte[]> data) => MockedKubeClientFactory.Create(new[]
    {
        Opaque("empty", data),
        Opaque("good", new Dictionary<string, byte[]> { ["tls.crt"] = CertPem(), ["tls.key"] = KeyPem() })
    });

    [Theory]
    [MemberData(nameof(NoDataValues))]
    public void Namespace_Inventory_SecretWithNoData_LogsNoWarning_AndOtherSecretsStillInventoried(
        Dictionary<string, byte[]> data)
    {
        var log = new CapturingLogger();
        var handler = new NamespaceSecretHandler(NoDataClient(data).Client, log, Context());

        var entries = handler.GetInventoryEntries(1);

        Assert.Empty(log.Warnings);
        Assert.Contains(entries, e => e.Alias == "opaque/empty" && e.Certificates.Count == 0);
        Assert.Contains(entries, e => e.Alias == "opaque/good" && e.Certificates.Count == 1);
    }

    [Theory]
    [MemberData(nameof(NoDataValues))]
    public void Cluster_Inventory_SecretWithNoData_LogsNoWarning_AndOtherSecretsStillInventoried(
        Dictionary<string, byte[]> data)
    {
        var log = new CapturingLogger();
        var handler = new ClusterSecretHandler(NoDataClient(data).Client, log, Context());

        var entries = handler.GetInventoryEntries(1);

        Assert.Empty(log.Warnings);
        Assert.Contains(entries, e => e.Alias == $"{Ns}/secrets/opaque/empty" && e.Certificates.Count == 0);
        Assert.Contains(entries, e => e.Alias == $"{Ns}/secrets/opaque/good" && e.Certificates.Count == 1);
    }

    /// <summary>
    /// The operator-facing signal for a single configured store is the job result, not a log Warning: an empty K8SSecret
    /// store still reports "No certificates found in store '&lt;path&gt;'" (as Success), so lowering the log level of
    /// "Secret has no data" does not hide anything from the operator.
    /// </summary>
    [Theory]
    [MemberData(nameof(NoDataValues))]
    public void K8SSecret_Inventory_SecretWithNoData_ReturnsSuccessWithNoCertificatesMessage(
        Dictionary<string, byte[]> data)
    {
        var job = new FakeSecretInventory(new[] { Opaque("empty", data) });
        var submitted = new List<CurrentInventoryItem>();

        var result = job.ProcessJob(Config("empty"), items =>
        {
            submitted.AddRange(items);
            return true;
        });

        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}: {result.FailureMessage}");
        Assert.Contains($"No certificates found in store '{Ns}/empty'", result.FailureMessage ?? "",
            StringComparison.OrdinalIgnoreCase);
        Assert.Empty(submitted);
    }
}
