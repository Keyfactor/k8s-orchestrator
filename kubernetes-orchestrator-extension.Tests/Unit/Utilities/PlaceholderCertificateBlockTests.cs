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
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using KeyType = Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper.KeyType;
using SecretInventory = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SSecret.Inventory;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Utilities;

/// <summary>
/// Regression tests for a <c>CERTIFICATE</c> PEM block whose body is well-formed Base-64 but not an X.509 certificate
/// (e.g. the placeholder <c>AAAA</c>, or an empty body). BouncyCastle 2.6.2's <c>X509CertificateParser.ReadCertificate</c>
/// returns null for it instead of throwing; <see cref="CertificateUtilities.LoadCertificateChain"/> used to add that null
/// to the returned list, which later surfaced as a NullReferenceException (chain extractor / inventory) or an
/// ArgumentNullException (thumbprint). Such a block is now skipped.
/// </summary>
public class PlaceholderCertificateBlockTests
{
    private const string Ns = "app-ns";
    private const string Source = "secret 'app' key 'tls.crt' in namespace 'app-ns'";

    private const string PlaceholderPem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
    private const string EmptyBodyPem = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----";
    private const string NotBase64Pem = "-----BEGIN CERTIFICATE-----\nthis is !!! not base64 @@@\n-----END CERTIFICATE-----";

    public static IEnumerable<object[]> PlaceholderBodies()
    {
        yield return new object[] { "placeholder body (AAAA)", PlaceholderPem };
        yield return new object[] { "empty body", EmptyBodyPem };
    }

    private static CertificateTestHelper.CertificateInfo Cert() =>
        CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "placeholder-block");

    private static string CertPem() => CertificateTestHelper.ConvertCertificateToPem(Cert().Certificate);

    private static string KeyPem() => CertificateTestHelper.ConvertPrivateKeyToPem(Cert().KeyPair.Private);

    private static KubeCertificateManagerClient Client() =>
        MockedKubeClientFactory.Create(Array.Empty<V1Secret>()).Client;

    #region CertificateUtilities.LoadCertificateChain

    [Theory]
    [MemberData(nameof(PlaceholderBodies))]
    public void LoadCertificateChain_PlaceholderBlock_ReturnsNoEntries(string description, string pem)
    {
        var result = CertificateUtilities.LoadCertificateChain(pem);

        Assert.Empty(result);
        Assert.DoesNotContain(result, c => c == null);
    }

    [Fact]
    public void LoadCertificateChain_RealCertificatePlusPlaceholder_ReturnsOnlyTheRealCertificate()
    {
        var pem = CertPem() + "\n" + PlaceholderPem + "\n";

        var result = CertificateUtilities.LoadCertificateChain(pem);

        var only = Assert.Single(result);
        Assert.NotNull(only);
        Assert.Equal(CertificateUtilities.GetThumbprint(Cert().Certificate), CertificateUtilities.GetThumbprint(only));
    }

    [Fact]
    public void LoadCertificateChain_PlaceholderBetweenRealCertificates_KeepsBothRealCertificatesInOrder()
    {
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "placeholder-chain");
        var first = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var second = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);

        var result = CertificateUtilities.LoadCertificateChain(first + "\n" + PlaceholderPem + "\n" + second);

        Assert.Equal(2, result.Count);
        Assert.All(result, Assert.NotNull);
        Assert.Equal(CertificateUtilities.GetThumbprint(chain[0].Certificate), CertificateUtilities.GetThumbprint(result[0]));
        Assert.Equal(CertificateUtilities.GetThumbprint(chain[1].Certificate), CertificateUtilities.GetThumbprint(result[1]));
    }

    [Fact]
    public void LoadCertificateChain_BodyThatIsNotBase64_StillThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => CertificateUtilities.LoadCertificateChain(NotBase64Pem));
    }

    #endregion

    #region CertificateChainExtractor.ExtractCertificates

    [Theory]
    [MemberData(nameof(PlaceholderBodies))]
    public void ExtractCertificates_PlaceholderBlock_ReturnsEmpty_WithoutThrowing(string description, string pem)
    {
        var extractor = new CertificateChainExtractor(Client(), new Mock<ILogger>().Object);

        var result = extractor.ExtractCertificates(pem, Source);

        Assert.Empty(result);
    }

    [Fact]
    public void ExtractCertificates_RealCertificatePlusPlaceholder_ReturnsOnlyTheRealCertificate()
    {
        var extractor = new CertificateChainExtractor(Client(), new Mock<ILogger>().Object);

        var result = extractor.ExtractCertificates(CertPem() + "\n" + PlaceholderPem + "\n", Source);

        var pem = Assert.Single(result);
        Assert.Contains("-----BEGIN CERTIFICATE-----", pem);
    }

    #endregion

    #region Inventory

    private static V1Secret Opaque(string name, Dictionary<string, byte[]> data) =>
        MockedKubeClientFactory.Secret(Ns, name, "Opaque", data);

    private static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

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
    [MemberData(nameof(PlaceholderBodies))]
    public void K8SSecret_Inventory_PlaceholderCertificateBlock_ReturnsSuccessWithNoCertificatesMessage(
        string description, string pem)
    {
        var job = new FakeSecretInventory(new[]
        {
            Opaque("placeholder", new Dictionary<string, byte[]> { ["tls.crt"] = Bytes(pem) })
        });
        var submitted = new List<CurrentInventoryItem>();

        var result = job.ProcessJob(Config("placeholder"), items =>
        {
            submitted.AddRange(items);
            return true;
        });

        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"Expected Success but got {result.Result}: {result.FailureMessage}");
        Assert.Contains($"No certificates found in store '{Ns}/placeholder'", result.FailureMessage ?? "",
            StringComparison.OrdinalIgnoreCase);
        Assert.Empty(submitted);
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

    private static MockedKubeClient MixedClient(string placeholderPem) => MockedKubeClientFactory.Create(new[]
    {
        Opaque("placeholder", new Dictionary<string, byte[]> { ["tls.crt"] = Bytes(placeholderPem) }),
        Opaque("good", new Dictionary<string, byte[]> { ["tls.crt"] = Bytes(CertPem()), ["tls.key"] = Bytes(KeyPem()) })
    });

    [Theory]
    [MemberData(nameof(PlaceholderBodies))]
    public void Namespace_Inventory_PlaceholderCertificateBlock_NoErrorAndOtherSecretsStillInventoried(
        string description, string pem)
    {
        var log = new CapturingLogger();
        var handler = new NamespaceSecretHandler(MixedClient(pem).Client, log, Context());

        var entries = handler.GetInventoryEntries(1);

        // A per-secret failure is only logged as "Errors processing N secrets".
        Assert.DoesNotContain(log.Warnings, w => w.Contains("Errors processing"));
        Assert.Contains(entries, e => e.Alias == "opaque/good" && e.Certificates.Count == 1);
        Assert.Contains(entries, e => e.Alias == "opaque/placeholder" && e.Certificates.Count == 0);
    }

    [Theory]
    [MemberData(nameof(PlaceholderBodies))]
    public void Cluster_Inventory_PlaceholderCertificateBlock_NoErrorAndOtherSecretsStillInventoried(
        string description, string pem)
    {
        var log = new CapturingLogger();
        var handler = new ClusterSecretHandler(MixedClient(pem).Client, log, Context());

        var entries = handler.GetInventoryEntries(1);

        Assert.DoesNotContain(log.Warnings, w => w.Contains("Errors processing"));
        Assert.Contains(entries, e => e.Alias == $"{Ns}/secrets/opaque/good" && e.Certificates.Count == 1);
        Assert.Contains(entries, e => e.Alias == $"{Ns}/secrets/opaque/placeholder" && e.Certificates.Count == 0);
    }

    #endregion
}
