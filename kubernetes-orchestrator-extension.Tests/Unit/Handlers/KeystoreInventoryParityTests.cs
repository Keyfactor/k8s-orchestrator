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
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Microsoft.Extensions.Logging;
using Moq;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;
using KeyType = Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper.KeyType;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Handlers;

/// <summary>
/// Triage tests for two suspected JKS/PKCS12 inventory regressions of 2.0 versus 1.3.0:
/// (1) HasPrivateKey is hard-coded true for every alias, (2) 1.3.0 skipped chain-certificate aliases.
/// Expectations are what 1.3.0 reported (verified by running the real 1.3.0 HandleJKSSecret/HandlePkcs12Secret/PushInventory against the same keystores),
/// EXCEPT for two deliberate 2.0.2 corrections of defects 1.3.0 already had: (1) PrivateKeyEntry is true only for key
/// entries, (2) JKS trusted-certificate-only aliases are inventoried (as PKCS12 already did) instead of being dropped.
/// </summary>
public class KeystoreInventoryParityTests
{
    private const string Ns = "ks-parity";
    private const string Pw = "storepw";
    private const string JksField = "keystore.jks";
    private const string P12Field = "keystore.p12";

    private static ISecretOperationContext Context(string name)
    {
        var mock = new Mock<ISecretOperationContext>();
        mock.Setup(c => c.KubeNamespace).Returns(Ns);
        mock.Setup(c => c.KubeSecretName).Returns(name);
        mock.Setup(c => c.StorePath).Returns($"{Ns}/{name}");
        mock.Setup(c => c.StorePassword).Returns(Pw);
        mock.Setup(c => c.PasswordSecretPath).Returns(string.Empty);
        mock.Setup(c => c.PasswordFieldName).Returns(string.Empty);
        mock.Setup(c => c.IncludeCertChain).Returns(true);
        mock.Setup(c => c.CertificateDataFieldName).Returns(string.Empty);
        return mock.Object;
    }

    private static List<InventoryEntry> InventoryJks(byte[] jks, string field = JksField)
    {
        var kube = MockedKubeClientFactory.Create(new[]
        {
            MockedKubeClientFactory.Secret(Ns, "ks", "Opaque", new Dictionary<string, byte[]> { [field] = jks })
        });
        return new JksSecretHandler(kube.Client, new Mock<ILogger>().Object, Context("ks")).GetInventoryEntries(1);
    }

    private static List<InventoryEntry> InventoryP12(byte[] p12)
    {
        var kube = MockedKubeClientFactory.Create(new[]
        {
            MockedKubeClientFactory.Secret(Ns, "ks", "Opaque", new Dictionary<string, byte[]> { [P12Field] = p12 })
        });
        return new Pkcs12SecretHandler(kube.Client, new Mock<ILogger>().Object, Context("ks")).GetInventoryEntries(1);
    }

    // leaf, intermediate, root (index 0..2) from the cached chain, plus an unrelated trust anchor
    private static (List<CertificateTestHelper.CertificateInfo> chain, X509Certificate trust) Material() =>
        (CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "ks-parity-leaf"),
            CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "ks-parity-trust").Certificate);

    private static byte[] Jks(Action<JksStore, List<CertificateTestHelper.CertificateInfo>, X509Certificate> fill)
    {
        var (chain, trust) = Material();
        var s = new JksStore();
        fill(s, chain, trust);
        using var ms = new MemoryStream();
        s.Save(ms, Pw.ToCharArray());
        return ms.ToArray();
    }

    private static byte[] P12(Action<Pkcs12Store, List<CertificateTestHelper.CertificateInfo>, X509Certificate> fill)
    {
        var (chain, trust) = Material();
        var s = new Pkcs12StoreBuilder().Build();
        fill(s, chain, trust);
        using var ms = new MemoryStream();
        s.Save(ms, Pw.ToCharArray(), new SecureRandom());
        return ms.ToArray();
    }

    private static void JksKey(JksStore s, string alias, List<CertificateTestHelper.CertificateInfo> c) =>
        s.SetKeyEntry(alias, c[0].KeyPair.Private, Pw.ToCharArray(), new[] { c[0].Certificate, c[1].Certificate });

    private static void P12Key(Pkcs12Store s, string alias, List<CertificateTestHelper.CertificateInfo> c) =>
        s.SetKeyEntry(alias, new AsymmetricKeyEntry(c[0].KeyPair.Private),
            new[] { new X509CertificateEntry(c[0].Certificate), new X509CertificateEntry(c[1].Certificate) });

    private static string[] Aliases(List<InventoryEntry> e) => e.Select(x => x.Alias).OrderBy(a => a).ToArray();

    // ───────────────────────── JKS ─────────────────────────

    [Fact]
    public void Jks_Control_SingleKeyEntry_ReportsOneAliasWithKey()
    {
        var e = Assert.Single(InventoryJks(Jks((s, c, _) => JksKey(s, "mykey", c))));
        Assert.Equal($"{JksField}/mykey", e.Alias);
        Assert.Equal(2, e.Certificates.Count);
        Assert.True(e.HasPrivateKey);
    }

    [Fact]
    public void Jks_KeyEntryWithChainPlusTrustOnly_ReportsBothWithCorrectKeyFlags()
    {
        // CHANGED vs 1.3.0 (which dropped the trusted-cert alias): trust-only alias is now inventoried, single cert, no key.
        var entries = InventoryJks(Jks((s, c, t) =>
        {
            JksKey(s, "mykey", c);
            s.SetCertificateEntry("trustca", t);
        }));
        Assert.Equal(new[] { $"{JksField}/mykey", $"{JksField}/trustca" }, Aliases(entries));
        var key = entries.Single(x => x.Alias.EndsWith("/mykey"));
        var trust = entries.Single(x => x.Alias.EndsWith("/trustca"));
        Assert.True(key.HasPrivateKey);
        Assert.Equal(2, key.Certificates.Count);
        Assert.False(trust.HasPrivateKey);
        Assert.Single(trust.Certificates);
    }

    [Fact]
    public void Jks_TrustOnlyKeystore_ReportsTrustedCertWithoutKey()
    {
        // CHANGED vs 1.3.0 (empty inventory): a truststore with only trusted CAs is no longer empty.
        var e = Assert.Single(InventoryJks(Jks((s, _, t) => s.SetCertificateEntry("trustca", t))));
        Assert.Equal($"{JksField}/trustca", e.Alias);
        Assert.Single(e.Certificates);
        Assert.False(e.HasPrivateKey);
    }

    [Fact]
    public void Jks_ChainCertAlsoStoredAsTrustedAlias_ReportsBothAliases()
    {
        var entries = InventoryJks(Jks((s, c, _) =>
        {
            JksKey(s, "mykey", c);
            s.SetCertificateEntry("intermediate", c[1].Certificate);
        }));
        // CHANGED vs 1.3.0 ({mykey} only): the explicitly stored trusted alias is now listed, without a key.
        Assert.Equal(new[] { $"{JksField}/intermediate", $"{JksField}/mykey" }, Aliases(entries));
        Assert.False(entries.Single(x => x.Alias.EndsWith("/intermediate")).HasPrivateKey);
        Assert.True(entries.Single(x => x.Alias.EndsWith("/mykey")).HasPrivateKey);
    }

    [Fact]
    public void Jks_FieldActuallyContainsPkcs12_FailsLikeLegacy()
    {
        // 1.3.0 (verified by run) threw the same IOException: BouncyCastle JksStore.Load reports a PKCS12 blob as
        // "password incorrect or store tampered with", which the serializer rethrows before the PKCS12 fallback
        // (and the chain-alias skip logic that depended on it) can run. Parity, not a regression.

        var p12 = P12((s, c, t) =>
        {
            P12Key(s, "mykey", c);
            s.SetCertificateEntry("trustca", new X509CertificateEntry(t));
        });
        Assert.Throws<IOException>(() => InventoryJks(p12));
    }

    // ───────────────────────── PKCS12 ─────────────────────────

    [Fact]
    public void Pkcs12_Control_SingleKeyEntry_ReportsOneAliasWithKey()
    {
        var e = Assert.Single(InventoryP12(P12((s, c, _) => P12Key(s, "mykey", c))));
        Assert.Equal($"{P12Field}/mykey", e.Alias);
        Assert.Equal(2, e.Certificates.Count);
        Assert.True(e.HasPrivateKey);
    }

    [Fact]
    public void Pkcs12_KeyEntryWithChainPlusTrustOnly_MatchesLegacyAliasSet()
    {
        // 1.3.0 (verified by run): trusted cert entry inventoried as its own alias with a single cert.
        var entries = InventoryP12(P12((s, c, t) =>
        {
            P12Key(s, "mykey", c);
            s.SetCertificateEntry("trustca", new X509CertificateEntry(t));
        }));
        Assert.Equal(new[] { $"{P12Field}/mykey", $"{P12Field}/trustca" }, Aliases(entries));
        Assert.Equal(2, entries.Single(x => x.Alias.EndsWith("/mykey")).Certificates.Count);
        Assert.Single(entries.Single(x => x.Alias.EndsWith("/trustca")).Certificates);
        Assert.True(entries.Single(x => x.Alias.EndsWith("/mykey")).HasPrivateKey);
    }

    [Fact]
    public void Pkcs12_TrustOnlyAlias_ShouldNotReportPrivateKey()
    {
        var entries = InventoryP12(P12((s, c, t) =>
        {
            P12Key(s, "mykey", c);
            s.SetCertificateEntry("trustca", new X509CertificateEntry(t));
        }));
        Assert.False(entries.Single(x => x.Alias.EndsWith("/trustca")).HasPrivateKey);
    }

    [Fact]
    public void Pkcs12_TrustOnlyKeystore_MatchesLegacyAliasSet()
    {
        var entries = InventoryP12(P12((s, _, t) => s.SetCertificateEntry("trustca", new X509CertificateEntry(t))));
        Assert.Equal(new[] { $"{P12Field}/trustca" }, Aliases(entries));
    }

    [Fact]
    public void Pkcs12_TrustOnlyKeystore_ShouldNotReportPrivateKey()
    {
        var entries = InventoryP12(P12((s, _, t) => s.SetCertificateEntry("trustca", new X509CertificateEntry(t))));
        Assert.False(Assert.Single(entries).HasPrivateKey);
    }

    [Fact]
    public void Pkcs12_ChainCertAlsoStoredAsTrustedAlias_MatchesLegacyAliasSet()
    {
        // 1.3.0 only had chain-alias skip logic for PKCS12-in-JKS (sourceIsPkcs12), and compared aliases with subject DNs.
        // For a real PKCS12 store 1.3.0 listed every alias BC returned, as 2.0 does.
        var entries = InventoryP12(P12((s, c, _) =>
        {
            P12Key(s, "mykey", c);
            s.SetCertificateEntry("intermediate", new X509CertificateEntry(c[1].Certificate));
        }));
        Assert.Equal(new[] { $"{P12Field}/intermediate", $"{P12Field}/mykey" }, Aliases(entries));
    }

    // ───────────────────────── HasPrivateKey() on the handler ─────────────────────────

    private static JksSecretHandler JksHandler(byte[] data) => new(
        MockedKubeClientFactory.Create(new[]
        {
            MockedKubeClientFactory.Secret(Ns, "ks", "Opaque", new Dictionary<string, byte[]> { [JksField] = data })
        }).Client, new Mock<ILogger>().Object, Context("ks"));

    [Fact]
    public void Jks_HandlerHasPrivateKey_FalseForTrustOnly_TrueWithKeyEntry()
    {
        Assert.False(JksHandler(Jks((s, _, t) => s.SetCertificateEntry("trustca", t))).HasPrivateKey());
        Assert.True(JksHandler(Jks((s, c, _) => JksKey(s, "mykey", c))).HasPrivateKey());
    }

    [Fact]
    public void Pkcs12_HandlerHasPrivateKey_FalseForTrustOnly_TrueWithKeyEntry()
    {
        Pkcs12SecretHandler H(byte[] d) => new(MockedKubeClientFactory.Create(new[]
        {
            MockedKubeClientFactory.Secret(Ns, "ks", "Opaque", new Dictionary<string, byte[]> { [P12Field] = d })
        }).Client, new Mock<ILogger>().Object, Context("ks"));
        Assert.False(H(P12((s, _, t) => s.SetCertificateEntry("trustca", new X509CertificateEntry(t)))).HasPrivateKey());
        Assert.True(H(P12((s, c, _) => P12Key(s, "mykey", c))).HasPrivateKey());
    }

    // ───────────────────────── Management: removing a trust-only alias ─────────────────────────

    /// <summary>Client whose secret replace call is captured so the written keystore can be inspected.</summary>
    private static (MockedKubeClient kube, Func<V1Secret> written) ClientCapturingReplace(string field, byte[] data)
    {
        var kube = MockedKubeClientFactory.Create(new[]
        {
            MockedKubeClientFactory.Secret(Ns, "ks", "Opaque", new Dictionary<string, byte[]> { [field] = data })
        });
        V1Secret captured = null;
        kube.Core.Setup(c => c.ReplaceNamespacedSecretWithHttpMessagesAsync(
                It.IsAny<V1Secret>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<string>(), It.IsAny<bool?>(),
                It.IsAny<IReadOnlyDictionary<string, IReadOnlyList<string>>>(), It.IsAny<System.Threading.CancellationToken>()))
            .Returns((V1Secret body, string _, string _, string _, string _, string _, bool? _,
                IReadOnlyDictionary<string, IReadOnlyList<string>> _, System.Threading.CancellationToken _) =>
            {
                captured = body;
                return System.Threading.Tasks.Task.FromResult(
                    new k8s.Autorest.HttpOperationResponse<V1Secret> { Body = body });
            });
        return (kube, () => captured);
    }

    [Fact]
    public void Jks_Remove_TrustOnlyAlias_RemovesOnlyThatAlias()
    {
        var data = Jks((s, c, t) =>
        {
            JksKey(s, "mykey", c);
            s.SetCertificateEntry("trustca", t);
        });
        var (kube, written) = ClientCapturingReplace(JksField, data);
        var handler = new JksSecretHandler(kube.Client, new Mock<ILogger>().Object, Context("ks"));

        handler.HandleRemove($"{JksField}/trustca");

        var store = new JksStore();
        using var ms = new MemoryStream(written().Data[JksField]);
        store.Load(ms, Pw.ToCharArray());
        Assert.False(store.ContainsAlias("trustca"));
        Assert.True(store.ContainsAlias("mykey"));
    }

    [Fact]
    public void Pkcs12_Remove_TrustOnlyAlias_RemovesOnlyThatAlias()
    {
        var data = P12((s, c, t) =>
        {
            P12Key(s, "mykey", c);
            s.SetCertificateEntry("trustca", new X509CertificateEntry(t));
        });
        var (kube, written) = ClientCapturingReplace(P12Field, data);
        var handler = new Pkcs12SecretHandler(kube.Client, new Mock<ILogger>().Object, Context("ks"));

        handler.HandleRemove($"{P12Field}/trustca");

        var store = new Pkcs12StoreBuilder().Build();
        using var ms = new MemoryStream(written().Data[P12Field]);
        store.Load(ms, Pw.ToCharArray());
        Assert.DoesNotContain("trustca", store.Aliases.Cast<string>());
        Assert.Contains("mykey", store.Aliases.Cast<string>());
    }
}
