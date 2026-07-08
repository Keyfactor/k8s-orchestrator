// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Org.BouncyCastle.Pkcs;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Jobs;

/// <summary>
/// Unit tests for K8SJobCertificate.GetCertificateContext().
/// </summary>
public class K8SJobCertificateTests
{
    #region GetCertificateContext — null/empty inputs

    [Fact]
    public void GetCertificateContext_NullCertificateEntry_ReturnsNull()
    {
        var jobCert = new K8SJobCertificate { CertificateEntry = null };

        var result = jobCert.GetCertificateContext();

        Assert.Null(result);
    }

    [Fact]
    public void GetCertificateContext_WithCert_NullChain_ReturnsContextWithNoCertChain()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "GetCtx NullChain");
        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(certInfo.Certificate),
            CertPem = "CERT_PEM",
            PrivateKeyPem = "KEY_PEM",
            CertificateEntryChain = null,
            ChainPem = null
        };

        var result = jobCert.GetCertificateContext();

        Assert.NotNull(result);
        Assert.Equal(certInfo.Certificate, result.Certificate);
        Assert.Equal("CERT_PEM", result.CertPem);
        Assert.Equal("KEY_PEM", result.PrivateKeyPem);
        Assert.Empty(result.Chain);
        // ChainPem auto-computes from Chain when not explicitly set; Chain is empty so ChainPem is also empty
        Assert.Empty(result.ChainPem);
    }

    [Fact]
    public void GetCertificateContext_WithCert_EmptyChainArray_ReturnsContextWithNoCertChain()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "GetCtx EmptyChain");
        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(certInfo.Certificate),
            CertificateEntryChain = [],
            ChainPem = null
        };

        var result = jobCert.GetCertificateContext();

        Assert.NotNull(result);
        Assert.Empty(result.Chain);
    }

    #endregion

    #region GetCertificateContext — chain handling

    [Fact]
    public void GetCertificateContext_WithChainNoCertPem_SetsChainSkippingLeaf()
    {
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.EcP256, "GetCtx Chain NoPem");
        var leaf = chain[0].Certificate;
        var intermediate = chain[1].Certificate;
        var root = chain[2].Certificate;

        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(leaf),
            CertificateEntryChain =
            [
                new X509CertificateEntry(leaf),
                new X509CertificateEntry(intermediate),
                new X509CertificateEntry(root)
            ],
            ChainPem = null
        };

        var result = jobCert.GetCertificateContext();

        Assert.NotNull(result);
        // Chain skips leaf (index 0), contains intermediate and root
        Assert.Equal(2, result.Chain.Count);
        Assert.Equal(intermediate, result.Chain[0]);
        Assert.Equal(root, result.Chain[1]);
        // ChainPem auto-computes from Chain when _chainPem is not explicitly set
        Assert.Equal(2, result.ChainPem.Count);
    }

    [Fact]
    public void GetCertificateContext_WithChainAndEmptyChainPemList_SetsChainNoChainPem()
    {
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.EcP256, "GetCtx Chain EmptyPem");
        var leaf = chain[0].Certificate;
        var intermediate = chain[1].Certificate;

        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(leaf),
            CertificateEntryChain =
            [
                new X509CertificateEntry(leaf),
                new X509CertificateEntry(intermediate)
            ],
            ChainPem = new List<string>()  // empty list
        };

        var result = jobCert.GetCertificateContext();

        Assert.NotNull(result);
        Assert.Single(result.Chain);
        // ChainPem auto-computes from Chain; _chainPem was not explicitly set (empty list doesn't trigger set)
        Assert.Single(result.ChainPem);
    }

    [Fact]
    public void GetCertificateContext_WithChainAndChainPem_SetsChainPemSkippingLeaf()
    {
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.EcP256, "GetCtx ChainPem");
        var leaf = chain[0].Certificate;
        var intermediate = chain[1].Certificate;
        var root = chain[2].Certificate;

        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(leaf),
            CertificateEntryChain =
            [
                new X509CertificateEntry(leaf),
                new X509CertificateEntry(intermediate),
                new X509CertificateEntry(root)
            ],
            ChainPem = new List<string> { "LEAF_PEM", "INTERMEDIATE_PEM", "ROOT_PEM" }
        };

        var result = jobCert.GetCertificateContext();

        Assert.NotNull(result);
        Assert.Equal(2, result.Chain.Count);
        // ChainPem also skips leaf (index 0)
        Assert.NotNull(result.ChainPem);
        Assert.Equal(2, result.ChainPem.Count);
        Assert.Equal("INTERMEDIATE_PEM", result.ChainPem[0]);
        Assert.Equal("ROOT_PEM", result.ChainPem[1]);
    }

    [Fact]
    public void GetCertificateContext_CertPemAndPrivateKeyPemAreCopied()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "GetCtx PemCopy");

        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(certInfo.Certificate),
            CertPem = "MY_CERT_PEM",
            PrivateKeyPem = "MY_KEY_PEM"
        };

        var result = jobCert.GetCertificateContext();

        Assert.Equal("MY_CERT_PEM", result.CertPem);
        Assert.Equal("MY_KEY_PEM", result.PrivateKeyPem);
    }

    [Fact]
    public void GetCertificateContext_Certificate_IsSetFromCertificateEntry()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "GetCtx CertSet");

        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(certInfo.Certificate)
        };

        var result = jobCert.GetCertificateContext();

        Assert.Equal(certInfo.Certificate, result.Certificate);
    }

    #endregion
}
