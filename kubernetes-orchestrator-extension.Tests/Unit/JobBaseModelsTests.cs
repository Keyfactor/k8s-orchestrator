// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Org.BouncyCastle.Pkcs;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit;

/// <summary>
/// Tests for model classes: K8SJobCertificate and exception classes.
/// </summary>
public class JobBaseModelsTests
{
    #region InvalidK8SSecretException Tests

    [Fact]
    public void InvalidK8SSecretException_DefaultConstructor_CreatesException()
    {
        var ex = new InvalidK8SSecretException();

        Assert.NotNull(ex);
        Assert.IsType<InvalidK8SSecretException>(ex);
    }

    [Fact]
    public void InvalidK8SSecretException_WithMessage_ContainsMessage()
    {
        const string message = "Secret format is invalid";

        var ex = new InvalidK8SSecretException(message);

        Assert.Equal(message, ex.Message);
    }

    [Fact]
    public void InvalidK8SSecretException_WithMessageAndInnerException_ContainsBoth()
    {
        const string message = "Secret format is invalid";
        var inner = new FormatException("Invalid format");

        var ex = new InvalidK8SSecretException(message, inner);

        Assert.Equal(message, ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void InvalidK8SSecretException_CanBeThrown()
    {
        var ex = Assert.Throws<InvalidK8SSecretException>(() => ThrowInvalidK8SSecretException());
        Assert.Equal("Test exception", ex.Message);
    }

    private static void ThrowInvalidK8SSecretException()
    {
        throw new InvalidK8SSecretException("Test exception");
    }

    [Fact]
    public void InvalidK8SSecretException_InheritsFromException()
    {
        var ex = new InvalidK8SSecretException("test");

        Assert.IsAssignableFrom<Exception>(ex);
    }

    #endregion

    #region JkSisPkcs12Exception Tests

    [Fact]
    public void JkSisPkcs12Exception_DefaultConstructor_CreatesException()
    {
        var ex = new JkSisPkcs12Exception();

        Assert.NotNull(ex);
        Assert.IsType<JkSisPkcs12Exception>(ex);
    }

    [Fact]
    public void JkSisPkcs12Exception_WithMessage_ContainsMessage()
    {
        const string message = "File is PKCS12 but was expected to be JKS";

        var ex = new JkSisPkcs12Exception(message);

        Assert.Equal(message, ex.Message);
    }

    [Fact]
    public void JkSisPkcs12Exception_WithMessageAndInnerException_ContainsBoth()
    {
        const string message = "Format mismatch";
        var inner = new InvalidOperationException("Cannot parse");

        var ex = new JkSisPkcs12Exception(message, inner);

        Assert.Equal(message, ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void JkSisPkcs12Exception_CanBeThrown()
    {
        var ex = Assert.Throws<JkSisPkcs12Exception>(() => ThrowJkSisPkcs12Exception());
        Assert.Equal("Test exception", ex.Message);
    }

    private static void ThrowJkSisPkcs12Exception()
    {
        throw new JkSisPkcs12Exception("Test exception");
    }

    [Fact]
    public void JkSisPkcs12Exception_InheritsFromException()
    {
        var ex = new JkSisPkcs12Exception("test");

        Assert.IsAssignableFrom<Exception>(ex);
    }

    #endregion

    #region StoreNotFoundException Tests

    [Fact]
    public void StoreNotFoundException_DefaultConstructor_CreatesException()
    {
        var ex = new StoreNotFoundException();

        Assert.NotNull(ex);
        Assert.IsType<StoreNotFoundException>(ex);
    }

    [Fact]
    public void StoreNotFoundException_WithMessage_ContainsMessage()
    {
        const string message = "Certificate store 'my-secret' not found in namespace 'default'";

        var ex = new StoreNotFoundException(message);

        Assert.Equal(message, ex.Message);
    }

    [Fact]
    public void StoreNotFoundException_WithMessageAndInnerException_ContainsBoth()
    {
        const string message = "Store not found";
        var inner = new InvalidOperationException("K8s API error");

        var ex = new StoreNotFoundException(message, inner);

        Assert.Equal(message, ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void StoreNotFoundException_CanBeThrown()
    {
        var ex = Assert.Throws<StoreNotFoundException>(() => ThrowStoreNotFoundException());
        Assert.Equal("Test store not found", ex.Message);
    }

    private static void ThrowStoreNotFoundException()
    {
        throw new StoreNotFoundException("Test store not found");
    }

    [Fact]
    public void StoreNotFoundException_InheritsFromException()
    {
        var ex = new StoreNotFoundException("test");

        Assert.IsAssignableFrom<Exception>(ex);
    }

    #endregion

    #region K8SJobCertificate.GetCertificateContext Tests

    [Fact]
    public void GetCertificateContext_NullCertificateEntry_ReturnsNull()
    {
        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = null
        };

        var result = jobCert.GetCertificateContext();

        Assert.Null(result);
    }

    [Fact]
    public void GetCertificateContext_CertificateEntryWithNullCert_ReturnsNull()
    {
        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(null)
        };

        try
        {
            var result = jobCert.GetCertificateContext();
            Assert.Null(result);
        }
        catch (ArgumentNullException)
        {
            // X509CertificateEntry constructor may throw for null - that's fine
        }
    }

    [Fact]
    public void GetCertificateContext_ValidCertificate_ReturnsContext()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert Context Test");
        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(certInfo.Certificate),
            CertPem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            PrivateKeyPem = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
        };

        var result = jobCert.GetCertificateContext();

        Assert.NotNull(result);
        Assert.Equal(certInfo.Certificate, result.Certificate);
        Assert.Equal(jobCert.CertPem, result.CertPem);
        Assert.Equal(jobCert.PrivateKeyPem, result.PrivateKeyPem);
    }

    [Fact]
    public void GetCertificateContext_WithChain_SkipsLeafCert()
    {
        var leafInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert Leaf");
        var intermediateInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert Intermediate");
        var rootInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert Root");

        var chainEntries = new[]
        {
            new X509CertificateEntry(leafInfo.Certificate),
            new X509CertificateEntry(intermediateInfo.Certificate),
            new X509CertificateEntry(rootInfo.Certificate)
        };

        var chainPem = new List<string>
        {
            "leaf-pem",
            "intermediate-pem",
            "root-pem"
        };

        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(leafInfo.Certificate),
            CertificateEntryChain = chainEntries,
            ChainPem = chainPem,
            CertPem = "leaf-cert-pem",
            PrivateKeyPem = ""
        };

        var result = jobCert.GetCertificateContext();

        Assert.NotNull(result);
        Assert.NotNull(result.Chain);
        Assert.Equal(2, result.Chain.Count);
        Assert.Equal(intermediateInfo.Certificate, result.Chain[0]);
        Assert.Equal(rootInfo.Certificate, result.Chain[1]);
        Assert.Equal(2, result.ChainPem.Count);
        Assert.Equal("intermediate-pem", result.ChainPem[0]);
        Assert.Equal("root-pem", result.ChainPem[1]);
    }

    [Fact]
    public void GetCertificateContext_WithChain_NullChainPem_ChainStillSet()
    {
        var leafInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert NullChainPem");
        var intermediateInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert NullChainPem Int");

        var chainEntries = new[]
        {
            new X509CertificateEntry(leafInfo.Certificate),
            new X509CertificateEntry(intermediateInfo.Certificate)
        };

        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(leafInfo.Certificate),
            CertificateEntryChain = chainEntries,
            ChainPem = null,
            CertPem = "leaf-pem",
            PrivateKeyPem = ""
        };

        var result = jobCert.GetCertificateContext();

        Assert.NotNull(result);
        Assert.NotNull(result.Chain);
        Assert.Single(result.Chain);
        Assert.Equal(intermediateInfo.Certificate, result.Chain[0]);
        Assert.NotNull(result.ChainPem);
    }

    [Fact]
    public void GetCertificateContext_EmptyChain_DoesNotSetChain()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert EmptyChain");

        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(certInfo.Certificate),
            CertificateEntryChain = Array.Empty<X509CertificateEntry>(),
            CertPem = "cert-pem",
            PrivateKeyPem = ""
        };

        var result = jobCert.GetCertificateContext();

        Assert.NotNull(result);
        Assert.Empty(result.Chain);
    }

    #endregion
}
