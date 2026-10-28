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
using System.Text;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.X509;
using Xunit;
using KeyType = Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper.KeyType;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Services;

/// <summary>
/// K8SCluster/K8SNS inventory visits every Opaque secret, so a value under an inventory key (<c>key</c>, <c>ca</c>,
/// <c>tls.key</c>, ...) that is simply not a certificate is normal. It must be skipped quietly (Debug), while a
/// genuinely unexpected fault must still surface instead of being swallowed.
/// </summary>
public class CertificateChainExtractorNonCertificateTests
{
    private const string Source = "secret 'app' key 'key' in namespace 'team-a'";

    private sealed class RecordingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();
        public IDisposable BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
            Func<TState, Exception, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));

        public IEnumerable<string> WarningsOrWorse => Entries.Where(e => e.Level >= LogLevel.Warning)
            .Select(e => $"{e.Level}: {e.Message}");
    }

    /// <summary>Extractor whose DER read throws a chosen exception, to simulate a fault that is not "not a cert".</summary>
    private sealed class FaultyDerExtractor : CertificateChainExtractor
    {
        private readonly Exception _fault;

        public FaultyDerExtractor(KubeCertificateManagerClient client, ILogger logger, Exception fault)
            : base(client, logger) => _fault = fault;

        protected override X509Certificate ReadDerCertificate(string certData) => throw _fault;
    }

    private static KubeCertificateManagerClient Client()
        => MockedKubeClientFactory.Create(Array.Empty<V1Secret>()).Client;

    private static string KeyPem() => CertificateTestHelper.ConvertPrivateKeyToPem(
        CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "non-cert-key").KeyPair.Private);

    private static string CertPem() => CertificateTestHelper.ConvertCertificateToPem(
        CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "non-cert-cert").Certificate);

    private static string DerBase64() => Convert.ToBase64String(
        CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "non-cert-cert").Certificate.GetEncoded());

    public static IEnumerable<object[]> NonCertificateValues()
    {
        var der = DerBase64();
        yield return new object[] { "PEM private key", KeyPem() };
        yield return new object[] { "random text", "this is !!! not a certificate @@@" };
        yield return new object[] { "password", "hunter2\n" };
        yield return new object[] { "json", "{\"auths\":{}}" };
        yield return new object[] { "padded single char", "  x  " };
        // Valid Base-64 that decodes to something other than an X.509 certificate:
        yield return new object[] { "base64 of text", Convert.ToBase64String(Encoding.UTF8.GetBytes("password123")) };
        yield return new object[] { "base64 of four junk bytes", Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }) };
        yield return new object[] { "base64 of zeros", Convert.ToBase64String(new byte[64]) };
        yield return new object[] { "base64 of foreign ASN.1", Convert.ToBase64String(new byte[] { 0x30, 3, 2, 1, 5 }) };
        // A real certificate cut off mid-way (Base-64 stays valid, the DER does not):
        yield return new object[] { "truncated base64 certificate", der.Substring(0, der.Length / 2 / 4 * 4) };
    }

    [Theory]
    [MemberData(nameof(NonCertificateValues))]
    public void ExtractCertificates_NonCertificateValue_ReturnsEmpty_WithoutWarningOrWorse(string description, string value)
    {
        var logger = new RecordingLogger();
        var extractor = new CertificateChainExtractor(Client(), logger);

        var result = extractor.ExtractCertificates(value, Source);

        Assert.Empty(result);
        Assert.Empty(logger.WarningsOrWorse);
        // The outcome is still recorded at Debug and says where it came from.
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Debug && e.Message.Contains(Source));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public void ExtractCertificates_EmptyOrWhitespace_ReturnsEmpty_WithoutWarningOrWorse(string value)
    {
        var logger = new RecordingLogger();

        var result = new CertificateChainExtractor(Client(), logger).ExtractCertificates(value, Source);

        Assert.Empty(result);
        Assert.Empty(logger.WarningsOrWorse);
    }

    [Fact]
    public void ExtractCertificates_NotBase64_DebugEntryCarriesTheReason_NotJustTheExceptionType()
    {
        var logger = new RecordingLogger();

        new CertificateChainExtractor(Client(), logger).ExtractCertificates("hunter2", Source);

        var entry = Assert.Single(logger.Entries,
            e => e.Level == LogLevel.Debug && e.Message.Contains("is not a DER certificate"));
        Assert.Contains(Source, entry.Message);
        Assert.Contains("FormatException", entry.Message);
        Assert.Contains("Base-64", entry.Message); // the exception message, not only its type
    }

    [Fact]
    public void ExtractCertificates_PrivateKeyText_DoesNotLeakTheKeyIntoLogs()
    {
        var logger = new RecordingLogger();
        var key = KeyPem();

        new CertificateChainExtractor(Client(), logger).ExtractCertificates(key, Source);

        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("PRIVATE KEY") || e.Message.Contains(key[40..80]));
    }

    [Fact]
    public void ExtractCertificates_ValidPemChain_StillParses()
    {
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "non-cert-chain");
        var pem = string.Join("\n", chain.Select(c => CertificateTestHelper.ConvertCertificateToPem(c.Certificate)));
        var logger = new RecordingLogger();

        var result = new CertificateChainExtractor(Client(), logger).ExtractCertificates(pem, Source);

        Assert.Equal(chain.Count, result.Count);
        Assert.All(result, c => Assert.Contains("-----BEGIN CERTIFICATE-----", c));
        Assert.Empty(logger.WarningsOrWorse);
    }

    [Theory]
    [InlineData("")]
    [InlineData("\n")]
    public void ExtractCertificates_ValidDer_StillParses(string suffix)
    {
        var logger = new RecordingLogger();

        var result = new CertificateChainExtractor(Client(), logger).ExtractCertificates(DerBase64() + suffix, Source);

        var pem = Assert.Single(result);
        Assert.Contains("-----BEGIN CERTIFICATE-----", pem);
        Assert.Empty(logger.WarningsOrWorse);
    }

    [Fact]
    public void ExtractFromSecretData_KeyOnlySecret_ReturnsEmpty_WithoutWarningOrWorse()
    {
        var logger = new RecordingLogger();
        var data = new Dictionary<string, byte[]> { ["tls.key"] = Encoding.UTF8.GetBytes(KeyPem()) };

        var result = new CertificateChainExtractor(Client(), logger)
            .ExtractFromSecretData(data, new[] { "tls.key", "key", "ca.crt" }, "app", "team-a");

        Assert.Empty(result);
        Assert.Empty(logger.WarningsOrWorse);
    }

    [Fact]
    public void ExtractFromSecretData_NonCertificateCaCrt_IsSkippedQuietly_AndPrimaryCertStillReturned()
    {
        var logger = new RecordingLogger();
        var data = new Dictionary<string, byte[]>
        {
            ["tls.crt"] = Encoding.UTF8.GetBytes(CertPem()),
            ["ca.crt"] = Encoding.UTF8.GetBytes("not a ca bundle")
        };

        var result = new CertificateChainExtractor(Client(), logger)
            .ExtractFromSecretData(data, new[] { "tls.crt", "ca.crt" }, "app", "team-a");

        Assert.Single(result);
        Assert.Empty(logger.WarningsOrWorse);
    }

    [Theory]
    [MemberData(nameof(UnexpectedFaults))]
    public void ExtractCertificates_UnexpectedFaultFromTheClient_Propagates(Exception fault)
    {
        var extractor = new FaultyDerExtractor(Client(), new RecordingLogger(), fault);

        // Valid Base-64 that is not a PEM, so the DER path (and therefore the faulty client) is reached.
        var thrown = Assert.Throws(fault.GetType(), () => extractor.ExtractCertificates(DerBase64(), Source));

        Assert.Same(fault, thrown);
    }

    public static IEnumerable<object[]> UnexpectedFaults() => new[]
    {
        new object[] { new InvalidOperationException("client is in a bad state") },
        new object[] { new IOException("disk fault") },
        new object[] { new NullReferenceException() },
        new object[] { new ArgumentException("unexpected argument") }
    };

    [Fact]
    public void ExtractCertificates_FormatAndCertificateFaults_AreStillTreatedAsNotACertificate()
    {
        var logger = new RecordingLogger();

        foreach (var fault in new Exception[]
                 {
                     new FormatException("bad base64"),
                     new Org.BouncyCastle.Security.Certificates.CertificateException("Failed to read certificate")
                 })
        {
            var result = new FaultyDerExtractor(Client(), logger, fault).ExtractCertificates(DerBase64(), Source);
            Assert.Empty(result);
        }

        Assert.Empty(logger.WarningsOrWorse);
    }
}
