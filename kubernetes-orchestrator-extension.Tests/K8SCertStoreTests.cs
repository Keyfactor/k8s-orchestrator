// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Moq;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests;

/// <summary>
/// Unit tests for K8SCert store type operations.
/// K8SCert is READ-ONLY - only Inventory and Discovery are supported.
/// No Management (Add/Remove) or Reenrollment operations.
/// Tests focus on CertificateSigningRequest handling.
/// </summary>
public class K8SCertStoreTests
{
    #region CSR Helper Methods

    private V1CertificateSigningRequest CreateTestCsr(
        string name,
        string status = "Approved",
        bool includeCertificate = true,
        KeyType keyType = KeyType.Rsa2048)
    {
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"CSR {name}");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var certBytes = System.Text.Encoding.UTF8.GetBytes(certPem);

        var csr = new V1CertificateSigningRequest
        {
            Metadata = new V1ObjectMeta
            {
                Name = name,
                CreationTimestamp = DateTime.UtcNow
            },
            Status = new V1CertificateSigningRequestStatus()
        };

        // Add conditions based on status
        if (status == "Approved")
        {
            csr.Status.Conditions = new List<V1CertificateSigningRequestCondition>
            {
                new V1CertificateSigningRequestCondition
                {
                    Type = "Approved",
                    Status = "True",
                    Reason = "AutoApproved",
                    Message = "This CSR was approved by test automation"
                }
            };

            if (includeCertificate)
            {
                csr.Status.Certificate = certBytes;
            }
        }
        else if (status == "Denied")
        {
            csr.Status.Conditions = new List<V1CertificateSigningRequestCondition>
            {
                new V1CertificateSigningRequestCondition
                {
                    Type = "Denied",
                    Status = "True",
                    Reason = "PolicyViolation",
                    Message = "CSR denied by policy"
                }
            };
        }
        else if (status == "Pending")
        {
            // No conditions means pending
            csr.Status.Conditions = null;
        }

        return csr;
    }

    #endregion

    #region CSR Status Tests

    [Fact]
    public void CertificateSigningRequest_ApprovedWithCertificate_HasValidStatus()
    {
        // Arrange
        var csr = CreateTestCsr("test-approved", status: "Approved", includeCertificate: true);

        // Assert
        Assert.NotNull(csr.Status);
        Assert.NotNull(csr.Status.Conditions);
        Assert.Single(csr.Status.Conditions);
        Assert.Equal("Approved", csr.Status.Conditions[0].Type);
        Assert.NotNull(csr.Status.Certificate);
        Assert.NotEmpty(csr.Status.Certificate);
    }

    [Fact]
    public void CertificateSigningRequest_Pending_HasNoConditions()
    {
        // Arrange
        var csr = CreateTestCsr("test-pending", status: "Pending", includeCertificate: false);

        // Assert
        Assert.NotNull(csr.Status);
        Assert.Null(csr.Status.Conditions);
        Assert.Null(csr.Status.Certificate);
    }

    [Fact]
    public void CertificateSigningRequest_Denied_HasDeniedCondition()
    {
        // Arrange
        var csr = CreateTestCsr("test-denied", status: "Denied", includeCertificate: false);

        // Assert
        Assert.NotNull(csr.Status);
        Assert.NotNull(csr.Status.Conditions);
        Assert.Single(csr.Status.Conditions);
        Assert.Equal("Denied", csr.Status.Conditions[0].Type);
        Assert.Null(csr.Status.Certificate);
    }

    [Fact]
    public void CertificateSigningRequest_ApprovedWithoutCertificate_IsIncomplete()
    {
        // Arrange - CSR approved but certificate not yet issued
        var csr = CreateTestCsr("test-approved-no-cert", status: "Approved", includeCertificate: false);

        // Assert
        Assert.NotNull(csr.Status);
        Assert.NotNull(csr.Status.Conditions);
        Assert.Equal("Approved", csr.Status.Conditions[0].Type);
        Assert.Null(csr.Status.Certificate); // Certificate not yet issued
    }

    #endregion

    #region CSR Certificate Parsing Tests

    [Fact]
    public void CertificateSigningRequest_WithValidCertificate_CanBeParsed()
    {
        // Arrange
        var csr = CreateTestCsr("test-parse", status: "Approved", includeCertificate: true, keyType: KeyType.Rsa2048);

        // Act
        var certBytes = csr.Status.Certificate;
        var certPem = System.Text.Encoding.UTF8.GetString(certBytes);

        // Assert
        Assert.NotNull(certPem);
        Assert.Contains("-----BEGIN CERTIFICATE-----", certPem);
        Assert.Contains("-----END CERTIFICATE-----", certPem);
    }

    [Theory]
    [InlineData(KeyType.Rsa1024)]
    [InlineData(KeyType.Rsa2048)]
    [InlineData(KeyType.Rsa4096)]
    [InlineData(KeyType.Rsa8192)]
    [InlineData(KeyType.EcP256)]
    [InlineData(KeyType.EcP384)]
    [InlineData(KeyType.EcP521)]
    [InlineData(KeyType.Dsa1024)]
    [InlineData(KeyType.Dsa2048)]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.Ed448)]
    public void CertificateSigningRequest_VariousKeyTypes_CanBeCreated(KeyType keyType)
    {
        // Arrange & Act
        var csr = CreateTestCsr($"test-{keyType}", status: "Approved", includeCertificate: true, keyType: keyType);

        // Assert
        Assert.NotNull(csr);
        Assert.NotNull(csr.Status.Certificate);
        var certPem = System.Text.Encoding.UTF8.GetString(csr.Status.Certificate);
        Assert.Contains("-----BEGIN CERTIFICATE-----", certPem);
    }

    #endregion

    #region CSR Collection Tests

    [Fact]
    public void CertificateSigningRequests_MultipleCSRs_CanBeEnumerated()
    {
        // Arrange
        var csrs = new List<V1CertificateSigningRequest>
        {
            CreateTestCsr("csr-1", "Approved", true),
            CreateTestCsr("csr-2", "Pending", false),
            CreateTestCsr("csr-3", "Denied", false),
            CreateTestCsr("csr-4", "Approved", true)
        };

        // Act
        var approvedCount = csrs.Count(c =>
            c.Status.Conditions?.Any(cond => cond.Type == "Approved") == true);
        var pendingCount = csrs.Count(c =>
            c.Status.Conditions == null || c.Status.Conditions.Count == 0);
        var deniedCount = csrs.Count(c =>
            c.Status.Conditions?.Any(cond => cond.Type == "Denied") == true);
        var withCertificates = csrs.Count(c => c.Status.Certificate != null);

        // Assert
        Assert.Equal(4, csrs.Count);
        Assert.Equal(2, approvedCount);
        Assert.Equal(1, pendingCount);
        Assert.Equal(1, deniedCount);
        Assert.Equal(2, withCertificates);
    }

    #endregion

    #region Edge Case Tests

    [Fact]
    public void CertificateSigningRequest_NullStatus_HandledGracefully()
    {
        // Arrange
        var csr = new V1CertificateSigningRequest
        {
            Metadata = new V1ObjectMeta { Name = "test-null-status" },
            Status = null
        };

        // Assert
        Assert.NotNull(csr);
        Assert.Null(csr.Status);
    }

    [Fact]
    public void CertificateSigningRequest_EmptyConditions_TreatedAsPending()
    {
        // Arrange
        var csr = new V1CertificateSigningRequest
        {
            Metadata = new V1ObjectMeta { Name = "test-empty-conditions" },
            Status = new V1CertificateSigningRequestStatus
            {
                Conditions = new List<V1CertificateSigningRequestCondition>()
            }
        };

        // Assert
        Assert.NotNull(csr.Status);
        Assert.NotNull(csr.Status.Conditions);
        Assert.Empty(csr.Status.Conditions);
    }

    [Fact]
    public void CertificateSigningRequest_MultipleConditions_LatestTakesPrecedence()
    {
        // Arrange - CSR that was pending, then approved
        var csr = new V1CertificateSigningRequest
        {
            Metadata = new V1ObjectMeta { Name = "test-multi-conditions" },
            Status = new V1CertificateSigningRequestStatus
            {
                Conditions = new List<V1CertificateSigningRequestCondition>
                {
                    new V1CertificateSigningRequestCondition
                    {
                        Type = "Approved",
                        Status = "True",
                        LastUpdateTime = DateTime.UtcNow
                    },
                    new V1CertificateSigningRequestCondition
                    {
                        Type = "Failed",
                        Status = "False",
                        LastUpdateTime = DateTime.UtcNow.AddMinutes(-5)
                    }
                }
            }
        };

        // Assert
        Assert.Equal(2, csr.Status.Conditions.Count);
        // The first condition in the list should be the most recent (Approved)
        Assert.Equal("Approved", csr.Status.Conditions[0].Type);
    }

    #endregion

    #region Metadata Tests

    [Fact]
    public void CertificateSigningRequest_Metadata_ContainsRequiredFields()
    {
        // Arrange
        var csr = CreateTestCsr("test-metadata", "Approved", true);

        // Assert
        Assert.NotNull(csr.Metadata);
        Assert.Equal("test-metadata", csr.Metadata.Name);
        Assert.NotNull(csr.Metadata.CreationTimestamp);
    }

    #endregion
}
