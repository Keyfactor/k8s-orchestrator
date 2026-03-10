// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SCluster;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SJKS;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SNS;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SPKCS12;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SSecret;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8STLSSecr;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Moq;
using Xunit;

// Type aliases to avoid fully qualified names in InlineData
using K8SSecretReenrollment = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SSecret.Reenrollment;
using K8STLSSecrReenrollment = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8STLSSecr.Reenrollment;
using K8SJKSReenrollment = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SJKS.Reenrollment;
using K8SPKCS12Reenrollment = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SPKCS12.Reenrollment;
using K8SClusterReenrollment = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SCluster.Reenrollment;
using K8SNSReenrollment = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SNS.Reenrollment;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit;

/// <summary>
/// Tests for Reenrollment classes - all store types return "not implemented".
/// </summary>
public class ReenrollmentTests
{
    private readonly Mock<IPAMSecretResolver> _mockResolver = new();

    private static ReenrollmentJobConfiguration CreateConfig(string capability = "K8SSecret") => new()
    {
        JobId = Guid.NewGuid(),
        JobHistoryId = 1,
        Capability = capability,
        CertificateStoreDetails = new CertificateStore
        {
            ClientMachine = "test-cluster",
            StorePath = "default/test-secret",
            StorePassword = ""
        }
    };

    [Fact]
    public void ReenrollmentBase_ProcessJob_ReturnsFailure()
    {
        // Arrange - use K8SSecret.Reenrollment as concrete implementation
        var reenrollment = new K8SSecretReenrollment(_mockResolver.Object);
        var config = CreateConfig("K8SSecret");

        // Act
        var result = reenrollment.ProcessJob(config, _ => null);

        // Assert
        Assert.Equal(OrchestratorJobStatusJobResult.Failure, result.Result);
        Assert.Contains("not implemented", result.FailureMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(typeof(K8SSecretReenrollment), "K8SSecret")]
    [InlineData(typeof(K8STLSSecrReenrollment), "K8STLSSecr")]
    [InlineData(typeof(K8SJKSReenrollment), "K8SJKS")]
    [InlineData(typeof(K8SPKCS12Reenrollment), "K8SPKCS12")]
    [InlineData(typeof(K8SClusterReenrollment), "K8SCluster")]
    [InlineData(typeof(K8SNSReenrollment), "K8SNS")]
    public void AllStoreTypes_Reenrollment_ReturnsNotImplemented(Type reenrollmentType, string capability)
    {
        // Arrange
        var instance = (IReenrollmentJobExtension)Activator.CreateInstance(reenrollmentType, _mockResolver.Object)!;
        var config = CreateConfig(capability);

        // Act
        var result = instance.ProcessJob(config, _ => null);

        // Assert
        Assert.Equal(OrchestratorJobStatusJobResult.Failure, result.Result);
        Assert.Contains("not implemented", result.FailureMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReenrollmentBase_WithNullConfig_ThrowsException()
    {
        // Arrange
        var reenrollment = new K8SSecretReenrollment(_mockResolver.Object);

        // Act & Assert
        Assert.ThrowsAny<Exception>(() => reenrollment.ProcessJob(null!, _ => null));
    }

    [Fact]
    public void ReenrollmentBase_Constructor_AcceptsResolver()
    {
        // Arrange & Act
        var reenrollment = new K8SSecretReenrollment(_mockResolver.Object);

        // Assert
        Assert.NotNull(reenrollment);
    }
}
