// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Jobs;

/// <summary>
/// Regression tests for ManagementBase.RouteOperation.
/// Verifies that CertStoreOperationType.Create is treated as Add (not rejected as unknown),
/// which was the bug: "create if missing" jobs sent operation type Create and got the error
/// "Unknown operation type: Create".
/// </summary>
public class ManagementBaseTests
{
    /// <summary>
    /// Minimal concrete subclass of ManagementBase used to test routing without K8S infrastructure.
    /// Overrides HandleAdd and HandleRemove to track which path was taken.
    /// </summary>
    private class TrackingManagement : ManagementBase
    {
        public bool AddCalled { get; private set; }
        public bool RemoveCalled { get; private set; }

        public TrackingManagement() : base(null)
        {
            Logger = LogHandler.GetClassLogger<TrackingManagement>();
        }

        protected override JobResult HandleAdd(ManagementJobConfiguration config)
        {
            AddCalled = true;
            return SuccessJob(config.JobHistoryId);
        }

        protected override JobResult HandleRemove(ManagementJobConfiguration config)
        {
            RemoveCalled = true;
            return SuccessJob(config.JobHistoryId);
        }
    }

    private static ManagementJobConfiguration MakeConfig(CertStoreOperationType opType) =>
        new() { OperationType = opType, JobHistoryId = 1 };

    #region CertStoreOperationType.Create regression

    [Fact]
    public void RouteOperation_CreateType_CallsHandleAdd()
    {
        // Regression: "create if missing" sends OperationType=Create, which was previously
        // not handled and returned "Unknown operation type: Create".
        var mgmt = new TrackingManagement();

        var result = mgmt.RouteOperation(MakeConfig(CertStoreOperationType.Create));

        Assert.True(mgmt.AddCalled, "Create should route to HandleAdd");
        Assert.False(mgmt.RemoveCalled);
        Assert.Equal(OrchestratorJobStatusJobResult.Success, result.Result);
    }

    [Fact]
    public void RouteOperation_CreateType_DoesNotFail()
    {
        var mgmt = new TrackingManagement();

        var result = mgmt.RouteOperation(MakeConfig(CertStoreOperationType.Create));

        Assert.NotEqual(OrchestratorJobStatusJobResult.Failure, result.Result);
    }

    #endregion

    #region Add still works

    [Fact]
    public void RouteOperation_AddType_CallsHandleAdd()
    {
        var mgmt = new TrackingManagement();

        var result = mgmt.RouteOperation(MakeConfig(CertStoreOperationType.Add));

        Assert.True(mgmt.AddCalled);
        Assert.Equal(OrchestratorJobStatusJobResult.Success, result.Result);
    }

    #endregion

    #region Remove still works

    [Fact]
    public void RouteOperation_RemoveType_CallsHandleRemove()
    {
        var mgmt = new TrackingManagement();

        var result = mgmt.RouteOperation(MakeConfig(CertStoreOperationType.Remove));

        Assert.True(mgmt.RemoveCalled);
        Assert.False(mgmt.AddCalled);
        Assert.Equal(OrchestratorJobStatusJobResult.Success, result.Result);
    }

    #endregion

    #region Unknown operation types still fail

    [Theory]
    [InlineData(CertStoreOperationType.Unknown)]
    [InlineData(CertStoreOperationType.Inventory)]
    [InlineData(CertStoreOperationType.Discovery)]
    public void RouteOperation_UnsupportedTypes_ReturnsFailure(CertStoreOperationType opType)
    {
        var mgmt = new TrackingManagement();

        var result = mgmt.RouteOperation(MakeConfig(opType));

        Assert.Equal(OrchestratorJobStatusJobResult.Failure, result.Result);
        Assert.False(mgmt.AddCalled);
        Assert.False(mgmt.RemoveCalled);
    }

    #endregion
}
