// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Jobs;

/// <summary>
/// Unit tests for the three custom exception classes: JkSisPkcs12Exception,
/// InvalidK8SSecretException, and StoreNotFoundException.
/// Each class has three constructors (default, message, message+inner) — all three are exercised.
/// </summary>
public class ExceptionTests
{
    #region JkSisPkcs12Exception

    [Fact]
    public void JkSisPkcs12Exception_DefaultConstructor_IsException()
    {
        var ex = new JkSisPkcs12Exception();
        Assert.IsAssignableFrom<Exception>(ex);
    }

    [Fact]
    public void JkSisPkcs12Exception_MessageConstructor_PreservesMessage()
    {
        const string msg = "JKS store is actually PKCS12";
        var ex = new JkSisPkcs12Exception(msg);
        Assert.Equal(msg, ex.Message);
    }

    [Fact]
    public void JkSisPkcs12Exception_InnerExceptionConstructor_PreservesInner()
    {
        var inner = new InvalidOperationException("inner");
        const string msg = "outer message";
        var ex = new JkSisPkcs12Exception(msg, inner);
        Assert.Equal(msg, ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    #endregion

    #region InvalidK8SSecretException

    [Fact]
    public void InvalidK8SSecretException_DefaultConstructor_IsException()
    {
        var ex = new InvalidK8SSecretException();
        Assert.IsAssignableFrom<Exception>(ex);
    }

    [Fact]
    public void InvalidK8SSecretException_MessageConstructor_PreservesMessage()
    {
        const string msg = "secret is invalid";
        var ex = new InvalidK8SSecretException(msg);
        Assert.Equal(msg, ex.Message);
    }

    [Fact]
    public void InvalidK8SSecretException_InnerExceptionConstructor_PreservesInner()
    {
        var inner = new ArgumentException("inner");
        const string msg = "outer";
        var ex = new InvalidK8SSecretException(msg, inner);
        Assert.Equal(msg, ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    #endregion

    #region StoreNotFoundException

    [Fact]
    public void StoreNotFoundException_DefaultConstructor_IsException()
    {
        var ex = new StoreNotFoundException();
        Assert.IsAssignableFrom<Exception>(ex);
    }

    [Fact]
    public void StoreNotFoundException_MessageConstructor_PreservesMessage()
    {
        const string msg = "store not found";
        var ex = new StoreNotFoundException(msg);
        Assert.Equal(msg, ex.Message);
    }

    [Fact]
    public void StoreNotFoundException_InnerExceptionConstructor_PreservesInner()
    {
        var inner = new Exception("inner");
        const string msg = "outer";
        var ex = new StoreNotFoundException(msg, inner);
        Assert.Equal(msg, ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    #endregion
}
