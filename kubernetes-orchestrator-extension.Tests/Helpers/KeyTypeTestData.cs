// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Helpers;

/// <summary>
/// Provides test data for parameterized key type tests using xUnit Theory/MemberData.
/// This allows consolidation of duplicate key type test methods into single parameterized tests.
/// </summary>
public static class KeyTypeTestData
{
    /// <summary>
    /// All supported key types for comprehensive certificate testing.
    /// Includes RSA, EC, and Ed25519 key types.
    /// </summary>
    public static IEnumerable<object[]> AllKeyTypes => new[]
    {
        new object[] { KeyType.Rsa2048 },
        new object[] { KeyType.Rsa4096 },
        new object[] { KeyType.EcP256 },
        new object[] { KeyType.EcP384 },
        new object[] { KeyType.EcP521 },
        new object[] { KeyType.Ed25519 }
    };

    /// <summary>
    /// Common key types for quick smoke tests.
    /// Covers RSA and EC with representative key sizes.
    /// </summary>
    public static IEnumerable<object[]> CommonKeyTypes => new[]
    {
        new object[] { KeyType.Rsa2048 },
        new object[] { KeyType.EcP256 }
    };

    /// <summary>
    /// RSA key types only.
    /// </summary>
    public static IEnumerable<object[]> RsaKeyTypes => new[]
    {
        new object[] { KeyType.Rsa2048 },
        new object[] { KeyType.Rsa4096 }
    };

    /// <summary>
    /// EC (Elliptic Curve) key types only.
    /// </summary>
    public static IEnumerable<object[]> EcKeyTypes => new[]
    {
        new object[] { KeyType.EcP256 },
        new object[] { KeyType.EcP384 },
        new object[] { KeyType.EcP521 }
    };
}
