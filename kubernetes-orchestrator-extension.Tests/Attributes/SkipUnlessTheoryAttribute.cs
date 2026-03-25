// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Attributes;

/// <summary>
/// Custom xUnit attribute that combines Theory behavior with environment variable skip logic.
/// Skips all test cases in the Theory unless the specified environment variable is set to the expected value.
/// </summary>
/// <example>
/// [SkipUnlessTheory(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
/// [MemberData(nameof(KeyTypeTestData.AllKeyTypes), MemberType = typeof(KeyTypeTestData))]
/// public void MyKeyTypeTest(KeyType keyType) { ... }
/// </example>
public class SkipUnlessTheoryAttribute : TheoryAttribute
{
    /// <summary>
    /// Gets or sets the name of the environment variable to check.
    /// </summary>
    public string EnvironmentVariable { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the expected value of the environment variable (defaults to "true").
    /// </summary>
    public string ExpectedValue { get; set; } = "true";

    public SkipUnlessTheoryAttribute()
    {
    }

    public override string? Skip
    {
        get
        {
            if (string.IsNullOrEmpty(EnvironmentVariable))
            {
                return "SkipUnlessTheory attribute requires EnvironmentVariable property to be set";
            }

            var value = Environment.GetEnvironmentVariable(EnvironmentVariable);

            if (string.IsNullOrEmpty(value) ||
                !value.Equals(ExpectedValue, StringComparison.OrdinalIgnoreCase))
            {
                return $"Test skipped because environment variable '{EnvironmentVariable}' is not set to '{ExpectedValue}'. " +
                       $"Current value: '{value ?? "(not set)"}'";
            }

            return null; // Don't skip
        }
        set { }
    }
}
