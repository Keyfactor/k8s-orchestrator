// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers.Serializers;

/// <summary>
/// Exception thrown when a JKS keystore contains PKCS12 data instead of proper JKS format,
/// or vice versa (format mismatch between expected and actual store format).
/// </summary>
public class JkSisPkcs12Exception : Exception
{
    /// <summary>Initializes a new instance of JkSisPkcs12Exception.</summary>
    public JkSisPkcs12Exception()
    {
    }

    /// <summary>Initializes a new instance of JkSisPkcs12Exception with a message.</summary>
    /// <param name="message">The exception message.</param>
    public JkSisPkcs12Exception(string message) : base(message)
    {
    }

    /// <summary>Initializes a new instance of JkSisPkcs12Exception with a message and inner exception.</summary>
    /// <param name="message">The exception message.</param>
    /// <param name="innerException">The inner exception.</param>
    public JkSisPkcs12Exception(string message, Exception innerException) : base(message, innerException)
    {
    }
}
