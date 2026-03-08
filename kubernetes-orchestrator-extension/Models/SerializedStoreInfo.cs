// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Security.Cryptography.X509Certificates;

namespace Keyfactor.Extensions.Orchestrator.K8S.Models;

/// <summary>
/// Data model containing the serialized contents of a certificate store along with its path.
/// Used to transport serialized store data between operations.
/// </summary>
/// <remarks>
/// Inherits from X509Certificate2 to allow treating the store info as a certificate when needed.
/// </remarks>
internal class SerializedStoreInfo : X509Certificate2
{
    /// <summary>Full file path where the serialized store should be written.</summary>
    public string FilePath { get; set; }

    /// <summary>The serialized store contents as raw bytes.</summary>
    public byte[] Contents { get; set; }
}