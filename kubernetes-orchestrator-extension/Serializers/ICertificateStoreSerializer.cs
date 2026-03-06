// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Org.BouncyCastle.Pkcs;

namespace Keyfactor.Extensions.Orchestrator.K8S.Serializers;

/// <summary>
/// Interface for certificate store serializers that handle different keystore formats.
/// Implemented by JKS and PKCS12 serializers to provide a consistent API for
/// reading and writing certificate stores.
/// </summary>
internal interface ICertificateStoreSerializer
{
    /// <summary>
    /// Deserializes a certificate store from raw bytes into a Pkcs12Store for manipulation.
    /// </summary>
    /// <param name="storeContents">The raw store bytes.</param>
    /// <param name="storePath">Path to the store (for logging context).</param>
    /// <param name="storePassword">Password to decrypt the store.</param>
    /// <returns>A Pkcs12Store containing the certificates and keys.</returns>
    Pkcs12Store DeserializeRemoteCertificateStore(byte[] storeContents, string storePath, string storePassword);

    /// <summary>
    /// Serializes a Pkcs12Store back to the appropriate format for storage.
    /// </summary>
    /// <param name="certificateStore">The store to serialize.</param>
    /// <param name="storePath">Directory path for the store.</param>
    /// <param name="storeFileName">Filename for the serialized store.</param>
    /// <param name="storePassword">Password to encrypt the store.</param>
    /// <returns>List of SerializedStoreInfo containing the serialized bytes and path.</returns>
    List<SerializedStoreInfo> SerializeRemoteCertificateStore(Pkcs12Store certificateStore, string storePath,
        string storeFileName, string storePassword);

    /// <summary>
    /// Gets the path for the private key file (for stores that separate private keys).
    /// </summary>
    /// <returns>The private key path, or null if not applicable.</returns>
    string GetPrivateKeyPath();
}