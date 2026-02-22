// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Org.BouncyCastle.Pkcs;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers.Serializers;

/// <summary>
/// Interface for certificate store serializers that handle different keystore formats.
/// Implemented by JKS and PKCS12 serializers to provide a consistent API for
/// reading and writing certificate stores.
/// </summary>
public interface ICertificateStoreSerializer
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
    /// Gets the path for the private key file (for stores that separate private keys).
    /// </summary>
    /// <returns>The private key path, or null if not applicable.</returns>
    string GetPrivateKeyPath();

    /// <summary>
    /// Creates a new certificate store or updates an existing one with a new certificate.
    /// Handles both add and remove operations for keystore formats (JKS, PKCS12).
    /// </summary>
    /// <param name="newCertBytes">Certificate bytes to add (PKCS12 format or raw certificate).</param>
    /// <param name="newCertPassword">Password for the new certificate's private key.</param>
    /// <param name="alias">Alias for the certificate entry in the store.</param>
    /// <param name="existingStore">Existing store bytes (null for new store).</param>
    /// <param name="existingStorePassword">Password for the existing store.</param>
    /// <param name="remove">True to remove the certificate, false to add.</param>
    /// <param name="includeChain">Whether to include the certificate chain.</param>
    /// <returns>The updated store as byte array.</returns>
    byte[] AddOrRemoveCertificate(
        byte[] newCertBytes,
        string newCertPassword,
        string alias,
        byte[] existingStore = null,
        string existingStorePassword = null,
        bool remove = false,
        bool includeChain = true);
}
