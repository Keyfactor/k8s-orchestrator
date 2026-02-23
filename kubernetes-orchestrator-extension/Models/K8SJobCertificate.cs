// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

/// <summary>
/// Comprehensive data model for a certificate processed during a Keyfactor orchestrator job.
/// Contains certificate data in multiple formats (PEM, bytes, base64), private key data,
/// certificate chain information, and password details.
/// </summary>
public class K8SJobCertificate
{
    /// <summary>Alias/friendly name for the certificate entry.</summary>
    public string Alias { get; set; } = "";

    /// <summary>Base64 encoded certificate data.</summary>
    public string CertB64 { get; set; } = "";

    /// <summary>Certificate in PEM format.</summary>
    public string CertPem { get; set; } = "";

    /// <summary>SHA-1 thumbprint of the certificate for identification.</summary>
    public string CertThumbprint { get; set; } = "";

    /// <summary>Raw certificate bytes (DER encoded).</summary>
    public byte[] CertBytes { get; set; }

    /// <summary>Private key in PEM format (unencrypted).</summary>
    public string PrivateKeyPem { get; set; } = "";

    /// <summary>Raw private key bytes (PKCS#8 format).</summary>
    public byte[] PrivateKeyBytes { get; set; }

    /// <summary>Password protecting the private key (if encrypted).</summary>
    public string Password { get; set; } = "";

    /// <summary>Indicates if the password is stored in a separate Kubernetes secret.</summary>
    public bool PasswordIsK8SSecret { get; set; } = false;

    /// <summary>Password for the certificate store (JKS/PKCS12).</summary>
    public string StorePassword { get; set; } = "";

    /// <summary>Path to a separate Kubernetes secret containing the store password.</summary>
    public string StorePasswordPath { get; set; } = "";

    /// <summary>Indicates whether this certificate has an associated private key.</summary>
    public bool HasPrivateKey { get; set; } = false;

    /// <summary>Indicates whether the certificate/key is password protected.</summary>
    public bool HasPassword { get; set; } = false;

    /// <summary>
    /// BouncyCastle X509CertificateEntry containing the certificate
    /// </summary>
    public X509CertificateEntry CertificateEntry { get; set; }

    /// <summary>
    /// BouncyCastle X509CertificateEntry array containing the certificate chain
    /// </summary>
    public X509CertificateEntry[] CertificateEntryChain { get; set; }

    public byte[] Pkcs12 { get; set; }

    public List<string> ChainPem { get; set; }

    /// <summary>
    /// Optional: K8SCertificateContext providing BouncyCastle-based certificate operations.
    /// This property can be used for modern certificate handling without X509Certificate2 dependencies.
    /// </summary>
    public Models.K8SCertificateContext CertificateContext { get; set; }

    /// <summary>
    /// Factory method to create K8SCertificateContext from this job certificate's data
    /// </summary>
    /// <returns>K8SCertificateContext instance or null if certificate data is unavailable</returns>
    public Models.K8SCertificateContext GetCertificateContext()
    {
        if (CertificateEntry?.Certificate == null)
            return null;

        var context = new Models.K8SCertificateContext
        {
            Certificate = CertificateEntry.Certificate,
            CertPem = CertPem,
            PrivateKeyPem = PrivateKeyPem
        };

        // Add chain if available
        if (CertificateEntryChain != null && CertificateEntryChain.Length > 0)
        {
            context.Chain = CertificateEntryChain
                .Skip(1) // Skip the first one (leaf cert)
                .Select(entry => entry.Certificate)
                .ToList();

            if (ChainPem != null && ChainPem.Count > 0)
            {
                context.ChainPem = ChainPem.Skip(1).ToList();
            }
        }

        return context;
    }
}
