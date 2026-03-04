// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Helpers;

/// <summary>
/// Thread-safe cached certificate provider that eliminates redundant certificate generation
/// during test execution. Certificates are cached by key type and subject CN for reuse
/// across read-only tests (Inventory, Discovery).
/// </summary>
public static class CachedCertificateProvider
{
    private static readonly ConcurrentDictionary<string, CertificateInfo> _certificateCache = new();
    private static readonly ConcurrentDictionary<string, List<CertificateInfo>> _chainCache = new();
    private static readonly object _chainLock = new();

    /// <summary>
    /// Gets or creates a cached certificate with the specified key type and subject CN.
    /// Thread-safe for concurrent access from parallel tests.
    /// </summary>
    /// <param name="keyType">The type of cryptographic key to use</param>
    /// <param name="subjectCN">The subject common name for the certificate</param>
    /// <returns>A cached or newly generated CertificateInfo</returns>
    public static CertificateInfo GetOrCreate(KeyType keyType, string subjectCN = "Cached Test Certificate")
    {
        var cacheKey = $"{keyType}:{subjectCN}";
        return _certificateCache.GetOrAdd(cacheKey, _ =>
            CertificateTestHelper.GenerateCertificate(keyType, subjectCN));
    }

    /// <summary>
    /// Gets or creates a cached certificate chain (leaf -> intermediate -> root) with the specified key type.
    /// Thread-safe for concurrent access from parallel tests.
    /// </summary>
    /// <param name="keyType">The type of cryptographic key to use for all certificates in the chain</param>
    /// <param name="leafCN">Optional leaf certificate CN (default: "Leaf Certificate")</param>
    /// <returns>A cached or newly generated certificate chain (leaf at index 0, root at last index)</returns>
    public static List<CertificateInfo> GetOrCreateChain(KeyType keyType, string leafCN = "Cached Leaf Certificate")
    {
        var cacheKey = $"chain:{keyType}:{leafCN}";

        // Use double-checked locking for chain generation since it's more expensive
        if (_chainCache.TryGetValue(cacheKey, out var existingChain))
        {
            return existingChain;
        }

        lock (_chainLock)
        {
            // Check again after acquiring lock
            if (_chainCache.TryGetValue(cacheKey, out existingChain))
            {
                return existingChain;
            }

            var newChain = CertificateTestHelper.GenerateCertificateChain(
                keyType,
                leafCN,
                $"Intermediate CA ({keyType})",
                $"Root CA ({keyType})");

            _chainCache[cacheKey] = newChain;
            return newChain;
        }
    }

    /// <summary>
    /// Gets a pre-generated PKCS12 byte array for the specified key type.
    /// Useful for management tests that need PKCS12 format.
    /// </summary>
    /// <param name="keyType">The type of cryptographic key to use</param>
    /// <param name="password">The password for the PKCS12 store</param>
    /// <param name="alias">The alias for the certificate entry</param>
    /// <returns>PKCS12 byte array containing the cached certificate</returns>
    public static byte[] GetOrCreatePkcs12(KeyType keyType, string password = "testpassword", string alias = "testcert")
    {
        var certInfo = GetOrCreate(keyType);
        return CertificateTestHelper.GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, password, alias);
    }

    /// <summary>
    /// Clears all cached certificates. Should be called between test collections
    /// if memory pressure becomes an issue, or in fixture disposal.
    /// </summary>
    public static void ClearCache()
    {
        _certificateCache.Clear();
        lock (_chainLock)
        {
            _chainCache.Clear();
        }
    }

    /// <summary>
    /// Gets the current cache statistics for debugging/monitoring.
    /// </summary>
    /// <returns>Tuple of (certificate count, chain count)</returns>
    public static (int CertificateCount, int ChainCount) GetCacheStats()
    {
        return (_certificateCache.Count, _chainCache.Count);
    }
}
