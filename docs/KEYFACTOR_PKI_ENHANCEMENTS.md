# Keyfactor.PKI Library Enhancement Proposals

This document identifies gaps in the `Keyfactor.PKI` library (v8.2.2) discovered during the k8s-orchestrator codebase cleanup. Each proposal includes the current workaround, the proposed API, and the orchestrator code that would be simplified.

## Context

The k8s-orchestrator extension handles certificate parsing, conversion, and private key export across 7 Kubernetes store types. It uses `Keyfactor.PKI` where possible but falls back to raw BouncyCastle for several common operations. These gaps likely affect other orchestrator extensions as well.

---

## Proposal 1: Unencrypted Private Key PEM Export (HIGH PRIORITY)

### Gap

`CryptographicObjectFormatter.PEM.Format(PrivateKeyConverter, string password)` only produces **encrypted** PEM output. There is no way to export an unencrypted private key in PEM format through the PKI library.

### Current Workaround

Every orchestrator that needs unencrypted PEM must use raw BouncyCastle:

```csharp
// PKCS#8 unencrypted PEM (what we do today)
var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
var privateKeyBytes = privateKeyInfo.ToAsn1Object().GetEncoded();
var pemObject = new PemObject("PRIVATE KEY", privateKeyBytes);
using var writer = new StringWriter();
var pemWriter = new PemWriter(writer);
pemWriter.WriteObject(pemObject);
return writer.ToString();

// PKCS#1 unencrypted PEM (what we do today)
using var writer = new StringWriter();
var pemWriter = new OpenSslPemWriter(writer);
pemWriter.WriteObject(privateKey); // writes RSA/EC/DSA PRIVATE KEY
return writer.ToString();
```

### Proposed API

```csharp
// Option A: Overload without password
CryptographicObjectFormatter.PEM.Format(PrivateKeyConverter privateKey);

// Option B: Format with explicit PKCS1/PKCS8 control
CryptographicObjectFormatter.PEM.Format(PrivateKeyConverter privateKey, bool usePkcs8);
```

### Impact

Would eliminate:
- `PrivateKeyFormatUtilities.ExportAsPkcs1Pem()` (13 lines)
- `PrivateKeyFormatUtilities.ExportAsPkcs8Pem()` (15 lines)
- `CertificateUtilities.ExtractPrivateKeyAsPem()` (24 lines)
- Similar code in other orchestrator extensions

### Files Affected in k8s-orchestrator
- `Utilities/PrivateKeyFormatUtilities.cs` (lines 119-171)
- `Utilities/CertificateUtilities.cs` (lines 450-475)
- `Clients/CertificateOperations.cs` (ExtractPrivateKeyAsPem method)

---

## Proposal 2: Certificate Chain Parsing from PEM (HIGH PRIORITY)

### Gap

`PemUtilities.SplitCollection(string)` splits a multi-certificate PEM string into individual PEM strings, but:
- Returns strings, not parsed `X509Certificate` objects
- **Throws** `ArgumentException` if private keys are present in the PEM data
- Requires a second parsing step to get usable certificate objects

### Current Workaround

Manual `PemReader` loop (duplicated in 2 places):

```csharp
var pemReader = new PemReader(new StringReader(pemData));
var certificates = new List<X509Certificate>();

PemObject pemObject;
while ((pemObject = pemReader.ReadPemObject()) != null)
    if (pemObject.Type == "CERTIFICATE")
    {
        var parser = new X509CertificateParser();
        certificates.Add(parser.ReadCertificate(pemObject.Content));
    }
```

### Proposed API

```csharp
// Parse multi-cert PEM directly to certificate objects, ignoring non-cert entries
public static List<X509Certificate> PemUtilities.ParseCertificateChain(string pemData);

// Or as an overload of SplitCollection that returns parsed objects
public static IEnumerable<X509Certificate> PemUtilities.ParseCertificates(string pemData);
```

### Key Behavior
- Should silently skip non-certificate PEM entries (private keys, CSRs, etc.)
- Should return empty list for null/empty input
- Should preserve certificate order

### Impact

Would eliminate:
- `CertificateUtilities.LoadCertificateChain()` (27 lines) - could become a one-liner
- The manual PemReader loop pattern used across orchestrator extensions

### Files Affected in k8s-orchestrator
- `Utilities/CertificateUtilities.cs` (lines 535-571)

---

## Proposal 3: Issuer CommonName Extension (MEDIUM PRIORITY)

### Gap

`BouncyCastleX509Extensions` provides `CommonName(X509Certificate)` for the **subject** but has no equivalent for the **issuer**.

### Current Workaround

Manual OID iteration:

```csharp
public static string GetIssuerCN(X509Certificate cert)
{
    var issuer = cert.IssuerDN;
    var oids = issuer.GetOidList();
    var values = issuer.GetValueList();
    for (var i = 0; i < oids.Count; i++)
        if (oids[i].ToString() == X509Name.CN.Id)
            return values[i].ToString();
    return string.Empty;
}
```

### Proposed API

```csharp
public static string BouncyCastleX509Extensions.IssuerCommonName(this X509Certificate cert);
```

### Impact

Would eliminate `CertificateUtilities.GetIssuerCN()` (12 lines) and similar manual OID parsing in other orchestrators.

### Files Affected in k8s-orchestrator
- `Utilities/CertificateUtilities.cs` (lines 275-291)

---

## Proposal 4: Algorithm Name from AsymmetricKeyParameter (MEDIUM PRIORITY)

### Gap

`BouncyCastleX509Extensions.GetKeyType(X509Certificate)` returns `EncryptionKeyType` (deprecated) and works only on certificates. There's no utility to get the algorithm name from a raw `AsymmetricKeyParameter`.

### Current Workaround

Type-switch pattern (duplicated 3 times):

```csharp
return privateKey switch
{
    RsaPrivateCrtKeyParameters => "RSA",
    ECPrivateKeyParameters => "EC",
    DsaPrivateKeyParameters => "DSA",
    Ed25519PrivateKeyParameters => "Ed25519",
    Ed448PrivateKeyParameters => "Ed448",
    _ => "Unknown"
};
```

### Proposed API

```csharp
// Extension method on AsymmetricKeyParameter
public static string GetAlgorithmName(this AsymmetricKeyParameter key);

// Should handle both public and private key types
// Return values: "RSA", "EC", "DSA", "Ed25519", "Ed448", etc.
```

### Additional Consideration

The existing `EncryptionKeyType` enum should be formally deprecated (or replaced) in favor of string-based algorithm names. The k8s-orchestrator already avoids `EncryptionKeyType` per code comments:
```csharp
// Use direct type checking instead of obsolete EncryptionKeyType enum
```

### Impact

Would eliminate:
- `PrivateKeyFormatUtilities.GetAlgorithmName()` (10 lines)
- `CertificateUtilities.GetKeyAlgorithm()` (15 lines)
- `CertificateUtilities.GetPrivateKeyType()` (10 lines)

### Files Affected in k8s-orchestrator
- `Utilities/PrivateKeyFormatUtilities.cs` (lines 98-109)
- `Utilities/CertificateUtilities.cs` (lines 350-366, 512-524)

---

## Proposal 5: Certificate Format Auto-Detection (LOW PRIORITY)

### Gap

No PKI utility for detecting whether binary data is PEM, DER, or PKCS12 format.

### Current Workaround

Header sniffing + trial parsing (30 lines):

```csharp
public static CertificateFormat DetectFormat(byte[] data)
{
    // Check for PEM "-----BEGIN"
    // Check ASN.1 sequence tag (0x30 0x82)
    // Try DER parse, fall back to PKCS12 parse
    // Return Unknown if nothing matches
}
```

### Proposed API

```csharp
public enum CertificateDataFormat { Unknown, Pem, Der, Pkcs12 }

public static CertificateDataFormat PemUtilities.DetectFormat(byte[] data);
// or
public static CertificateDataFormat CertificateFormatDetector.Detect(byte[] data);
```

### Impact

Would eliminate `CertificateUtilities.DetectFormat()` (50 lines) and the `CertificateFormat` enum definition.

### Files Affected in k8s-orchestrator
- `Utilities/CertificateUtilities.cs` (lines 26-32, 606-660)

---

## Implementation Plan

### Phase 1: High Priority (Proposals 1 & 2)

These have the broadest impact across the orchestrator ecosystem.

1. **Add unencrypted PEM export to `CryptographicObjectFormatter.PEM`**
   - Add `Format(PrivateKeyConverter)` overload (no password)
   - Add `Format(PrivateKeyConverter, bool usePkcs8)` overload
   - Ensure Ed25519/Ed448 keys always use PKCS8 (no PKCS1 representation)
   - Add unit tests for RSA, EC, DSA, Ed25519, Ed448 key types
   - Add unit tests verifying PKCS1 vs PKCS8 header correctness

2. **Add `ParseCertificates` to `PemUtilities`**
   - Add `ParseCertificates(string pemData) → List<X509Certificate>`
   - Silently skip non-certificate PEM entries
   - Return empty list for null/empty input
   - Add unit tests: single cert, multi-cert chain, mixed cert+key, empty input

### Phase 2: Medium Priority (Proposals 3 & 4)

Small, self-contained additions.

3. **Add `IssuerCommonName` extension**
   - Add to `BouncyCastleX509Extensions`
   - Mirror the `CommonName()` implementation but against `IssuerDN`
   - Add unit tests with various issuer DN formats

4. **Add `GetAlgorithmName(AsymmetricKeyParameter)` extension**
   - New extension method (or static utility)
   - Support both public and private key parameter types
   - Return string names: "RSA", "EC", "DSA", "Ed25519", "Ed448"
   - Consider deprecating `EncryptionKeyType` enum or adding `[Obsolete]` attribute
   - Add unit tests for each key type

### Phase 3: Low Priority (Proposal 5)

5. **Add certificate format detection**
   - Add `DetectFormat(byte[])` utility
   - PEM detection: check for "-----BEGIN" header
   - DER detection: try `X509CertificateParser.ReadCertificate`
   - PKCS12 detection: try `Pkcs12StoreBuilder` load
   - Add unit tests with various formats and edge cases

### Migration Path for k8s-orchestrator

After each PKI release:

1. Update `Keyfactor.PKI` package version in `.csproj`
2. Replace local implementations with PKI calls:
   - Phase 1: Simplify `PrivateKeyFormatUtilities` exports + `CertificateUtilities.LoadCertificateChain`
   - Phase 2: Replace `GetIssuerCN` + `GetAlgorithmName`/`GetKeyAlgorithm`/`GetPrivateKeyType`
   - Phase 3: Replace `DetectFormat` + remove local `CertificateFormat` enum
3. Run full test suite to verify behavioral equivalence
4. Remove dead local implementations
