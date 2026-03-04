namespace Keyfactor.Extensions.Orchestrator.K8S.Enums;

/// <summary>
/// Specifies the format for private key PEM encoding.
/// </summary>
public enum PrivateKeyFormat
{
    /// <summary>
    /// PKCS#8 format (BEGIN PRIVATE KEY) - Supports all key types including Ed25519/Ed448.
    /// This is the default format.
    /// </summary>
    Pkcs8,

    /// <summary>
    /// PKCS#1/SEC1 format (BEGIN RSA/EC PRIVATE KEY) - Traditional format for RSA/EC keys.
    /// Not supported for Ed25519/Ed448 keys.
    /// </summary>
    Pkcs1
}
