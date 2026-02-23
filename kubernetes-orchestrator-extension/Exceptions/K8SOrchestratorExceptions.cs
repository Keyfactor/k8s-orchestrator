// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;

namespace Keyfactor.Extensions.Orchestrator.K8S.Exceptions;

/// <summary>
/// Base exception class for all Kubernetes orchestrator exceptions.
/// Provides common properties for operation context and error tracking.
/// </summary>
public abstract class K8SOrchestratorException : Exception
{
    /// <summary>
    /// The type of operation being performed when the exception occurred.
    /// </summary>
    public string OperationType { get; }

    /// <summary>
    /// The store path being accessed when the exception occurred.
    /// </summary>
    public string StorePath { get; }

    /// <summary>
    /// The Kubernetes namespace involved in the operation (if applicable).
    /// </summary>
    public string Namespace { get; }

    /// <summary>
    /// The Kubernetes secret name involved in the operation (if applicable).
    /// </summary>
    public string SecretName { get; }

    /// <summary>
    /// Creates a new K8SOrchestratorException.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="operationType">The operation type (e.g., "Inventory", "Management").</param>
    /// <param name="storePath">The store path being accessed.</param>
    /// <param name="namespace">The Kubernetes namespace (optional).</param>
    /// <param name="secretName">The Kubernetes secret name (optional).</param>
    /// <param name="innerException">The inner exception (optional).</param>
    protected K8SOrchestratorException(
        string message,
        string operationType = "",
        string storePath = "",
        string @namespace = "",
        string secretName = "",
        Exception innerException = null)
        : base(message, innerException)
    {
        OperationType = operationType;
        StorePath = storePath;
        Namespace = @namespace;
        SecretName = secretName;
    }
}

/// <summary>
/// Exception thrown when a certificate store cannot be found in Kubernetes.
/// </summary>
public class StoreNotFoundException : Exception
{
    /// <summary>Initializes a new instance of StoreNotFoundException.</summary>
    public StoreNotFoundException()
    {
    }

    /// <summary>Initializes a new instance with the specified error message.</summary>
    /// <param name="message">The error message describing the missing store.</param>
    public StoreNotFoundException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with the specified error message and inner exception.</summary>
    /// <param name="message">The error message describing the missing store.</param>
    /// <param name="innerException">The exception that caused this exception.</param>
    public StoreNotFoundException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a Kubernetes secret is invalid, malformed, or missing required fields.
/// </summary>
public class InvalidK8SSecretException : Exception
{
    /// <summary>Initializes a new instance of InvalidK8SSecretException.</summary>
    public InvalidK8SSecretException()
    {
    }

    /// <summary>Initializes a new instance with the specified error message.</summary>
    /// <param name="message">The error message describing the invalid secret.</param>
    public InvalidK8SSecretException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with the specified error message and inner exception.</summary>
    /// <param name="message">The error message describing the invalid secret.</param>
    /// <param name="innerException">The exception that caused this exception.</param>
    public InvalidK8SSecretException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a Kubernetes secret has invalid or malformed data.
/// </summary>
public class InvalidSecretException : K8SOrchestratorException
{
    /// <summary>
    /// The field name that contained invalid data (if applicable).
    /// </summary>
    public string FieldName { get; }

    /// <summary>
    /// Creates a new InvalidSecretException.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="namespace">The Kubernetes namespace.</param>
    /// <param name="secretName">The secret name.</param>
    /// <param name="fieldName">The specific field that is invalid (optional).</param>
    /// <param name="innerException">The inner exception (optional).</param>
    public InvalidSecretException(
        string message,
        string @namespace = "",
        string secretName = "",
        string fieldName = "",
        Exception innerException = null)
        : base(message, "Parse", "", @namespace, secretName, innerException)
    {
        FieldName = fieldName;
    }
}

/// <summary>
/// Exception thrown when certificate data cannot be parsed or is malformed.
/// </summary>
public class CertificateParseException : K8SOrchestratorException
{
    /// <summary>
    /// The certificate thumbprint or alias being processed (if known).
    /// </summary>
    public string CertificateIdentifier { get; }

    /// <summary>
    /// Creates a new CertificateParseException.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="certificateIdentifier">The certificate thumbprint or alias.</param>
    /// <param name="innerException">The inner exception (optional).</param>
    public CertificateParseException(
        string message,
        string certificateIdentifier = "",
        Exception innerException = null)
        : base(message, "Parse", innerException: innerException)
    {
        CertificateIdentifier = certificateIdentifier;
    }
}

/// <summary>
/// Exception thrown when a password cannot be retrieved from its configured location.
/// </summary>
public class PasswordRetrievalException : K8SOrchestratorException
{
    /// <summary>
    /// The path to the password secret that failed.
    /// </summary>
    public string PasswordPath { get; }

    /// <summary>
    /// Creates a new PasswordRetrievalException.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="passwordPath">The path to the password secret.</param>
    /// <param name="innerException">The inner exception (optional).</param>
    public PasswordRetrievalException(
        string message,
        string passwordPath = "",
        Exception innerException = null)
        : base(message, "PasswordRetrieval", innerException: innerException)
    {
        PasswordPath = passwordPath;
    }
}

/// <summary>
/// Exception thrown when an unsupported store type is encountered.
/// </summary>
public class UnsupportedStoreTypeException : K8SOrchestratorException
{
    /// <summary>
    /// The unsupported store type.
    /// </summary>
    public StoreType UnsupportedType { get; }

    /// <summary>
    /// The string representation of the unsupported type (if enum is Unknown).
    /// </summary>
    public string TypeString { get; }

    /// <summary>
    /// Creates a new UnsupportedStoreTypeException.
    /// </summary>
    /// <param name="storeType">The unsupported store type.</param>
    /// <param name="operationType">The operation that was attempted.</param>
    public UnsupportedStoreTypeException(StoreType storeType, string operationType = "")
        : base($"Store type '{storeType}' is not supported for operation '{operationType}'.", operationType)
    {
        UnsupportedType = storeType;
        TypeString = storeType.ToString();
    }

    /// <summary>
    /// Creates a new UnsupportedStoreTypeException from a string type.
    /// </summary>
    /// <param name="typeString">The string representation of the unsupported type.</param>
    /// <param name="operationType">The operation that was attempted.</param>
    public UnsupportedStoreTypeException(string typeString, string operationType = "")
        : base($"Store type '{typeString}' is not supported for operation '{operationType}'.", operationType)
    {
        UnsupportedType = StoreType.Unknown;
        TypeString = typeString;
    }
}

/// <summary>
/// Exception thrown when a certificate alias format is invalid.
/// </summary>
public class AliasFormatException : K8SOrchestratorException
{
    /// <summary>
    /// The invalid alias that was provided.
    /// </summary>
    public string InvalidAlias { get; }

    /// <summary>
    /// The expected alias format.
    /// </summary>
    public string ExpectedFormat { get; }

    /// <summary>
    /// Creates a new AliasFormatException.
    /// </summary>
    /// <param name="invalidAlias">The invalid alias.</param>
    /// <param name="expectedFormat">The expected format description.</param>
    /// <param name="storeType">The store type (for context).</param>
    public AliasFormatException(string invalidAlias, string expectedFormat, StoreType storeType = StoreType.Unknown)
        : base($"Invalid alias format '{invalidAlias}' for store type '{storeType}'. Expected format: {expectedFormat}")
    {
        InvalidAlias = invalidAlias;
        ExpectedFormat = expectedFormat;
    }
}

/// <summary>
/// Exception thrown when configuration is missing or invalid.
/// </summary>
public class ConfigurationException : K8SOrchestratorException
{
    /// <summary>
    /// The name of the missing or invalid configuration property.
    /// </summary>
    public string PropertyName { get; }

    /// <summary>
    /// Creates a new ConfigurationException.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="propertyName">The missing or invalid property name.</param>
    /// <param name="innerException">The inner exception (optional).</param>
    public ConfigurationException(
        string message,
        string propertyName = "",
        Exception innerException = null)
        : base(message, "Configuration", innerException: innerException)
    {
        PropertyName = propertyName;
    }
}

/// <summary>
/// Exception thrown when a Kubernetes API operation fails.
/// </summary>
public class KubernetesApiException : K8SOrchestratorException
{
    /// <summary>
    /// The HTTP status code returned by the API (if applicable).
    /// </summary>
    public int? StatusCode { get; }

    /// <summary>
    /// Creates a new KubernetesApiException.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="operationType">The operation that failed.</param>
    /// <param name="namespace">The Kubernetes namespace.</param>
    /// <param name="secretName">The secret name.</param>
    /// <param name="statusCode">The HTTP status code (optional).</param>
    /// <param name="innerException">The inner exception (optional).</param>
    public KubernetesApiException(
        string message,
        string operationType = "",
        string @namespace = "",
        string secretName = "",
        int? statusCode = null,
        Exception innerException = null)
        : base(message, operationType, "", @namespace, secretName, innerException)
    {
        StatusCode = statusCode;
    }
}
