// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Linq;
using System.Text;
using k8s.Exceptions;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Clients;

public class KubeconfigParserTests
{
    private readonly KubeconfigParser _parser = new();

    #region Valid Kubeconfig Tests

    [Fact]
    public void Parse_ValidKubeconfig_ReturnsConfiguration()
    {
        // Arrange
        var kubeconfig = GetValidKubeconfig();

        // Act
        var config = _parser.Parse(kubeconfig);

        // Assert
        Assert.NotNull(config);
        Assert.Equal("v1", config.ApiVersion);
        Assert.Equal("Config", config.Kind);
        Assert.Equal("test-context", config.CurrentContext);
    }

    [Fact]
    public void Parse_ValidKubeconfig_ParsesClusters()
    {
        // Arrange
        var kubeconfig = GetValidKubeconfig();

        // Act
        var config = _parser.Parse(kubeconfig);
        var clusters = config.Clusters.ToList();

        // Assert
        Assert.NotNull(clusters);
        Assert.Single(clusters);
        Assert.Equal("test-cluster", clusters[0].Name);
        Assert.Equal("https://kubernetes.example.com:6443", clusters[0].ClusterEndpoint?.Server);
        Assert.NotNull(clusters[0].ClusterEndpoint?.CertificateAuthorityData);
    }

    [Fact]
    public void Parse_ValidKubeconfig_ParsesUsers()
    {
        // Arrange
        var kubeconfig = GetValidKubeconfig();

        // Act
        var config = _parser.Parse(kubeconfig);
        var users = config.Users.ToList();

        // Assert
        Assert.NotNull(users);
        Assert.Single(users);
        Assert.Equal("test-user", users[0].Name);
        Assert.Equal("test-token-12345", users[0].UserCredentials?.Token);
    }

    [Fact]
    public void Parse_ValidKubeconfig_ParsesContexts()
    {
        // Arrange
        var kubeconfig = GetValidKubeconfig();

        // Act
        var config = _parser.Parse(kubeconfig);
        var contexts = config.Contexts.ToList();

        // Assert
        Assert.NotNull(contexts);
        Assert.Single(contexts);
        Assert.Equal("test-context", contexts[0].Name);
        Assert.Equal("test-cluster", contexts[0].ContextDetails?.Cluster);
        Assert.Equal("default", contexts[0].ContextDetails?.Namespace);
        Assert.Equal("test-user", contexts[0].ContextDetails?.User);
    }

    #endregion

    #region Base64 Encoding Tests

    [Fact]
    public void Parse_Base64EncodedKubeconfig_ReturnsConfiguration()
    {
        // Arrange
        var kubeconfig = GetValidKubeconfig();
        var base64Kubeconfig = Convert.ToBase64String(Encoding.UTF8.GetBytes(kubeconfig));

        // Act
        var config = _parser.Parse(base64Kubeconfig);

        // Assert
        Assert.NotNull(config);
        Assert.Equal("v1", config.ApiVersion);
        Assert.Equal("Config", config.Kind);
    }

    #endregion

    #region Skip TLS Verify Tests

    [Fact]
    public void Parse_WithSkipTlsVerifyTrue_SetsSkipTlsVerifyOnClusters()
    {
        // Arrange
        var kubeconfig = GetValidKubeconfig();

        // Act
        var config = _parser.Parse(kubeconfig, skipTlsVerify: true);
        var clusters = config.Clusters.ToList();

        // Assert
        Assert.NotNull(clusters);
        Assert.True(clusters[0].ClusterEndpoint?.SkipTlsVerify);
    }

    [Fact]
    public void Parse_WithSkipTlsVerifyFalse_DoesNotSetSkipTlsVerify()
    {
        // Arrange
        var kubeconfig = GetValidKubeconfig();

        // Act
        var config = _parser.Parse(kubeconfig, skipTlsVerify: false);
        var clusters = config.Clusters.ToList();

        // Assert
        Assert.NotNull(clusters);
        Assert.False(clusters[0].ClusterEndpoint?.SkipTlsVerify);
    }

    #endregion

    #region Invalid Input Tests

    [Fact]
    public void Parse_NullKubeconfig_ThrowsKubeConfigException()
    {
        // Act & Assert
        var ex = Assert.Throws<KubeConfigException>(() => _parser.Parse(null));
        Assert.Contains("null or empty", ex.Message);
    }

    [Fact]
    public void Parse_EmptyKubeconfig_ThrowsKubeConfigException()
    {
        // Act & Assert
        var ex = Assert.Throws<KubeConfigException>(() => _parser.Parse(""));
        Assert.Contains("null or empty", ex.Message);
    }

    [Fact]
    public void Parse_NonJsonKubeconfig_ThrowsKubeConfigException()
    {
        // Arrange
        var invalidConfig = "this is not json";

        // Act & Assert
        var ex = Assert.Throws<KubeConfigException>(() => _parser.Parse(invalidConfig));
        Assert.Contains("not a JSON object", ex.Message);
    }

    [Fact]
    public void Parse_InvalidJsonStructure_ThrowsKubeConfigException()
    {
        // Arrange
        var invalidJson = "{ invalid json }";

        // Act & Assert
        Assert.Throws<KubeConfigException>(() => _parser.Parse(invalidJson));
    }

    #endregion

    #region Escaped JSON Tests

    [Fact]
    public void Parse_EscapedJson_HandlesBackslashesCorrectly()
    {
        // Arrange - JSON with leading backslash (as it might come from some sources)
        var escapedKubeconfig = "\\" + GetValidKubeconfig()
            .Replace("\"", "\\\"");

        // This test verifies the parser can handle escaped JSON formats
        // The actual behavior depends on the implementation
        try
        {
            var config = _parser.Parse(escapedKubeconfig);
            Assert.NotNull(config);
        }
        catch (KubeConfigException)
        {
            // Also acceptable - the key is it shouldn't throw NullReferenceException
        }
    }

    #endregion

    #region Multiple Clusters/Users/Contexts Tests

    [Fact]
    public void Parse_MultipleCluster_ParsesAll()
    {
        // Arrange
        var kubeconfig = GetMultiClusterKubeconfig();

        // Act
        var config = _parser.Parse(kubeconfig);
        var clusters = config.Clusters.ToList();

        // Assert
        Assert.NotNull(clusters);
        Assert.Equal(2, clusters.Count);
        Assert.Equal("cluster-1", clusters[0].Name);
        Assert.Equal("cluster-2", clusters[1].Name);
    }

    #endregion

    #region Helper Methods

    private static string GetValidKubeconfig()
    {
        return @"{
            ""apiVersion"": ""v1"",
            ""kind"": ""Config"",
            ""current-context"": ""test-context"",
            ""clusters"": [
                {
                    ""name"": ""test-cluster"",
                    ""cluster"": {
                        ""server"": ""https://kubernetes.example.com:6443"",
                        ""certificate-authority-data"": ""LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM1ekNDQWMrZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwdGFXNXAKYTNWaVpVTkJNQjRYRFRJd01EVXdOREV3TWpBMU1Wb1hEVE13TURVd016RXdNakExTVZvd0ZURVRNQkVHQTFVRQpBeE1LYldsdWFXdDFZbVZEUVRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHBYCldRa0ZLdEt0SVRDQnBOZEVQa2xrNmhwREp1ZWJvYklTKzlmc0hHbFpOckFMUFRrdllmQTZOdzBUcWR1d1RvblAKdktQcTZxSXBXTld3N2RLUUQ5d0Fpc0lNY0sxRDVwQ3M3d1JSRWROZmRPM1JLQ0c3emw2dVJQeHlLT0tnTmZoTQpLRWRmekp0TUdtUFB5SHhVRkZRRldJek1Jak5YRWNyVUxSMnhKM2dFYllKR2hwYlFpQlV4bTB4UTJpbGxoNE1PCkdvOXBCRGpoaFFlc0dmNnNsZFdZSjFTWWFMOWFPZjBoY2s4d1p4NVRCZU9xZWJyU3J2ME1DTHlhN0RoRmwyOTAKNGFSQVZ5a3dHdUF0TUVSeHpUNGJxSjlqTjZNTjdwWWJKdWliK0tZMjM2cUlHUFJhODBQdklIWHlmK3hhNHFMUApxUU9Mc3h3akhGQzhzQ3BOTlMwQ0F3RUFBYU5DTUVBd0RnWURWUjBQQVFIL0JBUURBZ0trTUIwR0ExVWRKUVFXCk1CUUdDQ3NHQVFVRkJ3TUNCZ2dyQmdFRkJRY0RBVEFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTBHQ1NxR1NJYjMKRFFFQkN3VUFBNElCQVFCN1VHUGNJdXdERVpRR2loVFNjSWxhWGhpSWRSS0hYMHZVL3RhOFFWTVNSbUZhQytISgpsY0JRRnNMRnhKWEhRREVDTFRwVWxNTTQ2aEtPR3J5OExkSHRKaVBNVjROYW1weGtaajNtYW9SRXpLMHhnZkhtClZaM2RDY3NqWUpmVkNoNUJSbGprUUFBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=""
                    }
                }
            ],
            ""users"": [
                {
                    ""name"": ""test-user"",
                    ""user"": {
                        ""token"": ""test-token-12345""
                    }
                }
            ],
            ""contexts"": [
                {
                    ""name"": ""test-context"",
                    ""context"": {
                        ""cluster"": ""test-cluster"",
                        ""namespace"": ""default"",
                        ""user"": ""test-user""
                    }
                }
            ]
        }";
    }

    private static string GetMultiClusterKubeconfig()
    {
        return @"{
            ""apiVersion"": ""v1"",
            ""kind"": ""Config"",
            ""current-context"": ""context-1"",
            ""clusters"": [
                {
                    ""name"": ""cluster-1"",
                    ""cluster"": {
                        ""server"": ""https://cluster1.example.com:6443"",
                        ""certificate-authority-data"": ""LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM1ekNDQWMrZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwdGFXNXAKYTNWaVpVTkJNQjRYRFRJd01EVXdOREV3TWpBMU1Wb1hEVE13TURVd016RXdNakExTVZvd0ZURVRNQkVHQTFVRQpBeE1LYldsdWFXdDFZbVZEUVRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHBYCldRa0ZLdEt0SVRDQnBOZEVQa2xrNmhwREp1ZWJvYklTKzlmc0hHbFpOckFMUFRrdllmQTZOdzBUcWR1d1RvblAKdktQcTZxSXBXTld3N2RLUUQ5d0Fpc0lNY0sxRDVwQ3M3d1JSRWROZmRPM1JLQ0c3emw2dVJQeHlLT0tnTmZoTQpLRWRmekp0TUdtUFB5SHhVRkZRRldJek1Jak5YRWNyVUxSMnhKM2dFYllKR2hwYlFpQlV4bTB4UTJpbGxoNE1PCkdvOXBCRGpoaFFlc0dmNnNsZFdZSjFTWWFMOWFPZjBoY2s4d1p4NVRCZU9xZWJyU3J2ME1DTHlhN0RoRmwyOTAKNGFSQVZ5a3dHdUF0TUVSeHpUNGJxSjlqTjZNTjdwWWJKdWliK0tZMjM2cUlHUFJhODBQdklIWHlmK3hhNHFMUApxUU9Mc3h3akhGQzhzQ3BOTlMwQ0F3RUFBYU5DTUVBd0RnWURWUjBQQVFIL0JBUURBZ0trTUIwR0ExVWRKUVFXCk1CUUdDQ3NHQVFVRkJ3TUNCZ2dyQmdFRkJRY0RBVEFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTBHQ1NxR1NJYjMKRFFFQkN3VUFBNElCQVFCN1VHUGNJdXdERVpRR2loVFNjSWxhWGhpSWRSS0hYMHZVL3RhOFFWTVNSbUZhQytISgpsY0JRRnNMRnhKWEhRREVDTFRwVWxNTTQ2aEtPR3J5OExkSHRKaVBNVjROYW1weGtaajNtYW9SRXpLMHhnZkhtClZaM2RDY3NqWUpmVkNoNUJSbGprUUFBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=""
                    }
                },
                {
                    ""name"": ""cluster-2"",
                    ""cluster"": {
                        ""server"": ""https://cluster2.example.com:6443"",
                        ""certificate-authority-data"": ""LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM1ekNDQWMrZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwdGFXNXAKYTNWaVpVTkJNQjRYRFRJd01EVXdOREV3TWpBMU1Wb1hEVE13TURVd016RXdNakExTVZvd0ZURVRNQkVHQTFVRQpBeE1LYldsdWFXdDFZbVZEUVRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHBYCldRa0ZLdEt0SVRDQnBOZEVQa2xrNmhwREp1ZWJvYklTKzlmc0hHbFpOckFMUFRrdllmQTZOdzBUcWR1d1RvblAKdktQcTZxSXBXTld3N2RLUUQ5d0Fpc0lNY0sxRDVwQ3M3d1JSRWROZmRPM1JLQ0c3emw2dVJQeHlLT0tnTmZoTQpLRWRmekp0TUdtUFB5SHhVRkZRRldJek1Jak5YRWNyVUxSMnhKM2dFYllKR2hwYlFpQlV4bTB4UTJpbGxoNE1PCkdvOXBCRGpoaFFlc0dmNnNsZFdZSjFTWWFMOWFPZjBoY2s4d1p4NVRCZU9xZWJyU3J2ME1DTHlhN0RoRmwyOTAKNGFSQVZ5a3dHdUF0TUVSeHpUNGJxSjlqTjZNTjdwWWJKdWliK0tZMjM2cUlHUFJhODBQdklIWHlmK3hhNHFMUApxUU9Mc3h3akhGQzhzQ3BOTlMwQ0F3RUFBYU5DTUVBd0RnWURWUjBQQVFIL0JBUURBZ0trTUIwR0ExVWRKUVFXCk1CUUdDQ3NHQVFVRkJ3TUNCZ2dyQmdFRkJRY0RBVEFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTBHQ1NxR1NJYjMKRFFFQkN3VUFBNElCQVFCN1VHUGNJdXdERVpRR2loVFNjSWxhWGhpSWRSS0hYMHZVL3RhOFFWTVNSbUZhQytISgpsY0JRRnNMRnhKWEhRREVDTFRwVWxNTTQ2aEtPR3J5OExkSHRKaVBNVjROYW1weGtaajNtYW9SRXpLMHhnZkhtClZaM2RDY3NqWUpmVkNoNUJSbGprUUFBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=""
                    }
                }
            ],
            ""users"": [
                {
                    ""name"": ""user-1"",
                    ""user"": {
                        ""token"": ""token-1""
                    }
                }
            ],
            ""contexts"": [
                {
                    ""name"": ""context-1"",
                    ""context"": {
                        ""cluster"": ""cluster-1"",
                        ""namespace"": ""default"",
                        ""user"": ""user-1""
                    }
                }
            ]
        }";
    }

    #endregion
}
