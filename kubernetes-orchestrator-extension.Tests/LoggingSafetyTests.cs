// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Xunit;

namespace Keyfactor.Extensions.Orchestrator.K8S.Tests
{
    /// <summary>
    /// Tests to ensure sensitive data is never logged
    /// </summary>
    public class LoggingSafetyTests
    {
        private readonly string _projectRoot;

        public LoggingSafetyTests()
        {
            // Get the project root directory
            var currentDir = Directory.GetCurrentDirectory();
            _projectRoot = Path.GetFullPath(Path.Combine(currentDir, "..", "..", "..", ".."));
        }

        [Fact]
        public void SourceCode_ShouldNotContain_DirectPasswordLogging()
        {
            // Arrange
            var sourceFiles = Directory.GetFiles(
                Path.Combine(_projectRoot, "kubernetes-orchestrator-extension"),
                "*.cs",
                SearchOption.AllDirectories
            ).Where(f => !f.Contains("obj") && !f.Contains("bin")).ToList();

            var violations = new System.Collections.Generic.List<string>();

            // Define patterns that indicate insecure password logging
            var insecurePatterns = new[]
            {
                // Direct password logging without redaction (but not correlation IDs or redaction calls)
                @"Logger\.Log.*[Pp]assword[^,]*,\s*[^""]*\b(password|Password|passwd|storePassword|StorePassword|pKeyPassword|keyPasswordStr|KubeSecretPassword)\b\s*\)",
                // TODO comments marked as insecure
                @"TODO.*[Ii]nsecure",
                @"TODO.*[Rr]emove.*insecure"
            };

            // Act
            foreach (var file in sourceFiles)
            {
                var content = File.ReadAllText(file);
                var lines = content.Split('\n');

                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];

                    // Skip if line is commented out
                    if (line.TrimStart().StartsWith("//"))
                        continue;

                    // Skip if line uses LoggingUtilities.RedactPassword
                    if (line.Contains("LoggingUtilities.RedactPassword"))
                        continue;

                    foreach (var pattern in insecurePatterns)
                    {
                        if (Regex.IsMatch(line, pattern, RegexOptions.IgnoreCase))
                        {
                            violations.Add($"{Path.GetFileName(file)}:{i + 1}: {line.Trim()}");
                        }
                    }
                }
            }

            // Assert
            Assert.Empty(violations);
        }

        [Fact]
        public void SourceCode_ShouldNotContain_DirectPrivateKeyLogging()
        {
            // Arrange
            var sourceFiles = Directory.GetFiles(
                Path.Combine(_projectRoot, "kubernetes-orchestrator-extension"),
                "*.cs",
                SearchOption.AllDirectories
            ).Where(f => !f.Contains("obj") && !f.Contains("bin")).ToList();

            var violations = new System.Collections.Generic.List<string>();

            // Define patterns that indicate insecure private key logging
            var insecurePatterns = new[]
            {
                // Direct private key variable logging (actual key objects, not boolean flags or method names)
                @"Logger\.Log.*,\s*\bprivateKey\b\s*\)",
                @"Logger\.Log.*,\s*\bPrivateKey\b\s*\)",
                @"Logger\.Log.*,\s*\bpKey\b\s*\)",
                // Logging PEM keys directly
                @"Logger\.Log.*BEGIN PRIVATE KEY"
            };

            // Act
            foreach (var file in sourceFiles)
            {
                var content = File.ReadAllText(file);
                var lines = content.Split('\n');

                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];

                    // Skip if line is commented out
                    if (line.TrimStart().StartsWith("//"))
                        continue;

                    // Skip if line uses LoggingUtilities redaction
                    if (line.Contains("LoggingUtilities.RedactPrivateKey") ||
                        line.Contains("LoggingUtilities.GetCertificateSummary"))
                        continue;

                    foreach (var pattern in insecurePatterns)
                    {
                        if (Regex.IsMatch(line, pattern, RegexOptions.IgnoreCase))
                        {
                            violations.Add($"{Path.GetFileName(file)}:{i + 1}: {line.Trim()}");
                        }
                    }
                }
            }

            // Assert
            Assert.Empty(violations);
        }

        [Fact]
        public void SourceCode_ShouldNotContain_DirectTokenLogging()
        {
            // Arrange
            var sourceFiles = Directory.GetFiles(
                Path.Combine(_projectRoot, "kubernetes-orchestrator-extension"),
                "*.cs",
                SearchOption.AllDirectories
            ).Where(f => !f.Contains("obj") && !f.Contains("bin")).ToList();

            var violations = new System.Collections.Generic.List<string>();

            // Define patterns that indicate insecure token logging
            var insecurePatterns = new[]
            {
                // Direct token logging
                @"Logger\.Log.*[Tt]oken[^,]*,\s*[^L][^o][^g][^g][^i][^n][^g].*\)"
            };

            // Act
            foreach (var file in sourceFiles)
            {
                var content = File.ReadAllText(file);
                var lines = content.Split('\n');

                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];

                    // Skip if line is commented out
                    if (line.TrimStart().StartsWith("//"))
                        continue;

                    // Skip if line uses LoggingUtilities.RedactToken
                    if (line.Contains("LoggingUtilities.RedactToken"))
                        continue;

                    foreach (var pattern in insecurePatterns)
                    {
                        if (Regex.IsMatch(line, pattern, RegexOptions.IgnoreCase))
                        {
                            violations.Add($"{Path.GetFileName(file)}:{i + 1}: {line.Trim()}");
                        }
                    }
                }
            }

            // Assert
            Assert.Empty(violations);
        }

        [Fact]
        public void NoTodoInsecureCommentsRemain()
        {
            // Arrange
            var sourceFiles = Directory.GetFiles(
                Path.Combine(_projectRoot, "kubernetes-orchestrator-extension"),
                "*.cs",
                SearchOption.AllDirectories
            ).Where(f => !f.Contains("obj") && !f.Contains("bin")).ToList();

            var violations = new System.Collections.Generic.List<string>();

            // Act
            foreach (var file in sourceFiles)
            {
                var content = File.ReadAllText(file);
                var lines = content.Split('\n');

                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];

                    // Check for TODO comments marked as insecure
                    if (Regex.IsMatch(line, @"TODO.*[Ii]nsecure", RegexOptions.IgnoreCase) ||
                        Regex.IsMatch(line, @"TODO.*[Rr]emove.*insecure", RegexOptions.IgnoreCase))
                    {
                        violations.Add($"{Path.GetFileName(file)}:{i + 1}: {line.Trim()}");
                    }
                }
            }

            // Assert
            Assert.Empty(violations);
        }

        [Fact]
        public void LoggingUtilities_RedactPassword_ShouldNotRevealPassword()
        {
            // Arrange
            var testPassword = "MySecretPassword123!";

            // Act
            var redacted = LoggingUtilities.RedactPassword(testPassword);

            // Assert
            Assert.DoesNotContain("MySecretPassword", redacted);
            Assert.DoesNotContain("123!", redacted);
            Assert.DoesNotContain(testPassword.Length.ToString(), redacted);
            Assert.Contains("REDACTED", redacted);
        }

        [Fact]
        public void LoggingUtilities_RedactPrivateKeyPem_ShouldNotRevealKeyMaterial()
        {
            // Arrange
            var testKeyPem = @"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----";

            // Act
            var redacted = LoggingUtilities.RedactPrivateKeyPem(testKeyPem);

            // Assert
            Assert.DoesNotContain("MIIEpAIBAAKCAQEA", redacted);
            Assert.DoesNotContain("1234567890", redacted);
            Assert.Contains("REDACTED", redacted);
            Assert.Contains("RSA", redacted);
        }

        [Fact]
        public void LoggingUtilities_RedactPrivateKey_ShouldShowKeyTypeOnly()
        {
            // Arrange - Generate a test RSA key
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyPairGenerator.GenerateKeyPair();
            var privateKey = keyPair.Private;

            // Act
            var redacted = LoggingUtilities.RedactPrivateKey(privateKey);

            // Assert
            Assert.Contains("REDACTED", redacted);
            Assert.Contains("isPrivate: True", redacted);
            // Should not contain any key material
            Assert.DoesNotContain("MII", redacted); // Common prefix in base64 encoded keys
        }

        [Fact]
        public void LoggingUtilities_RedactPkcs12Bytes_ShouldNotRevealContents()
        {
            // Arrange
            var testBytes = new byte[] { 0x30, 0x82, 0x01, 0x02, 0x03, 0x04 };

            // Act
            var redacted = LoggingUtilities.RedactPkcs12Bytes(testBytes);

            // Assert
            Assert.Contains("REDACTED", redacted);
            Assert.Contains($"bytes: {testBytes.Length}", redacted);
            Assert.DoesNotContain("30", redacted); // Should not contain hex values
            Assert.DoesNotContain("82", redacted);
        }

        [Fact]
        public void LoggingUtilities_RedactToken_ShouldShowOnlyPrefixSuffixAndLength()
        {
            // Arrange
            var testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

            // Act
            var redacted = LoggingUtilities.RedactToken(testToken);

            // Assert
            Assert.Contains("REDACTED", redacted);
            Assert.Contains($"length: {testToken.Length}", redacted);
            Assert.DoesNotContain("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", redacted); // Should not contain full token
            Assert.DoesNotContain("dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", redacted);
        }

        [Fact]
        public void LoggingUtilities_GetFieldPresence_ShouldIndicatePresenceNotValue()
        {
            // Arrange
            var sensitiveValue = "SensitiveData123!";

            // Act
            var result = LoggingUtilities.GetFieldPresence("myField", sensitiveValue);

            // Assert
            Assert.Contains("PRESENT", result);
            Assert.DoesNotContain("SensitiveData", result);
            Assert.DoesNotContain("123!", result);
        }
    }
}
