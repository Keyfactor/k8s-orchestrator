// Copyright 2022 Keyfactor
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using IdentityModel.Client;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Moq;
using Newtonsoft.Json;

namespace TestConsole
{
    public class OrchTestCase
    {
        public string TestName { get; set; }

        public string Description { get; set; }

        public bool Fail { get; set; }

        public string ExpectedValue { get; set; }

        public JobConfig JobConfig { get; set; }
    }

    public class CertificateStoreDetails
    {
        public string ClientMachine { get; set; }

        public string StorePath { get; set; }

        public string StorePassword { get; set; }

        public string Properties { get; set; }

        public int Type { get; set; }
    }

    public class JobCertificate
    {
        public object Thumbprint { get; set; }

        public string Contents { get; set; }

        public string Alias { get; set; }

        public string PrivateKeyPassword { get; set; }
    }

    public class JobConfig
    {

        public List<object> LastInventory { get; set; }

        public CertificateStoreDetails CertificateStoreDetails { get; set; }

        public bool JobCancelled { get; set; }

        public object ServerError { get; set; }

        public int JobHistoryId { get; set; }

        public int RequestStatus { get; set; }

        public string ServerUsername { get; set; }

        public string ServerPassword { get; set; }

        public bool UseSSL { get; set; }

        public object JobProperties { get; set; }

        public string JobTypeId { get; set; }

        public string JobId { get; set; }

        public string Capability { get; set; }

        public int OperationType { get; set; }

        public bool Overwrite { get; set; }

        public JobCertificate JobCertificate { get; set; }
    }

    public class JobProperties
    {
        [JsonProperty("Trusted Root")] public bool TrustedRoot { get; set; }
    }

    public class OrchestratorTestConfig
    {
        public List<OrchTestCase> inventory { get; set; }

        public List<OrchTestCase> add { get; set; }

        public List<OrchTestCase> remove { get; set; }

        public List<OrchTestCase> discovery { get; set; }
    }

    class Program
    {
        private const string EnvironmentVariablePrefix = "TEST_";
        private const string KubeConfigEnvVar = "TEST_KUBECONFIG";
        private const string KubeNamespaceEnvVar = "TEST_KUBE_NAMESPACE";

        public static int tableWidth = 200;

        private static readonly TestEnvironmentalVariable[] _envVariables;

        static Program()
        {
            _envVariables = new[]
            {
                new TestEnvironmentalVariable
                {
                    Name = "TEST_KUBECONFIG",
                    Description = "Kubeconfig file contents",
                    Default = "kubeconfig",
                    Type = "string",
                    Secret = true
                },
                new TestEnvironmentalVariable
                {
                    Name = "TEST_KUBE_NAMESPACE",
                    Description = "Kubernetes namespace",
                    Default = "default",
                    Type = "string"
                },
                new TestEnvironmentalVariable
                {
                    Name = "TEST_CERT_MGMT_TYPE",
                    Description = "Certificate management type",
                    Default = "inv",
                    Choices = new[] { "inv", "add", "remove" },
                    Type = "string"
                },
                new TestEnvironmentalVariable
                {
                    Name = "TEST_MANUAL",
                    Description = "Manual test",
                    Default = "false",
                    Type = "bool"
                },
                new TestEnvironmentalVariable
                {
                    Name = "TEST_ORCH_OPERATION",
                    Description = "Orchestrator operation",
                    Default = "inv",
                    Type = "string",
                    Choices = new[] { "inv", "mgmt" }
                }
            };
        }

        public static string ShowEnvConfig(string format = "json")
        {
            var envConfig = new Dictionary<string, string>();
            var showSecrets = Environment.GetEnvironmentVariable("TEST_SHOW_SECRETS") == "true";
            foreach (var testVar in _envVariables)
            {
                if (testVar.Secret)
                {
                    if (showSecrets)
                    {
                        envConfig.Add(testVar.Name, Environment.GetEnvironmentVariable(testVar.Name));
                        continue;
                    }
                    envConfig.Add(testVar.Name, "********");
                    continue;
                }
                envConfig.Add(testVar.Name, Environment.GetEnvironmentVariable(testVar.Name));
            }
            return format == "json" ? JsonConvert.SerializeObject(envConfig, Formatting.Indented) : envConfig.ToString();
        }


        public static OrchTestCase[] GetTestConfig(string testFileName, string jobType = "inventory")
        {
            // Read test config from file as JSON and deserialize to TestConfiguration
            var testConfig = JsonConvert.DeserializeObject<OrchestratorTestConfig>(File.ReadAllText(testFileName));

            //convert testList to array of objects
            switch (jobType)
            {
                case "inventory":
                case "inv":
                case "i":
                    return testConfig.inventory.ToArray();
                case "add":
                case "a":
                    return testConfig.add.ToArray();
                case "remove":
                case "rem":
                case "r":
                    return testConfig.remove.ToArray();
                case "discovery":
                case "discover":
                case "disc":
                case "d":
                    return testConfig.discovery.ToArray();

            }
            throw new Exception("Invalid job type");
        }
        private async static Task Main(string[] args)
        {
            var runTypeStr = Environment.GetEnvironmentVariable("TEST_MANUAL");
            var isManualTest = !string.IsNullOrEmpty(runTypeStr) && bool.Parse(runTypeStr);
            var hasFailure = false;

            var testOutputDict = new Dictionary<string, string>();

            Console.WriteLine("====KubeTestConsole====");
            Console.WriteLine("Environment Variables:");
            Console.WriteLine(ShowEnvConfig());
            Console.WriteLine("====End Environmental Variables====");

            var pamUserNameField = Environment.GetEnvironmentVariable("TEST_PAM_USERNAME_FIELD") ?? "ServerUsername";
            var pamPasswordField = Environment.GetEnvironmentVariable("TEST_PAM_PASSWORD_FIELD") ?? "ServerPassword";

            if (args.Length == 0)
            {
                // check TEST_OPERATION env var and use that if it else prompt user
                var testOperation = Environment.GetEnvironmentVariable("TEST_ORCH_OPERATION");
                var input = testOperation;
                if (string.IsNullOrEmpty(testOperation) || isManualTest)
                {
                    Console.WriteLine("Enter Operation: (I)nventory, or (M)anagement");
                    input = Console.ReadLine();
                }

                var testConfigPath = Environment.GetEnvironmentVariable("TEST_CONFIG_PATH") ?? "tests.json";

                var pamMockUsername = Environment.GetEnvironmentVariable("TEST_PAM_MOCK_USERNAME") ?? string.Empty;
                var pamMockPassword = Environment.GetEnvironmentVariable("TEST_PAM_MOCK_PASSWORD") ?? string.Empty;

                Console.WriteLine("TEST_PAM_USERNAME_FIELD: " + pamUserNameField);
                Console.WriteLine("TEST_PAM_MOCK_USERNAME: " + pamMockUsername);

                Console.WriteLine("TEST_PAM_PASSWORD_FIELD: " + pamPasswordField);
                Console.WriteLine("TEST_PAM_MOCK_PASSWORD: " + pamMockPassword);

                var secretResolver = new Mock<IPAMSecretResolver>();
                // Get from env var TEST_KUBECONFIG
                // setup resolver for "Server Username" to return "kubeconfig"
                secretResolver.Setup(m =>
                    m.Resolve(It.Is<string>(s => s == pamUserNameField))).Returns(() => pamMockUsername);
                // setup resolver for "Server Password" to return the value of the env var TEST_KUBECONFIG
                secretResolver.Setup(m =>
                    m.Resolve(It.Is<string>(s => s == pamPasswordField))).Returns(() => pamMockPassword);


                var tests = new OrchTestCase[] { };

                input = input.ToLower();
                switch (input)
                {
                    case "inventory":
                    case "inv":
                    case "i":
                        // Get test configurations from testConfigPath

                        tests = GetTestConfig(testConfigPath, input);
                        var inv = new Inventory(secretResolver.Object);

                        Console.WriteLine("Running Inventory Job Test Cases");
                        foreach (var testCase in tests)
                        {
                            testOutputDict.Add(testCase.TestName, "Running");
                            try
                            {
                                //convert testCase to InventoryJobConfig
                                Console.WriteLine($"=============={testCase.TestName}==================");
                                Console.WriteLine($"Description: {testCase.Description}");
                                Console.WriteLine($"Expected Fail: {testCase.Fail.ToString()}");
                                Console.WriteLine($"Expected Result: {testCase.ExpectedValue}");


                                var invJobConfig = GetInventoryJobConfiguration(JsonConvert.SerializeObject(testCase.JobConfig));
                                SubmitInventoryUpdate sui = GetItems;

                                var jobResult = inv.ProcessJob(invJobConfig, sui);

                                if (jobResult.Result == OrchestratorJobStatusJobResult.Success ||
                                    (jobResult.Result == OrchestratorJobStatusJobResult.Failure && testCase.Fail))
                                {
                                    testOutputDict[testCase.TestName] = $"Success {jobResult.FailureMessage}";
                                    Console.ForegroundColor = ConsoleColor.Green;
                                }
                                else
                                {
                                    testOutputDict[testCase.TestName] = $"Failure - {jobResult.FailureMessage}";
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    hasFailure = true;
                                }
                                Console.WriteLine(
                                    $"Job Hist ID:{jobResult.JobHistoryId}\nStorePath:{invJobConfig.CertificateStoreDetails.StorePath}\nStore Properties:\n{invJobConfig.CertificateStoreDetails.Properties}\nMessage: {jobResult.FailureMessage}\nResult: {jobResult.Result}");
                                Console.ResetColor();
                            }
                            catch (Exception e)
                            {
                                testOutputDict[testCase.TestName] = $"Failure - {e.Message}";
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine(e);
                                Console.WriteLine($"Failed to run inventory test case: {testCase.TestName}");
                                Console.ResetColor();
                            }


                        }
                        Console.WriteLine("Finished Running Inventory Job Test Cases");
                        break;
                    case "management":
                    case "man":
                    case "m":
                        // Get from env var TEST_CERT_MGMT_TYPE or prompt for it if not set
                        var testMgmtType = Environment.GetEnvironmentVariable("TEST_CERT_MGMT_TYPE");

                        if (string.IsNullOrEmpty(testMgmtType) || isManualTest)
                        {
                            Console.WriteLine("Select Management Type Add or Remove");
                            testMgmtType = Console.ReadLine();
                        }

                        tests = GetTestConfig(testConfigPath, testMgmtType);

                        Console.WriteLine("Running Management Job Test Cases");
                        foreach (var testCase in tests)
                        {
                            testOutputDict.Add(testCase.TestName, "Running");
                            try
                            {
                                //convert testCase to InventoryJobConfig
                                Console.WriteLine($"=============={testCase.TestName}==================");
                                Console.WriteLine($"Description: {testCase.Description}");
                                Console.WriteLine($"Expected Fail: {testCase.Fail.ToString()}");
                                Console.WriteLine($"Expected Result: {testCase.ExpectedValue}");
                                // var jobConfig = GetManagementJobConfiguration(JsonConvert.SerializeObject(testCase.JobConfig), testCase.JobConfig.JobCertificate.Alias);

                                //======================================================================================================

                                var jobResult = new JobResult();
                                switch (testMgmtType)
                                {
                                    case "Add":
                                    case "add":
                                    case "a":
                                    {
                                        // Get from env var TEST_PKEY_PASSWORD or prompt for it if not set
                                        var testPrivateKeyPwd = Environment.GetEnvironmentVariable("TEST_PKEY_PASSWORD") ??
                                                                testCase.JobConfig.JobCertificate.PrivateKeyPassword;
                                        var privateKeyPwd = testPrivateKeyPwd;
                                        if (string.IsNullOrEmpty(testPrivateKeyPwd) &&
                                            isManualTest) //Only prompt on explicit set of TEST_USE_PKEY_PASS and that password has not been provided
                                        {
                                            Console.WriteLine("Enter private key password or leave blank if no private key");
                                            privateKeyPwd = Console.ReadLine();
                                        }
                                        else
                                        {
                                            Console.WriteLine("Using Private Key Password from env var 'TEST_PKEY_PASSWORD'");
                                            Console.WriteLine("Password: " + testPrivateKeyPwd);
                                        }

                                        var isOverwriteStr = Environment.GetEnvironmentVariable("TEST_JOB_OVERWRITE") ?? "true";
                                        var isOverwrite = !string.IsNullOrEmpty(isOverwriteStr) && bool.Parse(isOverwriteStr);
                                        if (string.IsNullOrEmpty(isOverwriteStr) && isManualTest)
                                        {
                                            Console.WriteLine("Overwrite? Enter true or false");
                                            isOverwriteStr = Console.ReadLine();
                                            isOverwrite = bool.Parse(isOverwriteStr);
                                        }

                                        var certAlias = Environment.GetEnvironmentVariable("TEST_CERT_ALIAS") ?? testCase.JobConfig.JobCertificate.Alias;
                                        if (string.IsNullOrEmpty(certAlias) && isManualTest)
                                        {
                                            Console.WriteLine("Enter cert alias. This is usually the cert thumbprint.");
                                            certAlias = Console.ReadLine();
                                        }

                                        var isTrustedRootStr = Environment.GetEnvironmentVariable("TEST_IS_TRUSTED_ROOT") ?? "false";
                                        var isTrustedRoot = !string.IsNullOrEmpty(isTrustedRootStr) && bool.Parse(isTrustedRootStr);
                                        if (string.IsNullOrEmpty(isTrustedRootStr) && isManualTest)
                                        {
                                            Console.WriteLine("Trusted Root? Enter true or false");
                                            isTrustedRootStr = Console.ReadLine();
                                            isTrustedRoot = bool.Parse(isTrustedRootStr);
                                        }

                                        var mgmt = new Management(secretResolver.Object);

                                        var jobConfig = GetJobManagementConfiguration(
                                            JsonConvert.SerializeObject(testCase.JobConfig),
                                            certAlias,
                                            privateKeyPwd,
                                            isOverwrite,
                                            isTrustedRoot
                                        );

                                        jobResult = mgmt.ProcessJob(jobConfig);
                                        if (testCase.Fail && jobResult.Result == OrchestratorJobStatusJobResult.Success)
                                        {
                                            testOutputDict[testCase.TestName] = $"Failure - {jobResult.FailureMessage} This test case was expected to fail but succeeded.";
                                            Console.ForegroundColor = ConsoleColor.Red;
                                            hasFailure = true;
                                        }
                                        else if (!testCase.Fail && jobResult.Result == OrchestratorJobStatusJobResult.Failure)
                                        {
                                            testOutputDict[testCase.TestName] = $"Failure - {jobResult.FailureMessage} This test case was expected to succeed but failed.";
                                            Console.ForegroundColor = ConsoleColor.Red;
                                            hasFailure = true;
                                        }
                                        else
                                        {
                                            testOutputDict[testCase.TestName] = $"Success {jobResult.FailureMessage}";
                                            Console.ForegroundColor = ConsoleColor.Green;
                                        }
                                        Console.WriteLine(
                                            $"Job Hist ID:{jobResult.JobHistoryId}\nStorePath:{jobConfig.CertificateStoreDetails.StorePath}\nStore Properties:\n{jobConfig.CertificateStoreDetails.Properties}\nMessage: {jobResult.FailureMessage}\nResult: {jobResult.Result}");

                                        Console.ResetColor();
                                        break;
                                    }
                                    case "Remove":
                                    case "remove":
                                    case "rem":
                                    case "r":
                                    {
                                        // Get alias from env TEST_CERT_REMOVE_ALIAS or prompt for it if not set
                                        var alias = Environment.GetEnvironmentVariable("TEST_CERT_ALIAS") ??
                                                    testCase.JobConfig.JobCertificate.Thumbprint?.ToString() ?? testCase.JobConfig.JobCertificate.Alias;
                                        if (string.IsNullOrEmpty(alias) && isManualTest)
                                        {
                                            Console.WriteLine("Alias Enter Alias Name");
                                            alias = Console.ReadLine();
                                        }

                                        var mgmt = new Management(secretResolver.Object);

                                        var jobConfig = GetJobManagementConfiguration(JsonConvert.SerializeObject(testCase.JobConfig), alias);

                                        jobResult = mgmt.ProcessJob(jobConfig);
                                        if (jobResult.Result == OrchestratorJobStatusJobResult.Success ||
                                            (jobResult.Result == OrchestratorJobStatusJobResult.Failure && testCase.Fail))
                                        {
                                            testOutputDict[testCase.TestName] = $"Success {jobResult.FailureMessage}";
                                            Console.ForegroundColor = ConsoleColor.Green;
                                        }
                                        else
                                        {
                                            testOutputDict[testCase.TestName] = $"Failure - {jobResult.FailureMessage}";
                                            Console.ForegroundColor = ConsoleColor.Red;
                                            hasFailure = true;
                                        }
                                        Console.ResetColor();
                                        break;
                                    }
                                    default:
                                        testOutputDict[testCase.TestName] = $"Invalid Management Type {testMgmtType}. Valid types are 'Add' or 'Remove'.";
                                        // Console.WriteLine($"Invalid Management Type {testMgmtType}. Valid types are 'Add' or 'Remove'.");
                                        break;
                                }
                            }
                            catch (Exception e)
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine(e);
                                Console.WriteLine($"Failed to run inventory test case: {testCase.JobConfig.JobId}({testCase.JobConfig.CertificateStoreDetails.StorePath})");
                                Console.ResetColor();
                            }
                        }
                        Console.WriteLine("Finished Running Management Job Test Cases");
                        break;
                    case "discovery":
                    case "discover":
                    case "disc":
                    case "d":
                        tests = GetTestConfig(testConfigPath, input);
                        var discovery = new Discovery(secretResolver.Object);

                        Console.WriteLine("Running Discovery Job Test Cases");
                        foreach (var testCase in tests)
                        {
                            testOutputDict.Add(testCase.TestName, "Running");
                            try
                            {
                                //convert testCase to DiscoveryJobConfig
                                Console.WriteLine($"=============={testCase.TestName}==================");
                                Console.WriteLine($"Description: {testCase.Description}");
                                Console.WriteLine($"Expected Fail: {testCase.Fail.ToString()}");
                                Console.WriteLine($"Expected Result: {testCase.ExpectedValue}");


                                var discoveryJobConfiguration = GetDiscoveryJobConfiguration(JsonConvert.SerializeObject(testCase.JobConfig));
                                // create array of strings for discovery paths
                                var discPaths = new List<string>();
                                // foreach (var path in invJobConfig.DiscoveryPaths)
                                // {
                                //     dicoveryPaths.Add(path.Path);
                                // }
                                discPaths.Add("tls");
                                SubmitDiscoveryUpdate dui = DiscoverItems;
                                var jobResult = discovery.ProcessJob(discoveryJobConfiguration, dui);

                                if (jobResult.Result == OrchestratorJobStatusJobResult.Success ||
                                    (jobResult.Result == OrchestratorJobStatusJobResult.Failure && testCase.Fail))
                                {
                                    testOutputDict[testCase.TestName] = $"Success {jobResult.FailureMessage}";
                                    Console.ForegroundColor = ConsoleColor.Green;
                                }
                                else
                                {
                                    testOutputDict[testCase.TestName] = $"Failure - {jobResult.FailureMessage}";
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    hasFailure = true;
                                }
                                // Console.WriteLine(
                                //     $"Job Hist ID:{jobResult.JobHistoryId}\nStorePath:{invJobConfig.CertificateStoreDetails.StorePath}\nStore Properties:\n{invJobConfig.CertificateStoreDetails.Properties}\nMessage: {jobResult.FailureMessage}\nResult: {jobResult.Result}");
                                Console.ResetColor();
                            }
                            catch (Exception e)
                            {
                                testOutputDict[testCase.TestName] = $"Failure - {e.Message}";
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine(e);
                                Console.WriteLine($"Failed to run inventory test case: {testCase.TestName}");
                                Console.ResetColor();
                            }


                        }
                        Console.WriteLine("Finished Running Inventory Job Test Cases");
                        break;
                }
                if (input == "SerializeTest")
                {

                    var xml =
                        "<response status=\"error\" code=\"10\"><msg><line> <![CDATA[ Boingy]]> cannot be deleted because of references from:</line><line> certificate-profile -> Keyfactor -> CA -> Boingy</line></msg></response>";
                    // using System.Xml.Serialization;
                    // var serializer = new XmlSerializer(typeof(ErrorSuccessResponse));
                    // using var reader = new StringReader(xml);
                    // var test = (ErrorSuccessResponse)serializer.Deserialize(reader);
                    // Console.Write(test);
                }
                else
                {
                    // output test results as a table to the console

                    //write output to csv file
                    var csv = new StringBuilder();
                    csv.AppendLine("Test Name,Result");
                    PrintLine();
                    PrintRow("Test Name", "Result");
                    PrintLine();
                    foreach (var res in testOutputDict)
                    {
                        PrintRow(res.Key, res.Value);
                        csv.AppendLine($"{res.Key},{res.Value}");
                    }
                    PrintLine();
                    var resultFilePath = Environment.GetEnvironmentVariable("TEST_OUTPUT_FILE_PATH") ?? "testResults.csv";
                    try
                    {
                        File.WriteAllText(resultFilePath, csv.ToString());
                    }
                    catch (Exception e)
                    {
                        var currentColor = Console.ForegroundColor;
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Unable to write test results to file {resultFilePath}. Please check the file path and try again.");
                        Console.WriteLine(e.Message);
                        Console.ForegroundColor = currentColor;
                    }

                }
                if (hasFailure)
                {
                    // Send a failure exit code
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Some tests failed please check the output above.");
                    Environment.Exit(1);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("All tests passed.");
                }
            }
        }


        private static void PrintLine()
        {
            Console.WriteLine(new string('-', tableWidth));
        }

        private static void PrintRow(params string[] columns)
        {
            var width = (tableWidth - columns.Length) / columns.Length;
            var row = "|";

            foreach (var column in columns)
            {
                row += AlignLeft(column, width) + "|";
            }

            Console.WriteLine(row);
        }

        private static string AlignCentre(string text, int width)
        {
            text = text.Length > width ? text.Substring(0, width - 3) + "..." : text;

            if (string.IsNullOrEmpty(text))
            {
                return new string(' ', width);
            }
            return text.PadRight(width - (width - text.Length) / 2).PadLeft(width);
        }

        private static string AlignLeft(string text, int width)
        {
            text = text.Length > width ? text.Substring(0, width - 3) + "..." : text;

            return text.PadRight(width);
        }

        public static bool GetItems(IEnumerable<CurrentInventoryItem> items)
        {
            return true;
        }

        public static bool DiscoverItems(IEnumerable<string> items)
        {
            return true;
        }

        public static ManagementJobConfiguration GetJobManagementConfiguration(string jobConfigString, string alias, string privateKeyPwd = "", bool overWrite = true,
            bool trustedRoot = false)
        {
            var result = JsonConvert.DeserializeObject<ManagementJobConfiguration>(jobConfigString);
            return result;
        }

        public static InventoryJobConfiguration GetInventoryJobConfiguration(string jobConfigString)
        {
            var result = JsonConvert.DeserializeObject<InventoryJobConfiguration>(jobConfigString);
            return result;
        }

        public static DiscoveryJobConfiguration GetDiscoveryJobConfiguration(string jobConfigString)
        {
            var result = JsonConvert.DeserializeObject<DiscoveryJobConfiguration>(jobConfigString);
            return result;
        }

        public static ManagementJobConfiguration GetManagementJobConfiguration(string jobConfigString, string alias = null)
        {
            if (alias != null)
            {
                jobConfigString = jobConfigString.Replace("{{alias}}", alias);
            }
            var result = JsonConvert.DeserializeObject<ManagementJobConfiguration>(jobConfigString);
            return result;
        }

        public struct TestEnvironmentalVariable
        {
            public string Name { get; set; }

            public string Description { get; set; }

            public string Default { get; set; }

            public string Type { get; set; }

            public string[] Choices { get; set; }

            public bool Secret { get; set; }
        }
    }
}
