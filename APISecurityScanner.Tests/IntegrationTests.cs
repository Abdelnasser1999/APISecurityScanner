using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using APISecurityScanner.Scanners;

namespace APISecurityScanner.Tests
{
    public class IntegrationTests
    {
        [Fact]
        public async Task RunAllScanners_ShouldGenerateReport()
        {
            var httpClient = new HttpClient();

            // Instantiate all the scanners
            var scanners = new List<BaseScanner>
            {
                new SQLInjectionScanner(httpClient),
                new XSSScanner(httpClient),
                new CSRFScanner(httpClient),
                new IDORScanner(httpClient),
                new BrokenAuthenticationScanner(httpClient)
            };

            // Instantiate the SecurityScannerManager
            var scannerManager = new SecurityScannerManager(scanners);

            var requiredParams = new Dictionary<string, string>
            {
                { "sessionId", "validSession" }
            };

            var optionalParams = new List<string>
            {
                "token"
            };

            // Define the endpoint you want to scan
            string endpoint = "https://example.com/api"; // Replace with the actual endpoint

            // Run the scans
            await scannerManager.RunScans(endpoint, requiredParams, optionalParams, HttpMethod.Get);

            // Generate the report
            var report = await scannerManager.GenerateReportAsync();

            // Assert that the report is not empty
            Assert.NotEmpty(report);

            // Optionally, print the report for verification
            Console.WriteLine("Scan Report:");
            foreach (var line in report)
            {
                Console.WriteLine(line);
            }
        }
    }
}
