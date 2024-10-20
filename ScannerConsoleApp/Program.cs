using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Threading.Tasks;
using APISecurityScanner.Scanners;

class Program
{
    static async Task Main(string[] args)
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

        // Define the endpoint you want to scan
        string endpoint = "https://example.com/api"; // Replace with the actual endpoint

        // Define required and optional parameters
        var requiredParams = new Dictionary<string, string>
        {
            { "sessionId", "validSessionId" },  // Example of a required parameter
            { "username", "testuser" }
        };

        var optionalParams = new List<string>
        {
            "token",   // Example of an optional parameter
            "search"
        };

        // Choose the HTTP method (GET, POST, PUT)
        HttpMethod method = HttpMethod.Get;  // You can change this based on the endpoint requirements

        // Run the scans
        await scannerManager.RunScans(endpoint, requiredParams, optionalParams, method);

        // Generate the report
        var report = scannerManager.GenerateReport();

        // Print the report with better formatting
        Console.WriteLine("---- Scan Report ----");
        foreach (var line in report)
        {
            Console.WriteLine(line);
        }
        Console.WriteLine("---------------------");
    }
}
