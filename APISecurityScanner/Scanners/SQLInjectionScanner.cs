using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class SQLInjectionScanner : BaseScanner
    {
        public override string Name => "SQL Injection Scanner";

        private readonly HttpClient _httpClient;
        public List<string> Vulnerabilities { get; private set; }

        public SQLInjectionScanner(HttpClient httpClient)
        {
            _httpClient = httpClient;
            Vulnerabilities = new List<string>();
        }

        public override async Task Scan(string endpoint)
        {
            // Example payloads to test for SQL Injection vulnerabilities
            string[] payloads = { "' OR '1'='1", "'; DROP TABLE Users; --", "\" OR 1=1 --" };

            foreach (var payload in payloads)
            {
                string url = $"{endpoint}?input={Uri.EscapeDataString(payload)}";

                try
                {
                    // Send a request to the API endpoint
                    HttpResponseMessage response = await _httpClient.GetAsync(url);
                    string responseContent = await response.Content.ReadAsStringAsync();

                    // Basic check for SQL error in the response
                    if (responseContent.Contains("SQL syntax error"))
                    {
                        Vulnerabilities.Add(url);
                        Console.WriteLine($"Potential SQL Injection vulnerability found at: {url}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error while scanning {url}: {ex.Message}");
                }
            }
        }
    }
}
