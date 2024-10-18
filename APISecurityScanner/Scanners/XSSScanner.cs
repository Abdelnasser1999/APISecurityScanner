using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class XSSScanner : BaseScanner
    {
        public override string Name => "Cross-Site Scripting (XSS) Scanner";

        private readonly HttpClient _httpClient;
        public List<string> Vulnerabilities { get; private set; }

        public XSSScanner(HttpClient httpClient)
        {
            _httpClient = httpClient;
            Vulnerabilities = new List<string>();
        }

        public override async Task Scan(string endpoint)
        {
            // Example payloads to test for XSS vulnerabilities
            string[] payloads = { "<script>alert('XSS')</script>", "\" onerror=\"alert('XSS')\"" };

            foreach (var payload in payloads)
            {
                string url = $"{endpoint}?input={Uri.EscapeDataString(payload)}";

                try
                {
                    HttpResponseMessage response = await _httpClient.GetAsync(url);
                    string responseContent = await response.Content.ReadAsStringAsync();

                    // Check if the payload is reflected in the response
                    if (responseContent.Contains(payload))
                    {
                        Vulnerabilities.Add(url); // Add to vulnerabilities if found
                        Console.WriteLine($"Potential XSS vulnerability found at: {url}");
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
