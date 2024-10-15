using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class CSRFScanner : BaseScanner
    {
        public override string Name => "Cross-Site Request Forgery (CSRF) Scanner";

        private readonly HttpClient _httpClient;
        public List<string> Vulnerabilities { get; private set; }

        public CSRFScanner(HttpClient httpClient)
        {
            _httpClient = httpClient;
            Vulnerabilities = new List<string>(); 
        }

        public override async Task Scan(string endpoint)
        {
            try
            {
                HttpResponseMessage response = await _httpClient.GetAsync(endpoint);
                string responseContent = await response.Content.ReadAsStringAsync();

                // Basic check for CSRF token in the response headers or content
                if (!response.Headers.Contains("Set-Cookie") && !responseContent.Contains("csrf"))
                {
                    Vulnerabilities.Add(endpoint); // Add to vulnerabilities if found
                    Console.WriteLine($"Potential CSRF vulnerability found at: {endpoint}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while scanning {endpoint}: {ex.Message}");
            }
        }
    }
}
