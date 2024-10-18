using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class BrokenAuthenticationScanner : BaseScanner
    {
        public override string Name => "Broken Authentication Scanner";

        private readonly HttpClient _httpClient;
        public List<string> Vulnerabilities { get; private set; }

        public BrokenAuthenticationScanner(HttpClient httpClient)
        {
            _httpClient = httpClient;
            Vulnerabilities = new List<string>();
        }

        public override async Task Scan(string endpoint)
        {
            // Test without authentication
            try
            {
                HttpResponseMessage response = await _httpClient.GetAsync(endpoint);
                if (response.IsSuccessStatusCode)
                {
                    Vulnerabilities.Add(endpoint); // Add to vulnerabilities if found
                    Console.WriteLine($"Potential Broken Authentication found at: {endpoint}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while scanning {endpoint}: {ex.Message}");
            }

            // Test with invalid/expired credentials (Basic auth example)
            var invalidAuthHeader = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("invaliduser:invalidpassword"));
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", invalidAuthHeader);

            try
            {
                HttpResponseMessage response = await _httpClient.GetAsync(endpoint);
                if (response.IsSuccessStatusCode)
                {
                    Vulnerabilities.Add(endpoint);
                    Console.WriteLine($"Potential Broken Authentication found with invalid credentials at: {endpoint}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while scanning {endpoint} with invalid credentials: {ex.Message}");
            }
        }
    }
}
