using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class IDORScanner : BaseScanner
    {
        public override string Name => "Insecure Direct Object References (IDOR) Scanner";

        private readonly HttpClient _httpClient;
        public List<string> Vulnerabilities { get; private set; }

        public IDORScanner(HttpClient httpClient)
        {
            _httpClient = httpClient;
            Vulnerabilities = new List<string>();
        }

        public override async Task Scan(string endpoint)
        {
            // Example IDs for testing IDOR vulnerabilities
            string[] ids = { "1", "2", "3", "9999" }; // Include both valid and invalid IDs for testing

            foreach (var id in ids)
            {
                string url = $"{endpoint}/{id}";

                try
                {
                    HttpResponseMessage response = await _httpClient.GetAsync(url);
                    if (response.IsSuccessStatusCode)
                    {
                        string responseContent = await response.Content.ReadAsStringAsync();
                        // Here we should check if the user has access to the returned resource
                        // Simple check for an example - we need to enhance this based on real API responses
                        if (responseContent.Contains("User Data") && !responseContent.Contains($"ID: {id}"))
                        {
                            Vulnerabilities.Add(url);
                            Console.WriteLine($"Potential IDOR vulnerability found at: {url}");
                        }
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
