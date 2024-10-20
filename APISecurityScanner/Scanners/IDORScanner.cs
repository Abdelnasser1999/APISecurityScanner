using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class IDORScanner : BaseScanner
    {
        public override string Name => "IDOR Scanner";

        private readonly HttpClient _httpClient;

        public IDORScanner(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public override async Task Scan(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, HttpMethod method)
        {
            string[] ids = { "1", "2", "3", "9999" }; // Test with IDs

            if (method == HttpMethod.Get)
            {
                foreach (var id in ids)
                {
                    string url = $"{endpoint}/{id}?{string.Join("&", requiredParams.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"))}";

                    HttpResponseMessage response = await _httpClient.GetAsync(url);
                    if (response.IsSuccessStatusCode)
                    {
                        string responseContent = await response.Content.ReadAsStringAsync();
                        if (responseContent.Contains("Sensitive data"))
                        {
                            Vulnerabilities.Add($"{url} (IDOR)");
                            Console.WriteLine($"Potential IDOR vulnerability found at: {url}");
                        }
                    }
                }
            }
        }
    }
}
