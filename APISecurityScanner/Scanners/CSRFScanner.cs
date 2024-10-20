using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class CSRFScanner : BaseScanner
    {
        public override string Name => "CSRF Scanner";

        private readonly HttpClient _httpClient;

        public CSRFScanner(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public override async Task Scan(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, HttpMethod method)
        {
            string tokenPayload = "fake_csrf_token"; // Example payload for CSRF

            if (method == HttpMethod.Get)
            {
                await ScanGetRequest(endpoint, requiredParams, optionalParams, tokenPayload);
            }
            else if (method == HttpMethod.Post || method == HttpMethod.Put)
            {
                await ScanPostOrPutRequest(endpoint, requiredParams, optionalParams, tokenPayload, method);
            }
        }

        private async Task ScanGetRequest(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, string payload)
        {
            foreach (var param in optionalParams)
            {
                var allParams = new Dictionary<string, string>(requiredParams);
                allParams[param] = payload;

                string url = $"{endpoint}?{string.Join("&", allParams.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"))}";
                HttpResponseMessage response = await _httpClient.GetAsync(url);

                if (!response.Headers.Contains("X-CSRF-Token"))
                {
                    Vulnerabilities.Add($"{url} (Param: {param})");
                    Console.WriteLine($"Potential CSRF vulnerability found at: {url} (Param: {param})");
                }
            }
        }

        private async Task ScanPostOrPutRequest(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, string payload, HttpMethod method)
        {
            foreach (var param in optionalParams)
            {
                var formData = new Dictionary<string, string>(requiredParams);
                formData[param] = payload;

                var content = new FormUrlEncodedContent(formData);
                HttpResponseMessage response;

                if (method == HttpMethod.Post)
                    response = await _httpClient.PostAsync(endpoint, content);
                else
                    response = await _httpClient.PutAsync(endpoint, content);

                if (!response.Headers.Contains("X-CSRF-Token"))
                {
                    Vulnerabilities.Add($"{endpoint} [POST/PUT] (Param: {param})");
                    Console.WriteLine($"Potential CSRF vulnerability found at: {endpoint} [POST/PUT] (Param: {param})");
                }
            }
        }
    }
}
