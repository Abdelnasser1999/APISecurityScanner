using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class BrokenAuthenticationScanner : BaseScanner
    {
        public override string Name => "Broken Authentication Scanner";

        private readonly HttpClient _httpClient;

        public BrokenAuthenticationScanner(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public override async Task Scan(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, HttpMethod method)
        {
            string payload = "invalidtoken"; // Example payload for broken authentication

            if (method == HttpMethod.Get)
            {
                await ScanGetRequest(endpoint, requiredParams, optionalParams, payload);
            }
            else if (method == HttpMethod.Post || method == HttpMethod.Put)
            {
                await ScanPostOrPutRequest(endpoint, requiredParams, optionalParams, payload, method);
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

                if (response.IsSuccessStatusCode)
                {
                    Vulnerabilities.Add($"{url} (Param: {param})");
                    Console.WriteLine($"Potential Broken Authentication vulnerability found at: {url} (Param: {param})");
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

                if (response.IsSuccessStatusCode)
                {
                    Vulnerabilities.Add($"{endpoint} [POST/PUT] (Param: {param})");
                    Console.WriteLine($"Potential Broken Authentication vulnerability found at: {endpoint} [POST/PUT] (Param: {param})");
                }
            }
        }
    }
}
