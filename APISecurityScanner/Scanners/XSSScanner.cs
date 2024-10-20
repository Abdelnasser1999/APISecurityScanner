using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class XSSScanner : BaseScanner
    {
        public override string Name => "XSS Scanner";

        private readonly HttpClient _httpClient;

        public XSSScanner(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public override async Task Scan(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, HttpMethod method)
        {
            string[] payloads = { "<script>alert('XSS')</script>", "\" onerror=\"alert('XSS')\"" };

            if (method == HttpMethod.Get)
            {
                await ScanGetRequest(endpoint, requiredParams, optionalParams, payloads);
            }
            else if (method == HttpMethod.Post || method == HttpMethod.Put)
            {
                await ScanPostOrPutRequest(endpoint, requiredParams, optionalParams, payloads, method);
            }
        }

        private async Task ScanGetRequest(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, string[] payloads)
        {
            foreach (var payload in payloads)
            {
                foreach (var param in optionalParams)
                {
                    var allParams = new Dictionary<string, string>(requiredParams);
                    allParams[param] = payload;

                    string url = $"{endpoint}?{string.Join("&", allParams.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"))}";
                    HttpResponseMessage response = await _httpClient.GetAsync(url);

                    // Read the response content as a string
                    string responseContent = await response.Content.ReadAsStringAsync();

                    // Check if the response contains the payload
                    if (responseContent.Contains(payload))
                    {
                        Vulnerabilities.Add($"{url} (Param: {param})");
                        Console.WriteLine($"Potential XSS vulnerability found at: {url} (Param: {param})");
                    }
                }
            }
        }

        private async Task ScanPostOrPutRequest(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, string[] payloads, HttpMethod method)
        {
            foreach (var payload in payloads)
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

                    // Read the response content as a string
                    string responseContent = await response.Content.ReadAsStringAsync();

                    // Check if the response contains the payload
                    if (responseContent.Contains(payload))
                    {
                        Vulnerabilities.Add($"{endpoint} [POST/PUT] (Param: {param})");
                        Console.WriteLine($"Potential XSS vulnerability found at: {endpoint} [POST/PUT] (Param: {param})");
                    }
                }
            }
        }
    }
}
