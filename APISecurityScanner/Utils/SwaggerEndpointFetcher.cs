using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using APISecurityScanner.Helper;
using APISecurityScanner.Scanners;

namespace APISecurityScanner.Utils
{
    public class SwaggerEndpointFetcher
    {
        private readonly HttpClient _httpClient;
        private readonly SecurityScannerManager _scannerManager;

        public SwaggerEndpointFetcher(HttpClient httpClient, SecurityScannerManager scannerManager)
        {
            _httpClient = httpClient;
            _scannerManager = scannerManager;
        }

        public async Task<List<EndpointData>> GetEndpointsFromSwaggerAsync(string swaggerUrl)
        {
            var response = await _httpClient.GetStringAsync(swaggerUrl);
            var swaggerJson = JObject.Parse(response);

            var endpoints = new List<EndpointData>();

            foreach (var path in swaggerJson["paths"].Children<JProperty>())
            {
                var pathUrl = path.Name; // الحصول على URL المسار
                foreach (var method in path.Value.Children<JProperty>())
                {
                    var httpMethod = method.Name; // نوع الطلب HTTP
                    var endpointData = new EndpointData
                    {
                        Url = pathUrl,
                        HttpMethod = httpMethod,
                        RequiredParams = method.Value["parameters"]?
                            .Where(p => p["required"]?.Value<bool>() == true)
                            .ToDictionary(
                                p => p["name"].Value<string>(),
                                p => p["example"]?.Value<string>() ?? ""
                            ) ?? new Dictionary<string, string>(),
                        OptionalParams = method.Value["parameters"]?
                            .Where(p => p["required"]?.Value<bool>() == false)
                            .Select(p => p["name"].Value<string>())
                            .ToList() ?? new List<string>()
                    };

                    endpoints.Add(endpointData);
                }
            }
            //foreach(var point in endpoints)
            //{
            //    Console.WriteLine(point.Url);
            //    Console.WriteLine(point.HttpMethod);
            //    Console.WriteLine(point.RequiredParams);
            //    Console.WriteLine(point.OptionalParams);
            //}

            return endpoints;
        }

        public async Task RunScansOnEndpoints(string swaggerUrl)
        {
            var endpoints = await GetEndpointsFromSwaggerAsync(swaggerUrl);

            foreach (var endpoint in endpoints)
            {
                await _scannerManager.RunScans(
                    endpoint.Url,
                    endpoint.RequiredParams,
                    endpoint.OptionalParams,
                    new HttpMethod(endpoint.HttpMethod));
            }
        }

        public async Task GenerateSecurityReport(string swaggerUrl)
        {
            await RunScansOnEndpoints(swaggerUrl);

            var report = _scannerManager.GenerateReport();

            Console.WriteLine("Detected vulnerabilities:");
            foreach (var vulnerability in report)
            {
                Console.WriteLine(vulnerability); 
            }
        }
    }
}