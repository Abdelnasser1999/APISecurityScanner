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

                    // قائمة المعلمات
                    var requiredParams = new Dictionary<string, string>();
                    var optionalParams = new List<string>();

                    // جلب المعلمات من "parameters" 
                    var parameters = method.Value["parameters"];
                    if (parameters != null)
                    {
                        foreach (var param in parameters)
                        {
                            var paramName = param["name"].Value<string>();
                            var isRequired = param["required"]?.Value<bool>() ?? false;

                            if (isRequired)
                            {
                                requiredParams[paramName] = param["schema"]?["example"]?.Value<string>() ?? "";
                            }
                            else
                            {
                                optionalParams.Add(paramName);
                            }
                        }
                    }

                    // جلب المعلمات من "requestBody" إذا كانت موجودة
                    var requestBody = method.Value["requestBody"]?["content"];
                    if (requestBody != null)
                    {
                        var schemaProperties = requestBody.First.First["schema"]?["properties"];
                        if (schemaProperties != null)
                        {
                            foreach (var property in schemaProperties)
                            {
                                var propName = property.Path.Split('.').Last();
                                requiredParams[propName] = property.First["example"]?.Value<string>() ?? "";
                            }
                        }
                    }

                    //// طباعة القيم للتأكد من الجلب
                    ////Console.WriteLine($"Required Parameters for {pathUrl} ({httpMethod}): Count = {requiredParams.Count}");
                    //foreach (var param in requiredParams)
                    //{
                    //    Console.WriteLine($"- {param.Key}: {param.Value}");
                    //}

                    ////Console.WriteLine($"Optional Parameters for {pathUrl} ({httpMethod}): Count = {optionalParams.Count}");
                    //foreach (var param in optionalParams)
                    //{
                    //    Console.WriteLine($"- {param}");
                    //}

                    var endpointData = new EndpointData
                    {
                        Url = pathUrl,
                        HttpMethod = httpMethod,
                        RequiredParams = requiredParams,
                        OptionalParams = optionalParams
                    };

                    endpoints.Add(endpointData);
                }
            }
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