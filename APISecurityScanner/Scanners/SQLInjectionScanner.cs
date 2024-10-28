using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class SQLInjectionScanner : BaseScanner
    {
        public override string Name => "SQL Injection Scanner";

        private readonly HttpClient _httpClient;

        public SQLInjectionScanner(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public override async Task Scan(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, HttpMethod method)
        {
            string[] payloads = { "' OR '1'='1", "'; DROP TABLE Users; --", "\" OR 1=1 --" };
            //Console.WriteLine(Name + " Scanning " + endpoint);
            if (method == HttpMethod.Get)
            {
                await ScanGetRequests(endpoint, requiredParams, optionalParams, payloads);
            }
            else if (method == HttpMethod.Post || method == HttpMethod.Put)
            {
                await ScanPostOrPutRequests(endpoint, requiredParams, optionalParams, payloads, method);
            }
        }

        private async Task ScanGetRequests(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, string[] payloads)
        {
            foreach (var payload in payloads)
            {
                // استخدام المعلمات الإلزامية أو فقط تجربة الحمولات مباشرة إذا لم توجد معلمات اختيارية
                var allParams = new Dictionary<string, string>(requiredParams);

                if (optionalParams.Count > 0)
                {
                    foreach (var param in optionalParams)
                    {
                        allParams[param] = payload;
                        string url = $"{endpoint}?{string.Join("&", allParams.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"))}";

                        // تنفيذ الطلب والتحقق من الاستجابة
                        await ExecuteSqlInjectionCheck(url, param);
                    }
                }
                else
                {
                    // إجراء الفحص مباشرة على نقطة النهاية بدون معلمات اختيارية
                    string url = $"{endpoint}?{string.Join("&", allParams.Select(p => $"{p.Key}={Uri.EscapeDataString(payload)}"))}";
                    await ExecuteSqlInjectionCheck(url, "DirectPayload");
                }
            }
        }

        private async Task ExecuteSqlInjectionCheck(string url, string param)
        {
            try
            {
                HttpResponseMessage response = await _httpClient.GetAsync(url);
                string responseContent = await response.Content.ReadAsStringAsync();

                if (responseContent.Contains("SQL syntax error"))
                {
                    Vulnerabilities.Add($"{url} (Parameter: {param})");
                    Console.WriteLine($"SQL Injection vulnerability found at {url} (Parameter: {param})");
                }
                else
                {
                    Console.WriteLine($"**** NO *** SQL Injection vulnerability found at {url} (Parameter: {param})");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while scanning {url}: {ex.Message}");
            }
        }
        private async Task ScanPostOrPutRequests(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, string[] payloads, HttpMethod method)
        {
            foreach (var payload in payloads)
            {
                foreach (var param in optionalParams)
                {
                    var formData = new Dictionary<string, string>(requiredParams);
                    formData[param] = payload;

                    var content = new FormUrlEncodedContent(formData);

                    try
                    {
                        HttpResponseMessage response;
                        if (method == HttpMethod.Post)
                        {
                            response = await _httpClient.PostAsync(endpoint, content);
                        }
                        else
                        {
                            response = await _httpClient.PutAsync(endpoint, content);
                        }

                        string responseContent = await response.Content.ReadAsStringAsync();

                        if (responseContent.Contains("SQL syntax error"))
                        {
                            Vulnerabilities.Add($"{endpoint} [POST/PUT] (Parameter: {param})");
                            Console.WriteLine($"SQL Injection vulnerability found at {endpoint} [POST/PUT] (Parameter: {param})");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error while scanning {endpoint} [POST/PUT]: {ex.Message}");
                    }
                }
            }
        }
    }
}
