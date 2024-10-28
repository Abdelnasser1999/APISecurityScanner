using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Threading.Tasks;
using APISecurityScanner.Scanners;
using APISecurityScanner.Utils;

class Program
{
    static async Task Main(string[] args)
    {
        var httpClient = new HttpClient
        {
            BaseAddress = new Uri("https://localhost:7279") // تعيين BaseAddress
        };

        // تعريف قائمة الفاحصات
        var scanners = new List<BaseScanner>
        {
            new SQLInjectionScanner(httpClient),
            new XSSScanner(httpClient),
            new CSRFScanner(httpClient),
            new IDORScanner(httpClient),
            new BrokenAuthenticationScanner(httpClient)
        };

        // تهيئة SecurityScannerManager
        var scannerManager = new SecurityScannerManager(scanners);

        // رابط Swagger الخاص بـ API المطلوب فحصه
        var swaggerUrl = "/swagger/v1/swagger.json"; // استخدم مسار نسبي

        // إنشاء الكلاس SwaggerEndpointFetcher وتمرير scannerManager إليه
        var swaggerFetcher = new SwaggerEndpointFetcher(httpClient, scannerManager);

        // توليد التقرير عن الثغرات المكتشفة
        await swaggerFetcher.GenerateSecurityReport(swaggerUrl);
    }


}
