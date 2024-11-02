using APISecurityScanner.Scanners;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace APISecurityScanner.Reports
{
    public class ReportGenerator
    {
        private readonly AiRecommendationService _aiRecommendationService;

        public ReportGenerator(string apiKey)
        {
            _aiRecommendationService = new AiRecommendationService(apiKey);
        }

        public async Task<string> GenerateReportAsync(List<BaseScanner> scanners)
        {
            var report = new StringBuilder();

            foreach (var scanner in scanners)
            {
                report.AppendLine($"Scanner: {scanner.Name}");
                if (scanner.Vulnerabilities.Count == 0)
                {
                    report.AppendLine("No vulnerabilities found.");
                }
                else
                {
                    foreach (var vulnerability in scanner.Vulnerabilities)
                    {
                        report.AppendLine($"- Vulnerability: {vulnerability}");

                        // استدعاء الذكاء الاصطناعي للحصول على التوصية
                        var recommendation = await _aiRecommendationService.GetRecommendationAsync(
                            scanner.Name, vulnerability);

                        report.AppendLine("  AI-powered Recommendation:");
                        report.AppendLine($"  {recommendation}");
                    }
                }
                report.AppendLine();
            }
            return report.ToString();
        }
    }
}
