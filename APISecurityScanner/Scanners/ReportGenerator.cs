using APISecurityScanner.Scanners;
using System.Collections.Generic;
using System.Text;

namespace APISecurityScanner.Reports
{
    public class ReportGenerator
    {
        public string GenerateReport(List<BaseScanner> scanners)
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
                        report.AppendLine($"- {vulnerability}");
                    }
                }
                report.AppendLine();
            }
            return report.ToString();
        }
    }
}
