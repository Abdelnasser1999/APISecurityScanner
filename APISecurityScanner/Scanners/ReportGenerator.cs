using APISecurityScanner.Scanners;
using System.Collections.Generic;
using System.Text;

namespace APISecurityScanner.Reports
{
    public class ReportGenerator
    {
        // Generate a detailed report based on the results from all scanners
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
                        // Add the vulnerability details to the report
                        report.AppendLine($"- {vulnerability}");
                    }
                }
                report.AppendLine();
            }
            return report.ToString();
        }
    }
}
