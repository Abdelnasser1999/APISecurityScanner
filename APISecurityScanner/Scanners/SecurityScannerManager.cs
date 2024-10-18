using System.Collections.Generic;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class SecurityScannerManager
    {
        private readonly List<BaseScanner> _scanners;

        public SecurityScannerManager(List<BaseScanner> scanners)
        {
            _scanners = scanners;
        }

        public async Task RunScans(string endpoint)
        {
            foreach (var scanner in _scanners)
            {
                await scanner.Scan(endpoint);
            }
        }

        public List<string> GenerateReport()
        {
            var report = new List<string>();

            foreach (var scanner in _scanners)
            {
                report.Add($"--- Scanner: {scanner.Name} ---");

                if (scanner.Vulnerabilities.Count > 0)
                {
                    foreach (var vulnerability in scanner.Vulnerabilities)
                    {
                        report.Add($"[Vulnerability] {vulnerability}");
                    }
                }
                else
                {
                    report.Add("No vulnerabilities found.");
                }
            }

            return report;
        }
    }
}
