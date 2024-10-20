using System.Collections.Generic;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class SecurityScannerManager
    {
        private readonly List<BaseScanner> _scanners;

        // Initialize with a list of scanners
        public SecurityScannerManager(List<BaseScanner> scanners)
        {
            _scanners = scanners;
        }

        // Run all scanners against a specific endpoint
        public async Task RunScans(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, HttpMethod method)
        {
            foreach (var scanner in _scanners)
            {
                // Run each scanner with required and optional parameters
                await scanner.Scan(endpoint, requiredParams, optionalParams, method);
            }
        }

        // Generate a detailed report based on the vulnerabilities found by all scanners
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
