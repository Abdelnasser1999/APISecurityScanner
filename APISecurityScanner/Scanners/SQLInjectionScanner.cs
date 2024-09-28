using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public class SQLInjectionScanner : BaseScanner
    {
        public override string Name => "SQL Injection Scanner";

        public override void Scan(string endpoint)
        {
            // logic for SQL Injection scanning
            Console.WriteLine($"Scanning {endpoint} for SQL Injection...");
        }
    }
}
