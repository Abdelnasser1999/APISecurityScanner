using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public abstract class BaseScanner
    {
        // Name of the scanner (e.g., SQL Injection Scanner)
        public abstract string Name { get; }

        // List to store the vulnerabilities found
        public List<string> Vulnerabilities { get; protected set; }

        // Constructor to initialize the Vulnerabilities list
        public BaseScanner()
        {
            Vulnerabilities = new List<string>();
        }

        // Abstract method to be implemented by each scanner
        // Takes an endpoint, required parameters, optional parameters, and HTTP method
        public abstract Task Scan(string endpoint, Dictionary<string, string> requiredParams, List<string> optionalParams, HttpMethod method);
    }
}
