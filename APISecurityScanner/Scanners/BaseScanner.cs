using System.Collections.Generic;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public abstract class BaseScanner
    {
        public abstract string Name { get; }

        // List to store detected vulnerabilities
        public List<string> Vulnerabilities { get; private set; }

        public BaseScanner()
        {
            Vulnerabilities = new List<string>();
        }

        // Abstract method to be implemented by derived scanners
        public abstract Task Scan(string endpoint);
    }
}
