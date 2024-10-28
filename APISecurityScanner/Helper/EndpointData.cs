using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace APISecurityScanner.Helper
{
    public class EndpointData
    {
        public string Url { get; set; }
        public string HttpMethod { get; set; }
        public Dictionary<string, string> RequiredParams { get; set; }
        public List<string> OptionalParams { get; set; }
    }
}
