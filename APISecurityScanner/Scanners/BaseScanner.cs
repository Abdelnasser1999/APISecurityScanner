using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace APISecurityScanner.Scanners
{
    public abstract class BaseScanner
    {
        public abstract string Name { get; }
        public abstract void Scan(string endpoint);
    }
}
