# API Security Scanner
A .NET 8 NuGet package for scanning API endpoints for common security vulnerabilities like SQL Injection, XSS, CSRF, and more.
## Technical Requirements

### Vulnerabilities to Scan:
- SQL Injection: Detect malicious SQL code in user inputs.
- Cross-Site Scripting (XSS): Identify suspicious JavaScript code that may be injected into the API.
- Cross-Site Request Forgery (CSRF): Verify if the API is vulnerable to unauthorized commands by attackers.
- Insecure Direct Object References (IDOR): Check if API endpoints expose unauthorized access to internal objects.
- Broken Authentication: Analyze endpoints for weak authentication mechanisms.
