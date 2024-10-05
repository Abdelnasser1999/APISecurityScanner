# API Security Scanner
A .NET 8 NuGet package for scanning API endpoints for common security vulnerabilities like SQL Injection, XSS, CSRF, and more.

## Current Scanners
- **SQL Injection Scanner:** Tests API endpoints with various SQL payloads to detect potential vulnerabilities.

## Technical Requirements

### Vulnerabilities to Scan:
- SQL Injection: Detect malicious SQL code in user inputs.
- Cross-Site Scripting (XSS): Identify suspicious JavaScript code that may be injected into the API.
- Cross-Site Request Forgery (CSRF): Verify if the API is vulnerable to unauthorized commands by attackers.
- Insecure Direct Object References (IDOR): Check if API endpoints expose unauthorized access to internal objects.
- Broken Authentication: Analyze endpoints for weak authentication mechanisms.

- ## Technical Requirements (Update 10/05/2024)

### SQL Injection Scanner
- The `SQLInjectionScanner` class sends various payloads to test the API endpoints for potential SQL Injection vulnerabilities.
- Uses `HttpClient` to send requests and analyze responses for SQL errors.
- Stores detected vulnerabilities in a list for further analysis and reporting.

## Scan Scenarios

### SQL Injection:
- Send inputs to the API containing SQL payloads (e.g., `'; DROP TABLE`).
- Monitor the response to analyze for possible vulnerabilities.

### XSS:
- Inject JavaScript payloads, such as `<script>alert('XSS')</script>`, into API inputs.
- Analyze the API response to identify any reflected or stored content injection.
## Technical Roadmap

### Project Structure
- **Scanners:** Contains classes that implement scanning for specific vulnerabilities (e.g., `SQLInjectionScanner`, `XSSScanner`).
- **Reports:** Responsible for generating detailed reports (`ReportGenerator`).
- **Utilities:** Helper tools for scanning (e.g., JSON response analysis, HTTP request handling).
- **Tests:** Unit tests for each scanner module.
