# API Security Scanner
A .NET 8 NuGet package for scanning API endpoints for common security vulnerabilities like SQL Injection, XSS, CSRF, and more.

## Current Scanners
- **SQL Injection Scanner:** Tests API endpoints with various SQL payloads to detect potential vulnerabilities.
- **XSS Scanner:** Detects Cross-Site Scripting (XSS) vulnerabilities by sending malicious JavaScript payloads and checking if they are reflected in the API response.
- **CSRF Scanner:** Detects Cross-Site Request Forgery (CSRF) vulnerabilities by verifying the presence of CSRF tokens in API responses.

## Usage

1. To use the scanner, instantiate the desired scanner class (e.g., `SQLInjectionScanner`, `XSSScanner`, `CSRFScanner`).
2. Call the `Scan` method with the API endpoint to test.
3. Check the `Vulnerabilities` list for detected vulnerabilities.

## Technical Requirements

### Vulnerabilities to Scan:
- SQL Injection: Detect malicious SQL code in user inputs.
- Cross-Site Scripting (XSS): Identify suspicious JavaScript code that may be injected into the API.
- Cross-Site Request Forgery (CSRF): Verify if the API is vulnerable to unauthorized commands by attackers.
- Insecure Direct Object References (IDOR): Check if API endpoints expose unauthorized access to internal objects.
- Broken Authentication: Analyze endpoints for weak authentication mechanisms.

## Technical Requirements (Update 10/12/2024)

### SQL Injection Scanner
- The `SQLInjectionScanner` class sends various payloads to test the API endpoints for potential SQL Injection vulnerabilities.
- Uses `HttpClient` to send requests and analyze responses for SQL errors.
- Stores detected vulnerabilities in a list for further analysis and reporting.
### XSS Scanner
- The `XSSScanner` class is responsible for detecting potential Cross-Site Scripting (XSS) vulnerabilities.
- It sends various payloads to the API to check for reflected or stored JavaScript code.
- Detected vulnerabilities are stored in the `Vulnerabilities` list, which includes the URL where the vulnerability was found.

### CSRF Scanner
- The `CSRFScanner` class is responsible for detecting Cross-Site Request Forgery (CSRF) vulnerabilities.
- It checks if the API responses include CSRF tokens in headers or body content.
- If no CSRF tokens are found, the `Vulnerabilities` list stores the endpoint where the vulnerability was found.

## Scan Scenarios (Update 10/12/2024)

### SQL Injection:
- Send inputs to the API containing SQL payloads (e.g., `'; DROP TABLE`).
- Monitor the response to analyze for possible vulnerabilities.
  
### XSS
- The scanner sends various payloads such as `<script>alert('XSS')</script>` to the API endpoint.
- If the payload is reflected in the response, the endpoint is considered vulnerable to XSS.
- Example URL: `https://example.com/api/test?input=<script>alert('XSS')</script>`

### CSRF
- The scanner checks if CSRF tokens are included in the response headers or body.
- If no CSRF tokens are found, the endpoint is marked as potentially vulnerable.
- Example URL: `https://example.com/api/test`
## Technical Roadmap

### Project Structure
- **Scanners:** Contains classes that implement scanning for specific vulnerabilities (e.g., `SQLInjectionScanner`, `XSSScanner`).
- **Reports:** Responsible for generating detailed reports (`ReportGenerator`).
- **Utilities:** Helper tools for scanning (e.g., JSON response analysis, HTTP request handling).
- **Tests:** Unit tests for each scanner module.
