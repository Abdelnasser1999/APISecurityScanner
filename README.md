# APISecurityScanner ( Update 11/02/2024 )

A .NET 8 NuGet package for scanning API endpoints for common security vulnerabilities like SQL Injection, XSS, CSRF, IDOR, and Broken Authentication.

## Current Scanners
- **SQL Injection Scanner:** Tests API endpoints with various SQL payloads to detect potential vulnerabilities.
- **XSS Scanner:** Detects Cross-Site Scripting (XSS) vulnerabilities by sending malicious JavaScript payloads and checking if they are reflected in the API response.
- **CSRF Scanner:** Detects Cross-Site Request Forgery (CSRF) vulnerabilities by verifying the presence of CSRF tokens in API responses.
- **IDOR Scanner:** Detects Insecure Direct Object References (IDOR) vulnerabilities by testing unauthorized access to internal objects through exposed endpoints.
- **Broken Authentication Scanner:** Detects weaknesses in API authentication mechanisms by attempting to access protected endpoints with invalid or no credentials.


### Vulnerabilities to Scan:
- **SQL Injection:** Detects malicious SQL code in user inputs.
- **Cross-Site Scripting (XSS):** Identifies suspicious JavaScript code that may be injected into the API.
- **Cross-Site Request Forgery (CSRF):** Verifies if the API is vulnerable to unauthorized commands by attackers.
- **Insecure Direct Object References (IDOR):** Checks if API endpoints expose unauthorized access to internal objects.
- **Broken Authentication:** Analyzes endpoints for weak authentication mechanisms.

## Project Structure
- **Scanners:** Contains classes that implement scanning for specific vulnerabilities (e.g., `SQLInjectionScanner`, `XSSScanner`, `CSRFScanner`, `IDORScanner`, `BrokenAuthenticationScanner`).
- **Security Scanner Manager:** Organizes scans and coordinates the execution of different scanners. It aggregates the final results from each scanner and generates a comprehensive report.
- **Swagger Endpoint Fetcher:** Fetches all endpoints from the Swagger documentation of the target API, analyzing required parameters to facilitate scanning.
- **AI Recommendation Service:** A built-in service that analyzes the scan results and provides dynamic recommendations on how to address each discovered vulnerability using OpenAI's GPT-4 model.
- **Reports:** Responsible for generating detailed reports (e.g., `ReportGenerator`).
- **Utilities:** Helper tools for scanning, including JSON response analysis and HTTP request handling.
- **Tests:** Unit tests for each scanner module.

## Scan Scenarios

### SQL Injection:
- Sends inputs to the API containing SQL payloads to analyze for potential vulnerabilities.

### XSS
- Sends various payloads to the API endpoint to check for reflected or stored JavaScript code vulnerabilities.

### CSRF
- Verifies if CSRF tokens are included in the response headers or body.

### IDOR
- Sends object identifiers (IDs) to the API endpoint to verify access to resources and checks if unauthorized access to internal resources is possible.

### Broken Authentication
- Attempts to access protected API endpoints using invalid credentials or without any authentication.

## AI Recommendation Service

The **AI Recommendation Service** is an integrated service that provides dynamic, context-based guidance for fixing detected vulnerabilities. It uses OpenAI’s GPT-4 model to generate recommendations based on the detected vulnerability type and relevant endpoint details. This service enhances the scanner's utility by providing actionable insights to help secure API endpoints.

## Technical Roadmap

### Upcoming Tasks
- **Week 7 (Nov 3 - Nov 9):** Integrate with CI/CD tools to enable automated security scans during builds and deployments.
- **Week 8 (Nov 10 - Nov 16):** Test the package across various projects for compatibility and performance; resolve any identified issues.
- **Week 9 (Nov 17 - Nov 23):** Document the package thoroughly, including setup and usage guides for developers.
- **Week 10 (Nov 24 - Nov 30):** Publish the package on NuGet for the developer community.

## Example of Resulting Report

After each scan, a comprehensive report is generated, detailing:
- **Detected Vulnerabilities:** Lists each vulnerability type and affected endpoints.
- **AI Recommendations:** Provides customized guidance on addressing each detected vulnerability.
