# APISecurityScanner (Updated 12/06/2024)

**APISecurityScanner** is a .NET 8 NuGet package that provides automated scanning of API endpoints to detect common security vulnerabilities. Designed specifically for ASP.NET projects, it integrates seamlessly with Swagger and CI/CD pipelines, leveraging AI-powered recommendations to help developers secure their APIs.

---

## **Features**
- **Automated Scanning:** Detects vulnerabilities like SQL Injection, XSS, CSRF, IDOR, and Broken Authentication.
- **AI Recommendations:** Utilizes Google Gemini AI to provide tailored, actionable recommendations for remediating vulnerabilities.
- **Swagger Integration:** Automatically collects API endpoints from Swagger documentation, simplifying the setup process.
- **CI/CD Compatibility:** Easily integrates with GitHub Actions to enable automated security checks during builds and deployments.
- **Detailed Reporting:** Generates comprehensive, developer-friendly reports, with clear insights and remediation suggestions.

---

## **Supported Vulnerabilities**
- **SQL Injection:** Identifies malicious SQL payloads that may compromise the database.
- **Cross-Site Scripting (XSS):** Detects vulnerabilities where malicious scripts could be injected into API responses.
- **Cross-Site Request Forgery (CSRF):** Checks for the absence of CSRF tokens, which protect APIs from unauthorized commands.
- **Insecure Direct Object References (IDOR):** Verifies if endpoints improperly expose internal object references to unauthorized users.
- **Broken Authentication:** Tests API endpoints for weak or missing authentication mechanisms.

---

## **Project Structure**
- **`Scanners/`:** Contains specialized scanner modules for detecting vulnerabilities.
    - **SQLInjectionScanner.cs**
    - **XSSScanner.cs**
    - **CSRFScanner.cs**
    - **IDORScanner.cs**
    - **BrokenAuthenticationScanner.cs**
- **`Reports/`:** Manages report generation, providing actionable insights via `ReportGenerator.cs`.
- **`Helper/`:** Utilities like `EndpointData.cs` for managing endpoint metadata.
- **`Utils/`:** Includes tools like `SwaggerEndpointFetcher.cs` for fetching and managing API endpoints.
- **`AI Recommendation Service/`:** Provides AI-powered recommendations by analyzing scan results using Google Gemini AI.
- **`Tests/`:** Unit tests for individual scanner modules, ensuring accuracy and stability.
- **`ScannerConsoleApp/`:** A console-based app to run scans and generate reports.

---

## **Installation**
Install the package from NuGet using the following command:

```bash
dotnet add package APISecurityScanner
