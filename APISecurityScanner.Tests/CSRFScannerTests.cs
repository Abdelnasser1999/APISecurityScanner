﻿using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using Moq.Protected;
using Xunit;
using APISecurityScanner.Scanners;
using System.Collections.Generic;

namespace APISecurityScanner.Tests
{
    public class CSRFScannerTests
    {
        [Fact]
        public async Task Scan_ShouldDetectCSRF_WhenVulnerableEndpointIsGiven()
        {
            // Arrange
            var mockHttpMessageHandler = new Mock<HttpMessageHandler>();

            mockHttpMessageHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("No CSRF token found") // Simulate CSRF vulnerability detection
                });

            var httpClient = new HttpClient(mockHttpMessageHandler.Object);
            var scanner = new CSRFScanner(httpClient);
            string vulnerableEndpoint = "https://example.com/api/vulnerable"; // Mock vulnerable endpoint

            var requiredParams = new Dictionary<string, string>
            {
                { "sessionId", "validSessionId" }
            };

            var optionalParams = new List<string>
            {
                "csrf_token"
            };

            // Act
            await scanner.Scan(vulnerableEndpoint, requiredParams, optionalParams, HttpMethod.Get);

            // Assert
            Assert.NotNull(scanner.Vulnerabilities); // Ensure the list is not null
            Assert.NotEmpty(scanner.Vulnerabilities); // Ensure there's at least one vulnerability detected
        }
    }
}
