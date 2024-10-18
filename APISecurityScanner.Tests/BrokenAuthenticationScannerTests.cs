﻿using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using Moq.Protected;
using Xunit;
using APISecurityScanner.Scanners;

namespace APISecurityScanner.Tests
{
    public class BrokenAuthenticationScannerTests
    {
        [Fact]
        public async Task Scan_ShouldDetectBrokenAuthentication_WhenVulnerableEndpointIsGiven()
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
                    Content = new StringContent("Access Granted without Authentication") // Simulate broken authentication
                });

            var httpClient = new HttpClient(mockHttpMessageHandler.Object);
            var scanner = new BrokenAuthenticationScanner(httpClient);
            string vulnerableEndpoint = "https://example.com/api/protected"; // Mock vulnerable endpoint

            // Act
            await scanner.Scan(vulnerableEndpoint);

            // Assert
            Assert.NotNull(scanner.Vulnerabilities); // Ensure the vulnerabilities list is not null
            Assert.NotEmpty(scanner.Vulnerabilities); // Ensure at least one vulnerability is detected
        }
    }
}
