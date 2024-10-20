using System.Net;
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
    public class IDORScannerTests
    {
        [Fact]
        public async Task Scan_ShouldDetectIDOR_WhenVulnerableEndpointIsGiven()
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
                    Content = new StringContent("Sensitive data exposed for ID: 9999") // Simulate IDOR vulnerability
                });

            var httpClient = new HttpClient(mockHttpMessageHandler.Object);
            var scanner = new IDORScanner(httpClient);
            string vulnerableEndpoint = "https://example.com/api/resource"; // Mock vulnerable endpoint

            var requiredParams = new Dictionary<string, string>
            {
                { "userId", "1234" }
            };

            var optionalParams = new List<string>
            {
                "resourceId"
            };

            // Act
            await scanner.Scan(vulnerableEndpoint, requiredParams, optionalParams, HttpMethod.Get);

            // Assert
            Assert.NotNull(scanner.Vulnerabilities); // Ensure the vulnerabilities list is not null
            Assert.NotEmpty(scanner.Vulnerabilities); // Ensure at least one vulnerability is detected
        }
    }
}
