using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using Moq.Protected;
using Xunit;
using APISecurityScanner.Scanners;

namespace APISecurityScanner.Tests
{
    public class XSSScannerTests
    {
        [Fact]
        public async Task Scan_ShouldDetectXSS_WhenVulnerableEndpointIsGiven()
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
                    Content = new StringContent("<script>alert('XSS')</script>") // Simulate XSS vulnerability detection
                });

            var httpClient = new HttpClient(mockHttpMessageHandler.Object);
            var scanner = new XSSScanner(httpClient);
            string vulnerableEndpoint = "https://example.com/api/vulnerable"; // Mock vulnerable endpoint

            // Act
            await scanner.Scan(vulnerableEndpoint);

            // Assert
            // Ensure that the XSS vulnerability was detected
            Assert.NotNull(scanner.Vulnerabilities); // Ensure the list is not null
            Assert.NotEmpty(scanner.Vulnerabilities); // Ensure there's at least one vulnerability detected
        }
    }
}
