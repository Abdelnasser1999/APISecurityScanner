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
    public class SQLInjectionScannerTests
    {
        [Fact]
        public async Task Scan_ShouldNotThrowException_WhenEndpointIsValid()
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
                    Content = new StringContent("Valid response") // Simulate a normal API response
                });

            var httpClient = new HttpClient(mockHttpMessageHandler.Object);
            var scanner = new SQLInjectionScanner(httpClient);
            string testEndpoint = "https://example.com/api/test"; // Mock endpoint

            var requiredParams = new Dictionary<string, string>
            {
                { "param1", "value1" }
            };

            var optionalParams = new List<string>
            {
                "param2"
            };

            // Act & Assert
            var exception = await Record.ExceptionAsync(() => scanner.Scan(testEndpoint, requiredParams, optionalParams, HttpMethod.Get));
            Assert.Null(exception); // Ensuring that no exception is thrown
        }

        [Fact]
        public async Task Scan_ShouldDetectSQLInjection_WhenVulnerableEndpointIsGiven()
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
                    Content = new StringContent("SQL syntax error") // Simulate SQL injection detection
                });

            var httpClient = new HttpClient(mockHttpMessageHandler.Object);
            var scanner = new SQLInjectionScanner(httpClient);
            string vulnerableEndpoint = "https://example.com/api/vulnerable"; // Mock vulnerable endpoint

            var requiredParams = new Dictionary<string, string>
            {
                { "param1", "value1" }
            };

            var optionalParams = new List<string>
            {
                "param2"
            };

            // Act
            await scanner.Scan(vulnerableEndpoint, requiredParams, optionalParams, HttpMethod.Get);

            // Assert
            Assert.NotEmpty(scanner.Vulnerabilities); // Ensure that vulnerabilities are detected
        }
    }
}
