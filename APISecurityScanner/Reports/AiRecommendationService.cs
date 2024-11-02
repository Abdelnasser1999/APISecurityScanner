using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace APISecurityScanner.Reports
{
    public class AiRecommendationService
    {
        private readonly string _apiKey;
        private readonly HttpClient _httpClient;

        public AiRecommendationService(string apiKey)
        {
            _apiKey = apiKey;
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_apiKey}");
        }

        public async Task<string> GetRecommendationAsync(string vulnerabilityType, string details)
        {
            var prompt = $"Detected a {vulnerabilityType}. Details: {details}. Please provide a recommendation for mitigating this vulnerability.";

            var requestBody = new
            {
                model = "gpt-4o-mini",
                messages = new[]
                {
            new { role = "system", content = "You are an AI cybersecurity expert providing security recommendations." },
            new { role = "user", content = prompt }
        },
                max_tokens = 100,
                temperature = 0.7
            };

            try
            {
                var response = await _httpClient.PostAsync("https://api.openai.com/v1/chat/completions",
                    new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json"));

                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var result = JsonDocument.Parse(responseContent);
                    return result.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString();
                }
                else
                {
                    // إذا لم يكن هناك نجاح، اطبع محتوى استجابة الخطأ
                    var errorContent = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Error retrieving AI recommendation: {errorContent}");
                    return "Could not retrieve AI-powered recommendation.";
                }
            }
            catch (Exception ex)
            {
                // طباعة الخطأ في حالة وجود استثناء غير متوقع
                Console.WriteLine($"Exception occurred while fetching AI recommendation: {ex.Message}");
                return "Could not retrieve AI-powered recommendation due to an error.";
            }
        }
    }
}
