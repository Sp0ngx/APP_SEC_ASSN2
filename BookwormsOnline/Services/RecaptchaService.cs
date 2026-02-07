namespace BookwormsOnline.Services
{
    public class RecaptchaService
    {
        private readonly IConfiguration _config;

        public RecaptchaService(IConfiguration config)
        {
            _config = config;
        }

        public async Task<bool> Verify(string token, string action)
        {
            if (string.IsNullOrEmpty(token))
                return false;

            var secret = _config["GoogleReCaptcha:SecretKey"];
            var client = new HttpClient();
            var response = await client.PostAsync(
                $"https://www.google.com/recaptcha/api/siteverify?secret={secret}&response={token}",
                null);

            var json = await response.Content.ReadAsStringAsync();

            // Deserialize case-insensitive
            var result = System.Text.Json.JsonSerializer.Deserialize<RecaptchaResponse>(
                json,
                new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

            if (result == null)
                return false;

            // Verify action and score
            return result.Success && result.Action == action && result.Score >= 0.5;
        }
    }

    public class RecaptchaResponse
    {
        public bool Success { get; set; }
        public float Score { get; set; }
        public string Action { get; set; } = "";
        public string Challenge_ts { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string[] ErrorCodes { get; set; } = Array.Empty<string>();
    }
}