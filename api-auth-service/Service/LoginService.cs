using Google.Apis.Auth;
using System.IdentityModel.Tokens.Jwt;

namespace api_auth_service.Service
{
    public class LoginService
    {
        public async Task<GoogleJsonWebSignature.Payload> ValidateGoogleTokenOffline(string idToken)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadToken(idToken) as JwtSecurityToken;

                if (jwtToken == null)
                    return null;

                // Validate essential claims
                if (jwtToken.Issuer != "accounts.google.com" && jwtToken.Issuer != "https://accounts.google.com")
                    return null;

                if (!jwtToken.Audiences.Contains(GoogleService.FetchContentUser())) // Replace with your Google Client ID
                    return null;

                if (jwtToken.ValidTo < DateTime.UtcNow) // Check expiration time
                    return null;

                return new GoogleJsonWebSignature.Payload
                {
                    Issuer = jwtToken.Issuer,
                    Audience = jwtToken.Audiences.FirstOrDefault(),
                    Email = jwtToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value,
                    Name = jwtToken.Claims.FirstOrDefault(c => c.Type == "name")?.Value,
                    ExpirationTimeSeconds = new DateTimeOffset(jwtToken.ValidTo).ToUnixTimeSeconds()
                };
            }
            catch
            {
                return null;
            }
        }
    }
}
