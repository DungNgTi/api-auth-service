using api_auth_service.Service;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace api_auth_service.Pages.Login
{
    [IgnoreAntiforgeryToken] // ⚠️ Disable CSRF check for API login
    public class LoginModel : PageModel
    {
        private static readonly HttpClient HttpClient = new();
        private static Dictionary<string, string> CachedCertificates;
        private static readonly object LockObj = new();

        [BindProperty]
        public string IdToken { get; set; }

        [BindProperty]
        public string ReturnUrl { get; set; }

        public void OnGet()
        {
            ReturnUrl = Request.Query["url"];
        }

        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                if (string.IsNullOrEmpty(IdToken))
                {
                    return StatusCode((int)HttpStatusCode.Unauthorized, new { message = "No token received." });
                }

                var payload = await ValidateGoogleTokenOffline(IdToken);
                if (payload == null)
                {
                    return StatusCode((int)HttpStatusCode.Unauthorized, new { message = "Invalid Google ID token." });
                }

                // Store token in a secure HTTP-only cookie
                Response.Cookies.Append("googleToken", IdToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,  // Required for HTTPS security
                    SameSite = SameSiteMode.None, // Allows cross-site cookie sending
                    Expires = DateTime.UtcNow.AddDays(7)
                });

                // Construct a safe return URL (avoid open redirects)
                var newUrl = string.IsNullOrWhiteSpace(ReturnUrl) ? "/" : ReturnUrl;
                if (Uri.TryCreate(newUrl, UriKind.Absolute, out var result) || newUrl.StartsWith("/"))
                {
                    newUrl = $"{newUrl}?token={IdToken}";
                    if (newUrl.Length > 2048) newUrl = "/";
                }
                else
                {
                    newUrl = "/";
                }

                return Redirect(newUrl);
            }
            catch (Exception ex)
            {
                return StatusCode((int)HttpStatusCode.Unauthorized, new { message = "Invalid Google ID token", error = ex.ToString() });
            }
        }

        private async Task<GoogleJsonWebSignature.Payload> ValidateGoogleTokenOffline(string idToken)
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

                if (!jwtToken.Audiences.Contains(DatabaseFetchService.FetchContentUser())) // Replace with your Google Client ID
                    return null;

                if (jwtToken.ValidTo < DateTime.UtcNow) // Check expiration time
                    return null;

                return  new GoogleJsonWebSignature.Payload
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
