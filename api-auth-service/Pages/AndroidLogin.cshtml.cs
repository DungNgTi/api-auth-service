using Google.Apis.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Net;
using System.Threading.Tasks;

namespace api_auth_service.Pages
{
    [IgnoreAntiforgeryToken] // Ignore CSRF protection for this login
    public class AndroidLoginModel : PageModel
    {
        [BindProperty]
        public string IdToken { get; set; }

        [BindProperty]
        public string AppCallbackUrl { get; set; }

        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                if (string.IsNullOrEmpty(IdToken))
                {
                    return StatusCode((int)HttpStatusCode.Unauthorized, "No token received.");
                }

                // Validate Google ID token
                var payload = await GoogleJsonWebSignature.ValidateAsync(IdToken);

                // Serialize payload
                var tokenData = Newtonsoft.Json.JsonConvert.SerializeObject(payload);

                // Store token in a secure HTTP-only cookie
                Response.Cookies.Append("googleToken", tokenData, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Expires = DateTime.UtcNow.AddMinutes(30)
                });

                // Redirect back to the Android app with the token data
                if (!string.IsNullOrEmpty(AppCallbackUrl))
                {
                    string redirectUrl = $"{AppCallbackUrl}?token={Uri.EscapeDataString(IdToken)}";
                    return Redirect(redirectUrl);
                }

                return new OkObjectResult(new { message = "Login successful, but no callback URL was provided." });
            }
            catch (Exception ex)
            {
                return StatusCode((int)HttpStatusCode.Unauthorized, new { message = "Invalid Google ID token", error = ex.Message });
            }
        }
    }
}
