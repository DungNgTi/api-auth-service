using Google.Apis.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Net;
using System.Threading.Tasks;

namespace api_auth_service.Pages.Login
{
    [IgnoreAntiforgeryToken] // ⚠️ Disable CSRF check for API login
    public class LoginModel : PageModel
    {
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
                    return StatusCode((int)HttpStatusCode.Unauthorized, "No token received.");
                }

                // Validate the Google ID token
                var payload = await GoogleJsonWebSignature.ValidateAsync(IdToken);

                // Serialize payload to store in a secure cookie
                var tokenData = Newtonsoft.Json.JsonConvert.SerializeObject(payload);

                Response.Cookies.Append("googleToken", IdToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,  // Required for HTTPS security
                    SameSite = SameSiteMode.None, // Allows cross-site cookie sending
                    Expires = DateTime.UtcNow.AddDays(7)
                });

                // Redirect to the return URL (or home if missing)
                var newUrl = (ReturnUrl ?? "/");
                var fixedNewUrl = newUrl + "?token=" + IdToken;
                if (fixedNewUrl.Length < 2048) newUrl = fixedNewUrl;

                return Redirect(newUrl);
            }
            catch (Exception ex)
            {
                return StatusCode((int)HttpStatusCode.Unauthorized, new { message = "Invalid Google ID token", error = ex.ToString() });
            }
        }
    }
}
