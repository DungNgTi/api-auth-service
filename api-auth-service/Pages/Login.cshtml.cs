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
        public static readonly LoginService _service = new();

        private static int timeInSecond;

        public LoginModel(IConfiguration configuration)
        {
            var delay = configuration["Cookie:Second"];
            timeInSecond = delay == null ? 604800 : int.Parse(delay);
        }

        [BindProperty]
        public string IdToken { get; set; }

        [BindProperty]
        public string ReturnUrl { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            ReturnUrl = Request.Query["url"];
            var cookieValue = Request.Cookies["googleToken"];

            if (!string.IsNullOrEmpty(cookieValue))
            {
                try
                {
                    if (string.IsNullOrEmpty(cookieValue))
                    {
                        StatusCode((int)HttpStatusCode.Unauthorized, new { message = "No token received." });
                    }

                    var payload = await _service.ValidateGoogleTokenOffline(cookieValue);
                    if (payload == null)
                    {
                        return StatusCode((int)HttpStatusCode.Unauthorized, new { message = "Invalid Google ID token." });
                    }



                    // Construct a safe return URL (avoid open redirects)
                    var newUrl = string.IsNullOrWhiteSpace(ReturnUrl) ? "/" : ReturnUrl;
                    if (Uri.TryCreate(newUrl, UriKind.Absolute, out var result) || newUrl.StartsWith("/"))
                    {
                        newUrl = $"{newUrl}?token={cookieValue}";
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
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                if (string.IsNullOrEmpty(IdToken))
                {
                    return StatusCode((int)HttpStatusCode.Unauthorized, new { message = "No token received." });
                }

                var payload = await _service.ValidateGoogleTokenOffline(IdToken);
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
                    Expires = DateTime.UtcNow.AddSeconds(timeInSecond)
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

    }
}
