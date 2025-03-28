﻿using api_auth_service.Service;
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
        public string IsNeedRefresh { get; set; }

        [BindProperty]
        public string IdToken { get; set; }

        [BindProperty]
        public string ReturnUrl { get; set; }

        public async Task<IActionResult> OnGetAsync()
            {
            ReturnUrl = Request.Query["url"];
            var cookieValue = Request.Cookies["googleToken"];

            /*if (!string.IsNullOrEmpty(cookieValue))
            {
                try
                {
                    await buildCookie(Response, cookieValue);
                    return Redirect(buildNewUrl());
                }
                catch (Exception ex)
                {
                    return StatusCode((int)HttpStatusCode.Unauthorized, new { message = "Invalid Google ID token", error = ex.ToString() });
                }
            }*/
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (IsNeedRefresh == "true")
            {
               return Redirect(buildNewUrl());
            }
            try
            {
                if (string.IsNullOrEmpty(IdToken))
                {
                    return StatusCode((int)HttpStatusCode.Unauthorized, new { message = "No token received." });
                }

                await buildCookie(Response, IdToken);
                // Construct a safe return URL (avoid open redirects)


                //return Redirect(buildNewUrl());
                IsNeedRefresh = "true";
                return Page();
            }
            catch (Exception ex)
            {
                return StatusCode((int)HttpStatusCode.Unauthorized, new { message = "Invalid Google ID token", error = ex.ToString() });
            }
        }

        private string buildNewUrl()
        {
            var newUrl = string.IsNullOrWhiteSpace(ReturnUrl) ? "/" : ReturnUrl;
            if (Uri.TryCreate(newUrl, UriKind.Absolute, out var result) || newUrl.StartsWith("/"))
            {
                var uri = Uri.TryCreate(newUrl, UriKind.Absolute, out var newUri);
                var isHasToken = newUri.Query.Contains("token");
                var url = isHasToken ? newUri.GetLeftPart(UriPartial.Path) : newUrl;

                newUrl = $"{url}?token={IdToken}";
                if (newUrl.Length > 2048) newUrl = "/";
            }
            else
            {
                newUrl = "/";
            }
            return newUrl;
        }

        private async Task buildCookie(HttpResponse Response, string IdToken)
        {
            var payload = await _service.ValidateGoogleTokenOffline(IdToken);
            var domain = new Uri(ReturnUrl).Host;
            var isLocalHost = Request.Host.Host.Contains("localhost") || domain == "127.0.0.1";

            if (payload == null)
            {
                throw new Exception("Invalid Google Token");
            }
            // Store token in a secure HTTP-only cookie
            Response.Cookies.Append("googleToken", IdToken, new CookieOptions
            {
                HttpOnly = true,  // Prevents JavaScript access
                Secure = !isLocalHost, // Secure=True only in production
                SameSite = isLocalHost ? SameSiteMode.Lax : SameSiteMode.None, // Allows cross-origin cookie sending
                Domain = isLocalHost ? null : domain, // ✅ Allows sharing cookies across subdomains only in production
                Expires = DateTime.UtcNow.AddSeconds(timeInSecond)
            });

        }
    }

}
