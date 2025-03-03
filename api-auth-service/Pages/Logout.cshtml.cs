using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;

namespace api_auth_service.Pages
{
    public class LogoutModel : PageModel
    {
        [BindProperty]
        public string ReturnUrl { get; set; }

        public void OnGet()
        {
            // Get the return URL from the query string
            ReturnUrl = string.IsNullOrEmpty(Request.Query["url"]) ? "/Login" : Request.Query["url"];
        }

        public IActionResult OnPost()
        {
            // Clear the authentication cookie (remove the Google token cookie)
            Response.Cookies.Delete("googleToken");

            // Redirect to the specified return URL or default to home page if none exists
            var redirectUrl = string.IsNullOrWhiteSpace(ReturnUrl) ? "/" : ReturnUrl;

            // Redirect the user
            return Redirect(redirectUrl);
        }
    }
}
