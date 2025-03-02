using api_auth_service.Entity;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace api_auth_service.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        [HttpGet("current-user")]
        public IActionResult GetCurrentUser()
        {
            // Extract JWT token from Authorization header
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

            if (string.IsNullOrEmpty(token))
            {
                return Unauthorized(new { message = "Missing or invalid token" });
            }

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadToken(token) as JwtSecurityToken;

                if (jwtToken == null)
                {
                    return Unauthorized(new { message = "Invalid JWT token" });
                }

                // Extract all claims (useful for debugging)
                var claims = jwtToken.Claims.ToDictionary(c => c.Type, c => c.Value);
                var json = new
                {
                    UserInfo = new
                    {
                        Name = claims.ContainsKey("name") ? claims["name"] : null,
                        Email = (claims.ContainsKey(System.Security.Claims.ClaimTypes.Email) ? claims[System.Security.Claims.ClaimTypes.Email] : null) ??
                                (claims.ContainsKey("email") ? claims["email"] : null),
                        Issuer = jwtToken.Issuer,  // Example non-important claim
                        Expiration = jwtToken.ValidTo
                    }
                };

                return Ok(json);
            }
            catch (Exception ex)
            {
                return Unauthorized(new { message = "Invalid JWT token", error = ex.Message });
            }
        }
    }


}
