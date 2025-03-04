using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using Google.Apis.Auth;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using api_auth_service.Service;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

// Enable CORS for all origins, headers, and methods
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowDynamicOrigins", builder =>
    {
        builder.SetIsOriginAllowed(origin => true) // ✅ Allow all origins dynamically
               .AllowCredentials() // ✅ Allow sending authentication cookies
               .AllowAnyMethod()
               .AllowAnyHeader();
    });
});


// Add Google authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "Cookies";
    options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
})
.AddCookie("Cookies", options =>
{
    options.Cookie.Name = "MyAuthCookie"; // Shared cookie name
    options.Cookie.Domain = null; // Remove domain setting
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Secure cookie policy
    options.Cookie.SameSite = SameSiteMode.None; // Allow sharing cookies across ports
})
.AddGoogle(options =>
{
    options.ClientId = GoogleService.FetchContentUser();
    options.ClientSecret = GoogleService.FetchSecret();  // Read from appsettings.json
    options.CallbackPath = "/signin-google"; // The callback URL after login
});

// Register Swagger services
builder.Services.AddEndpointsApiExplorer();  // Add support for API discovery
builder.Services.AddSwaggerGen();  // Enable Swagger UI

builder.Services.AddControllers();
builder.Services.AddRazorPages();
builder.Services.AddAntiforgery(options => options.SuppressXFrameOptionsHeader = true);

var app = builder.Build();

app.UseCors("AllowDynamicOrigins");;  // Use CORS policy

app.UseAuthentication();
app.UseAuthorization();

// Enable Swagger middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();  // Serve Swagger-generated JSON
    app.UseSwaggerUI();  // Serve Swagger UI
}

app.MapControllers();
app.MapRazorPages();

if (app.Environment.IsProduction())
{
    var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
    app.Urls.Add($"http://0.0.0.0:{port}");
}

app.Run();
