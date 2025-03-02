using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using Google.Apis.Auth;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection.KeyManagement;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

// Enable CORS for all origins, headers, and methods
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

string FetchFromDatabase(string encrypted, string key) =>
    Encoding.UTF8.GetString(Aes.Create().CreateDecryptor(Encoding.UTF8.GetBytes(key), new byte[16])
        .TransformFinalBlock(Convert.FromBase64String(encrypted), 0, Convert.FromBase64String(encrypted).Length));


// Add Google authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "Cookies";
    options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
})
.AddCookie("Cookies", options =>
{
    options.Cookie.Name = "MyAuthCookie"; // Shared cookie name
    options.Cookie.Domain = ".localhost"; // Enable sharing cookies between localhost subdomains
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Secure cookie policy
    options.Cookie.SameSite = SameSiteMode.None; // Allow sharing cookies across ports
})
.AddGoogle(options =>
{
    options.ClientId = FetchFromDatabase("Y94+WuTkBaaphJTps8IvmdB2IazYjKRnMkm3rFhUR4iArt3MFxRfr9UKMUdtF6w3/Gmykqm/PdH5MwO1UaJYVWKsBMLnCwjquJnoZZYIhIc=", "0000000000000000");
    options.ClientSecret = FetchFromDatabase("afKSUhIxf/0VZsGl8bq1s2cUJ6IKnl9pn6WnlYpQv2o54228Q+0Y6CPBLXjg+m6/", "1111111111111111");  // Read from appsettings.json
    options.CallbackPath = "/signin-google"; // The callback URL after login
});

// Register Swagger services
builder.Services.AddEndpointsApiExplorer();  // Add support for API discovery
builder.Services.AddSwaggerGen();  // Enable Swagger UI

builder.Services.AddControllers();
builder.Services.AddRazorPages();

var app = builder.Build();

app.UseCors();  // Use CORS policy

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
