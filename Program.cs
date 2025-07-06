// App1/Program.cs

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection; // Needed for AddDataProtection
using System.IO; // Needed for Directory.GetCurrentDirectory

var builder = WebApplication.CreateBuilder(args);

// --- 1. App1's Authentication (Simple Hardcoded User) ---
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/AccessDenied";
        options.Cookie.IsEssential = true; // Mark the cookie as essential for the application to function
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Ensure cookie is only sent over HTTPS
        options.Cookie.SameSite = SameSiteMode.Lax; // Lax is generally safe for cross-site requests (default)
        options.Cookie.HttpOnly = true; // Prevent client-side JavaScript access to the cookie
        options.ExpireTimeSpan = TimeSpan.FromHours(1); // Explicitly set cookie expiry (matches SignInAsync)
        options.SlidingExpiration = true; // Renew cookie if half of ExpireTimeSpan has passed
    });

builder.Services.AddAuthorization();
builder.Services.AddRazorPages();

// Add Anti-forgery services
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "CSRF-TOKEN";
});

// --- NEW/UPDATED: Configure Data Protection to persist keys to the file system ---
// This ensures authentication cookies remain valid across application restarts.
// Using a more explicit path relative to the content root.
var dataProtectionKeysPath = Path.Combine(builder.Environment.ContentRootPath, "DataProtectionKeys");
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionKeysPath))
    .SetApplicationName("App1SharedAuth"); // A unique name for your application

// --- 2. JWT Signing Key (for App1 to sign tokens) ---
var jwtSecret = "ThisIsASuperSecureSecretKeyForJWTSigningThatIsAtLeast32BytesLong";
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
builder.Services.AddSingleton(signingKey);

var app = builder.Build();

// --- Retrieve IConfiguration and App Origins AFTER app.Build() ---
var configuration = app.Services.GetRequiredService<IConfiguration>();
var app1Origin = configuration["AppOrigins:App1Origin"];
var app2Origin = configuration["AppOrigins:App2Origin"];

app.Logger.LogInformation($"App1: Configured App1Origin: {app1Origin}");
app.Logger.LogInformation($"App1: Configured App2Origin: {app2Origin}");
app.Logger.LogInformation($"App1: Data Protection keys path: {dataProtectionKeysPath}"); // NEW LOG

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

// --- 3. Custom OIDC-like Endpoints for App1 (Simplified IdP) ---
app.MapGet("/.well-known/openid-configuration", (HttpContext context) =>
{
    var issuer = app1Origin;
    return Results.Json(new
    {
        issuer = issuer,
        authorization_endpoint = $"{issuer}/connect/authorize",
        jwks_uri = $"{issuer}/jwks",
        response_types_supported = new[] { "id_token token", "code" },
        scopes_supported = new[] { "openid", "profile", "project_id_scope" },
        id_token_signing_alg_values_supported = new[] { SecurityAlgorithms.HmacSha256 }
    });
});

app.MapGet("/jwks", (SymmetricSecurityKey key) =>
{
    var jwk = JsonWebKeyConverter.ConvertFromSymmetricSecurityKey(key);
    return Results.Json(new
    {
        keys = new[] {
            new
            {
                kty = jwk.Kty,
                kid = jwk.Kid,
                alg = jwk.Alg,
                k = jwk.K
            }
        }
    });
});

app.MapGet("/connect/authorize", (HttpContext context, SymmetricSecurityKey key) =>
{
    var clientId = context.Request.Query["client_id"].ToString()?.Trim();
    var responseType = context.Request.Query["response_type"].ToString()?.Trim();
    var scope = context.Request.Query["scope"].ToString()?.Trim();
    var redirectUri = context.Request.Query["redirect_uri"].ToString()?.Trim();
    var prompt = context.Request.Query["prompt"].ToString()?.Trim();
    var nonce = context.Request.Query["nonce"].ToString()?.Trim();
    var state = context.Request.Query["state"].ToString()?.Trim();

    app.Logger.LogInformation($"App1: /connect/authorize received redirect_uri: '{redirectUri}'");
    app.Logger.LogInformation($"App1: /connect/authorize expected App2Origin: '{app2Origin}'");

    if (clientId != "app2_client" || string.IsNullOrEmpty(redirectUri) || !redirectUri.StartsWith($"{app2Origin}/silent-refresh"))
    {
        app.Logger.LogWarning($"App1: Invalid client_id ('{clientId}') or redirect_uri ('{redirectUri}'). Validation failed against expected '{app2Origin}/silent-refresh'.");
        return Results.Redirect($"{redirectUri ?? app2Origin}/?error=invalid_request&state={state}");
    }

    if (prompt == "none" && !context.User.Identity?.IsAuthenticated == true)
    {
        app.Logger.LogWarning("App1: Silent authentication requested but user is not authenticated.");
        return Results.Redirect($"{redirectUri}?error=login_required&state={state}");
    }

    if (!context.User.Identity?.IsAuthenticated == true)
    {
        app.Logger.LogInformation("App1: User not authenticated, redirecting to login.");
        return Results.Redirect("/login");
    }

    var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "unknown_user_id";
    var username = context.User.Identity?.Name ?? "unknown_user";
    var projectId = "proj_xyz_123";

    var idTokenHandler = new JwtSecurityTokenHandler();
    var idTokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("sub", userId),
            new Claim("name", username),
            new Claim("project_id", projectId),
            new Claim("nonce", nonce ?? string.Empty)
        }),
        Expires = DateTime.UtcNow.AddMinutes(5),
        Issuer = app1Origin,
        Audience = clientId,
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
    };
    var idToken = idTokenHandler.CreateToken(idTokenDescriptor);
    var encodedIdToken = idTokenHandler.WriteToken(idToken);

    var accessTokenHandler = new JwtSecurityTokenHandler();
    var accessTokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("sub", userId),
            new Claim("scope", scope ?? string.Empty)
        }),
        Expires = DateTime.UtcNow.AddMinutes(1),
        Issuer = app1Origin,
        Audience = "app2_api_resource",
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
    };
    var accessToken = accessTokenHandler.CreateToken(accessTokenDescriptor);
    var encodedAccessToken = accessTokenHandler.WriteToken(accessToken);

    var responseFragment = $"#id_token={encodedIdToken}&access_token={encodedAccessToken}&token_type=Bearer&expires_in=300&state={state}";
    app.Logger.LogInformation($"App1: Redirecting to {redirectUri}{responseFragment}");
    return Results.Redirect($"{redirectUri}{responseFragment}");
});

app.Run();

public static class JsonWebKeyConverter
{
    public static JsonWebKey ConvertFromSymmetricSecurityKey(SymmetricSecurityKey key)
    {
        return new JsonWebKey
        {
            Kty = "oct",
            Alg = SecurityAlgorithms.HmacSha256,
            Kid = key.KeyId ?? Guid.NewGuid().ToString("N"),
            K = Base64UrlEncoder.Encode(key.Key)
        };
    }
}
