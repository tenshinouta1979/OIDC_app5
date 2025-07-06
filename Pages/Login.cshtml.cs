// App1/Pages/Login.cshtml.cs

using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using System.Collections.Generic;
using System.Threading.Tasks;

// IMPORTANT: Replace 'App1' with your actual project's root namespace if it's different (e.g., 'OIDC_app5')
namespace OIDC_app5.Pages // Assuming your App1 project's root namespace is OIDC_app5
{
    public class LoginModel : PageModel
    {
        private readonly ILogger<LoginModel> _logger; // Declare logger

        public LoginModel(ILogger<LoginModel> logger) // Inject ILogger
        {
            _logger = logger;
        }

        public async Task<IActionResult> OnPostAsync(string username, string password)
        {
            if (username == "testuser" && password == "password123")
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.NameIdentifier, "user_001") // Unique ID for the user
                };

                var claimsIdentity = new ClaimsIdentity(
                    claims, CookieAuthenticationDefaults.AuthenticationScheme);

                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = true, // Keep session persistent
                    ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1) // Cookie expiry
                };

                _logger.LogInformation($"App1 Login: Signing in user '{username}'. IsPersistent: {authProperties.IsPersistent}, ExpiresUtc: {authProperties.ExpiresUtc}");

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                // Redirect to the original URL or home after login
                return LocalRedirect(Url.Content("~/"));
            }

            ViewData["ErrorMessage"] = "Invalid username or password.";
            return Page();
        }

        // The OnPostLogoutAsync handler has been moved to Index.cshtml.cs
        // If you had any other methods here, they would remain.
    }
}
