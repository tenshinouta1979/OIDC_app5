// App1/Pages/Index.cshtml.cs
using Microsoft.AspNetCore.Mvc; // Needed for IActionResult, IgnoreAntiforgeryToken
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authentication; // Needed for SignOutAsync
using Microsoft.AspNetCore.Authentication.Cookies; // Needed for CookieAuthenticationDefaults
using System.Threading.Tasks; // Needed for Task
using Microsoft.Extensions.Logging; // Needed for ILogger

// IMPORTANT: Replace 'App1' with your actual project's root namespace if it's different (e.g., 'OIDC_app5')
namespace OIDC_app5.Pages // Assuming your App1 project's root namespace is OIDC_app5
{
    public class IndexModel : PageModel
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<IndexModel> _logger; // Added for logging

        public string App1Origin { get; private set; }
        public string App2Origin { get; private set; }

        public IndexModel(IConfiguration configuration, ILogger<IndexModel> logger) // Injected ILogger
        {
            _configuration = configuration;
            _logger = logger; // Assigned logger
            App1Origin = _configuration["AppOrigins:App1Origin"] ?? "https://localhost:5001";
            App2Origin = _configuration["AppOrigins:App2Origin"] ?? "https://localhost:5002";
        }

        public IActionResult OnGet()
        {
            if (!User.Identity?.IsAuthenticated == true)
            {
                return RedirectToPage("/Login");
            }
            return Page();
        }

        [IgnoreAntiforgeryToken] // This attribute should bypass anti-forgery validation for this handler
        public async Task<IActionResult> OnPostLogoutAsync()
        {
            _logger.LogInformation("App1: OnPostLogoutAsync handler invoked. Attempting to sign out."); // NEW LOG
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            _logger.LogInformation("App1: User signed out. Redirecting to login page."); // NEW LOG
            return RedirectToPage("/Login");
        }
    }
}
