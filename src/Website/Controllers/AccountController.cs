using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Mvc;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.Extensions.OptionsModel;
using Website.Properties;
using Microsoft.AspNet.Authentication.OpenIdConnect;
using Microsoft.AspNet.Authentication.Cookies;
using System.Security.Claims;
using Microsoft.AspNet.Authorization;

namespace Website.Controllers
{
    public class AccountController : Controller
    {
        private readonly AzureAdSettings _azureAdSettings;

        public AccountController(IOptions<AzureAdSettings> azureAdSettings)
        {
            _azureAdSettings = azureAdSettings.Value;
        }

        public IActionResult SignIn()
        {
            if (HttpContext.User == null || !HttpContext.User.Identity.IsAuthenticated)
                return new ChallengeResult(OpenIdConnectDefaults.AuthenticationScheme,
                    new AuthenticationProperties(new Dictionary<string, string> {
                             {Startup.PolicyKey, _azureAdSettings.SignInPolicyId}
                         })
                    { RedirectUri = _azureAdSettings.RedirectUri });


            return RedirectToAction("Index");

        }

        public IActionResult ExternalLogin()
        {
            return RedirectToRoute("default");
        }

        public IActionResult SignUp()
        {
            if (HttpContext.User == null || !HttpContext.User.Identity.IsAuthenticated)
                return new ChallengeResult(OpenIdConnectDefaults.AuthenticationScheme,
                    new AuthenticationProperties(new Dictionary<string, string> {
                             {Startup.PolicyKey, _azureAdSettings.SignUpPolicyId}
                         })
                    { RedirectUri = _azureAdSettings.RedirectUri });

            return RedirectToAction("Index");
        }

        public IActionResult Profile()
        {
            if (HttpContext.User == null || HttpContext.User.Identity.IsAuthenticated)
                return new ChallengeResult(OpenIdConnectDefaults.AuthenticationScheme,
                    new AuthenticationProperties(new Dictionary<string, string> {
                             {Startup.PolicyKey, _azureAdSettings.UserProfilePolicyId}
                         })
                    { RedirectUri = _azureAdSettings.RedirectUri });

            return RedirectToAction("Index");
        }

        public IActionResult SignOut()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                HttpContext.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    new AuthenticationProperties(new Dictionary<string, string> {
                         {Startup.PolicyKey, User.FindFirst(Startup.AcrClaimType).Value}
                     })
                    { RedirectUri = _azureAdSettings.RedirectUri });

                HttpContext.Authentication.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme,
                    new AuthenticationProperties(new Dictionary<string, string> {
                         {Startup.PolicyKey, User.FindFirst(Startup.AcrClaimType).Value}
                     })
                    { RedirectUri = _azureAdSettings.RedirectUri });
            }

            return RedirectToAction("Index");
        }

        [AllowAnonymous]
        [Authorize]
        public IActionResult Index()
        {
            return View();
        }
    }
}
