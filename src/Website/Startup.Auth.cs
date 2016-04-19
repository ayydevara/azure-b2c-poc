using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNet.Builder;
using Microsoft.Extensions.OptionsModel;
using Website.Properties;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Globalization;
using System.Threading;
using Microsoft.AspNet.Authentication.Cookies;
using Microsoft.AspNet.Authentication.OpenIdConnect;
using Microsoft.AspNet.Http;
using Website.PolicyAuthHelpers;

namespace Website
{
    public partial class Startup
    {
        // The ACR claim is used to indicate which policy was executed 
        public const string AcrClaimType = "http://schemas.microsoft.com/claims/authnclassreference";
        public const string PolicyKey = "b2cpolicy";
        public const string OidcMetadataSuffix = "/.well-known/openid-configuration";

        public void ConfigureAuth(IApplicationBuilder app, IOptions<AzureAdSettings> azureAdSettings)
        {
            // Configure the OWIN Pipeline to use Cookie Authentication 
            app.UseCookieAuthentication(options =>
            {
                // By default, all middleware are passive/not automatic. Making cookie middleware automatic so that it acts on all the messages. 
                options.AutomaticAuthenticate = true;
                options.AutomaticChallenge = true;
                options.LoginPath = "/account/SignIn";
            });
            // app.UseSteamAuthentication();
            app.UseOpenIdConnectAuthentication(options =>
            {
                options.Scope.Add("openid");
                options.Scope.Add("email");
                options.Scope.Add("profile");
                options.ClientId = azureAdSettings.Value.ClientId;
                options.ResponseType = OpenIdConnectResponseTypes.IdToken;
                options.SaveTokensAsClaims = true;
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.AuthenticationMethod = OpenIdConnectRedirectBehavior.FormPost;
                options.Authority = string.Format(CultureInfo.InvariantCulture, azureAdSettings.Value.AadInstance, azureAdSettings.Value.Tenant, string.Empty, string.Empty);
                options.CallbackPath = new PathString("/account/ExternalLogin");
                options.Events = new OpenIdConnectEvents
                {
                    OnAuthenticationFailed = OnAuthenticationFailed,
                    OnRedirectToAuthenticationEndpoint = OnRedirectToAuthenticationEndpoint,
                };

                // The PolicyConfigurationManager takes care of getting the correct Azure AD authentication 
                // endpoints from the OpenID Connect metadata endpoint.  It is included in the PolicyAuthHelpers folder. 
                options.ConfigurationManager = new PolicyConfigurationManager(
                    string.Format(CultureInfo.InvariantCulture, azureAdSettings.Value.AadInstance,
                        azureAdSettings.Value.Tenant, "/v2.0", OidcMetadataSuffix),
                    new string[]
                    {
                        azureAdSettings.Value.SignUpPolicyId, azureAdSettings.Value.SignInPolicyId,
                        azureAdSettings.Value.UserProfilePolicyId
                    });

            });
        }

        private Task OnAuthenticationFailed(AuthenticationFailedContext context)
        {
            context.HandleResponse();
            context.Response.Redirect("/Home/Error?message=" + context.Exception.Message);
            return Task.FromResult(0);
        }


        // This notification can be used to manipulate the OIDC request before it is sent.  Here we use it to send the correct policy. 
        private async Task OnRedirectToAuthenticationEndpoint(RedirectContext context)
        {
            var azureAdSettings = (IOptions<AzureAdSettings>)context.HttpContext.ApplicationServices.GetService(typeof(IOptions<AzureAdSettings>));
            var mgr = context.Options.ConfigurationManager as PolicyConfigurationManager;
            if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest && mgr != null)
            {
                if (context.Request.Path.Value.ToLower().Contains("signup"))
                {
                    var config = await mgr.GetConfigurationByPolicyAsync(CancellationToken.None, azureAdSettings.Value.SignUpPolicyId);
                    context.ProtocolMessage.IssuerAddress = config.EndSessionEndpoint;
                }
                else if (context.Request.Path.Value.ToLower().Contains("signin"))
                {
                    var config = await mgr.GetConfigurationByPolicyAsync(CancellationToken.None, azureAdSettings.Value.SignInPolicyId);
                    context.ProtocolMessage.IssuerAddress = config.EndSessionEndpoint;
                }
                else if (context.Request.Path.Value.ToLower().Contains("profile"))
                {
                    var config = await mgr.GetConfigurationByPolicyAsync(CancellationToken.None, azureAdSettings.Value.UserProfilePolicyId);
                    context.ProtocolMessage.IssuerAddress = config.EndSessionEndpoint;
                }
            }
            else if (mgr != null)
            {
                if (context.Request.Path.Value.ToLower().Contains("signup"))
                {
                    var config = await mgr.GetConfigurationByPolicyAsync(CancellationToken.None, azureAdSettings.Value.SignUpPolicyId);
                    context.ProtocolMessage.IssuerAddress = config.AuthorizationEndpoint;
                }
                else if (context.Request.Path.Value.ToLower().Contains("signin"))
                {
                    var config = await mgr.GetConfigurationByPolicyAsync(CancellationToken.None, azureAdSettings.Value.SignInPolicyId);
                    context.ProtocolMessage.IssuerAddress = config.AuthorizationEndpoint;
                }
                else if (context.Request.Path.Value.ToLower().Contains("profile"))
                {
                    var config = await mgr.GetConfigurationByPolicyAsync(CancellationToken.None, azureAdSettings.Value.UserProfilePolicyId);
                    context.ProtocolMessage.IssuerAddress = config.AuthorizationEndpoint;
                }
            }
        }

    }
}
