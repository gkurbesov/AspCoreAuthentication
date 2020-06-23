using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace AspCoreAuthentication.Bearer
{
    public class BearerAuthenticationHandler<TOptions> : AuthenticationHandler<TOptions> where TOptions : AuthenticationSchemeOptions, new()
    {
        private readonly IBearerAuthenticationManager AuthManager;
        public BearerAuthenticationHandler(
        IOptionsMonitor<TOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        IBearerAuthenticationManager manager)
        : base(options, logger, encoder, clock)
        {
            AuthManager = manager;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (Request.Headers.ContainsKey("Authorization"))
            {
                string authorization = Request.Headers["Authorization"];
                if (string.IsNullOrWhiteSpace(authorization))
                {
                    if (authorization.StartsWith("bearer", StringComparison.OrdinalIgnoreCase))
                    {
                        string token = authorization.Substring("bearer".Length).Trim();
                        if (!string.IsNullOrWhiteSpace(token))
                        {
                            try
                            {
                                return await ValidateToken(token);
                            }
                            catch (Exception ex)
                            {
                                return AuthenticateResult.Fail(ex.Message);
                            }
                        }
                        else
                        {
                            return AuthenticateResult.Fail("Unauthorized");
                        }
                    }
                    else
                    {
                        return AuthenticateResult.Fail("Unauthorized");
                    }
                }
                else
                {
                    return AuthenticateResult.NoResult();
                }
            }
            else
            {
                return AuthenticateResult.Fail("Unauthorized");
            }
        }


        protected virtual async Task<AuthenticateResult> ValidateToken(string token)
        {
            if (AuthManager != null)
            {
                var result = await AuthManager.ValidateToken(token);
                if (result)
                {
                    var claims = new List<Claim>() { new Claim(ClaimTypes.Name, token), };
                    var identity = new ClaimsIdentity(claims, Scheme.Name);
                    var principal = new System.Security.Principal.GenericPrincipal(identity, null);
                    var ticket = new AuthenticationTicket(principal, Scheme.Name);
                    return AuthenticateResult.Success(ticket);
                }
                else
                {
                    return AuthenticateResult.Fail("Unauthorized");
                }
            }
            else
            {
                return AuthenticateResult.NoResult();
            }
        }
    }
}