using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace AspCoreAuthentication.Basic
{
    public class BasicAuthenticationHandler<TOptions> : AuthenticationHandler<TOptions> where TOptions : AuthenticationSchemeOptions, new()
    {
        private readonly IBasicAuthenticationManager AuthManager;
        public BasicAuthenticationHandler(
        IOptionsMonitor<TOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        IBasicAuthenticationManager manager)
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
                    if (authorization.StartsWith("basic", StringComparison.OrdinalIgnoreCase))
                    {
                        string token = authorization.Substring("basic".Length).Trim();
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
                var data = Encoding.Default.GetString(Convert.FromBase64String(token)).Split(":");
                var result = await AuthManager.Authenticate(data[0], data[1]);

                if (result)
                {
                    var claims = new List<Claim>() { new Claim(ClaimTypes.Name, data[0]), };
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