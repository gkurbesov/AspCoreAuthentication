using AspCoreAuthentication.Basic;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace AspCoreAuthentication
{
    public static class ServiceCollectionExtensions
    {
        public static void AddBasicAuthentication<TOptions>(this IServiceCollection services) where TOptions : AuthenticationSchemeOptions, new()
        {
            services.AddAuthentication("Basic")
                .AddScheme<TOptions, BasicAuthenticationHandler<TOptions>>("Basic", null);
        }
        public static void AddBasicAuthentication(this IServiceCollection services)
        {
            services.AddAuthentication("Basic")
                .AddScheme<BasicAuthenticationOptions, BasicAuthenticationHandler<BasicAuthenticationOptions>>("Basic", null);
        }
        public static void AddBearerAuthentication<TOptions>(this IServiceCollection services) where TOptions : AuthenticationSchemeOptions, new()
        {
            services.AddAuthentication("Bearer")
                .AddScheme<TOptions, BasicAuthenticationHandler<TOptions>>("Bearer", null);
        }
        public static void AddBearerAuthentication(this IServiceCollection services)
        {
            services.AddAuthentication("Bearer")
                .AddScheme<BasicAuthenticationOptions, BasicAuthenticationHandler<BasicAuthenticationOptions>>("Bearer", null);
        }
    }
}
