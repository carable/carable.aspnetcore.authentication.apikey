using System;
using Carable.AspNetCore.Authentication.ApiKey;
using Microsoft.AspNetCore.Authentication;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class ApiKeyExtensions
    {
        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder builder)
            => builder.AddApiKey(ApiKeyDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder builder, Action<ApiKeyOptions> configureOptions)
            => builder.AddApiKey(ApiKeyDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder builder, string authenticationScheme, Action<ApiKeyOptions> configureOptions)
            => builder.AddApiKey(authenticationScheme, displayName: null, configureOptions: configureOptions);

        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<ApiKeyOptions> configureOptions)
        {
            return builder.AddScheme<ApiKeyOptions, ApiKeyAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
