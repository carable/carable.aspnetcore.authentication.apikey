using System;
using System.Security.Claims;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    internal class DefaultSecurityValidator : ISecurityApiKeyValidator
    {
        public bool CanReadApiKey(string apiKey)
        {
            return true;
        }

        public ClaimsPrincipal ValidateApiKey(ApiKeyValidationContext context, string apiKey, out ValidatedApiKey validatedApiKey)
        {
            ApiKeyInfo info;
            if (context.ApiKeys.TryGetValue(apiKey, out info))
            {
                validatedApiKey = new ValidatedApiKey();
                return new ClaimsPrincipal(new ClaimsIdentity(info.Claims, context.Options.AuthenticationScheme));
            }
            throw new ApiKeyNotFoundException() { ApiKey = apiKey };
        }
    }
}