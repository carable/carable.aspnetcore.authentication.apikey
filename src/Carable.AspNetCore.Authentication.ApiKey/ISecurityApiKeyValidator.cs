using System.Security.Claims;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    public interface ISecurityApiKeyValidator
    {
        ClaimsPrincipal ValidateApiKey(ApiKeyValidationContext context, string apiKey, out ValidatedApiKey validatedApiKey);
        bool CanReadApiKey(string apiKey);
    }
}