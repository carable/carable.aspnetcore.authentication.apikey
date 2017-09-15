using System;
using System.Security.Claims;

namespace Tests
{
    public partial class ApiKeyMiddlewareTests
    {
        class BlobTokenValidator : ISecurityApiKeyValidator
        {
            private Action<string> _tokenValidator;
            public BlobTokenValidator()
            {

            }

            public BlobTokenValidator(Action<string> tokenValidator)
            {
                _tokenValidator = tokenValidator;
            }

            public bool CanReadApiKey(string apiKey)
            {
                return true;
            }

            public ClaimsPrincipal ValidateApiKey(ApiKeyValidationContext context, string apiKey, out ValidatedApiKey validatedApiKey)
            {
                validatedApiKey = new ValidatedApiKey();
                _tokenValidator?.Invoke(apiKey);
                var claims = new[]
                {
                    // Make sure to use a different name identifier
                    // than the one defined by CustomTokenValidated.
                    new Claim(ClaimTypes.NameIdentifier, "Bob le Tout Puissant"),
                    new Claim(ClaimTypes.Email, "bob@contoso.com"),
                    new Claim(ClaimsIdentity.DefaultNameClaimType, "bob"),
                };

                return new ClaimsPrincipal(new ClaimsIdentity(claims, context.Options.AuthenticationScheme));
            }
        }
    }
}
