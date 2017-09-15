using System;
using System.Security.Claims;

namespace Tests
{
    public partial class ApiKeyMiddlewareTests
    {
        class InvalidApiKeyValidator : ISecurityApiKeyValidator
        {
            private Type errorType;

            public InvalidApiKeyValidator(Type errorType)
            {
                this.errorType = errorType;
            }
            public InvalidApiKeyValidator()
            {
            }

            public ClaimsPrincipal ValidateApiKey(ApiKeyValidationContext context, string apiKey, out ValidatedApiKey validatedApiKey)
            {
                if (errorType != null)
                {
                    var err = (Exception)Activator.CreateInstance(errorType);
                    throw err;
                }
                throw new Exception();
            }

            public bool CanReadApiKey(string apiKey)
            {
                return true;
            }
        }
    }
}
