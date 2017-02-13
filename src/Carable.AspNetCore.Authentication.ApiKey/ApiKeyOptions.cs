using Microsoft.AspNetCore.Builder;
using System.Collections.Generic;
using Microsoft.Extensions.Primitives;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    public class ApiKeyOptions : AuthenticationOptions
    {
        public ApiKeyOptions()
        {
            AuthenticationScheme = ApiKeyDefaults.AuthenticationScheme;
            AutomaticAuthenticate = true;
            AutomaticChallenge = true;
        }

        /// <summary>
        /// Gets or sets the challenge to put in the "WWW-Authenticate" header.
        /// </summary>
        public string Challenge { get; set; } = ApiKeyDefaults.AuthenticationScheme;
        public IApiKeyEvents Events { get; set; } = new ApiKeyEvents();
        public IDictionary<string, ApiKeyInfo> ApiKeys { get; set; } = new Dictionary<string, ApiKeyInfo>();
        /// <summary>
        /// Defines whether the api key validation errors should be returned to the caller.
        /// Enabled by default, this option can be disabled to prevent the API Key middleware
        /// from returning an error and an error_description in the WWW-Authenticate header.
        /// </summary>
        public bool IncludeErrorDetails { get; set; } = true;

        /// <summary>
        /// Gets the ordered list of <see cref="ISecurityApiKeyValidator"/> used to validate access tokens.
        /// </summary>
        public IList<ISecurityApiKeyValidator> SecurityValidators { get; } = new List<ISecurityApiKeyValidator> { new DefaultSecurityValidator() };
    }
}