using System.Collections.Generic;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    public class ApiKeyValidationContext
    {
        public ApiKeyOptions Options { get; set; }
        public IDictionary<string, ApiKeyInfo> ApiKeys => Options.ApiKeys;
    }
}