using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    internal class ApiKeyMiddleware : AuthenticationMiddleware<ApiKeyOptions>
    {
        public ApiKeyMiddleware(RequestDelegate next, IOptions<ApiKeyOptions> options, ILoggerFactory loggerFactory, UrlEncoder encoder) : base(next, options, loggerFactory, encoder)
        {
        }

        protected override AuthenticationHandler<ApiKeyOptions> CreateHandler()
        {
            return new ApiKeyAuthenticationHandler();
        }
    }
}