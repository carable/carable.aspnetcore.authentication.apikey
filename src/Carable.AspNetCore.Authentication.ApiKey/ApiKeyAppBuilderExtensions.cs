using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    /// <summary>
    /// Extension methods to add Api key authentication capabilities to an HTTP application pipeline.
    /// </summary>
    public static class ApiKeyAppBuilderExtensions
    {
        /// <summary>
        /// Adds the <see cref="ApiKeyMiddleware"/> middleware to the specified <see cref="IApplicationBuilder"/>
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the middleware to.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IApplicationBuilder UseApiKeyAuthentication(this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<ApiKeyMiddleware>();
        }

        /// <summary>
        /// Adds the <see cref="ApiKeyMiddleware"/> middleware to the specified <see cref="IApplicationBuilder"/>
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the middleware to.</param>
        /// <param name="options">A  <see cref="ApiKeyOptions"/> that specifies options for the middleware.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IApplicationBuilder UseApiKeyAuthentication(this IApplicationBuilder app, ApiKeyOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            return app.UseMiddleware<ApiKeyMiddleware>(Options.Create(options));
        }
    }
}
