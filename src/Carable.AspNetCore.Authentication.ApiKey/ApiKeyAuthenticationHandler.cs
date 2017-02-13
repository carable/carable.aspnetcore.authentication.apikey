using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using System.Text;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    internal class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyOptions>
    {
        /// <summary>
        /// Searches the 'Authorization' header for a 'Apikey' token.
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string apiKey = null;
            AuthenticateResult result = null;
            try
            {
                // Give application opportunity to find from a different location, adjust, or reject api key
                var messageReceivedContext = new MessageReceivedContext(Context, Options);

                // event can set the token
                await Options.Events.MessageReceived(messageReceivedContext);
                if (messageReceivedContext.CheckEventResult(out result))
                {
                    return result;
                }

                // If application retrieved token from somewhere else, use that.
                apiKey = messageReceivedContext.Token;

                if (string.IsNullOrEmpty(apiKey))
                {
                    string authorization = Request.Headers["Authorization"];

                    // If no authorization header found, nothing to process further
                    if (string.IsNullOrEmpty(authorization))
                    {
                        return AuthenticateResult.Skip();
                    }

                    if (authorization.StartsWith(Options.AuthenticationScheme + " ", StringComparison.OrdinalIgnoreCase))
                    {
                        apiKey = authorization.Substring(Options.AuthenticationScheme.Length + 1).Trim();
                    }

                    // If no token found, no further work possible
                    if (string.IsNullOrEmpty(apiKey))
                    {
                        return AuthenticateResult.Skip();
                    }
                }

                List<Exception> validationFailures = null;
                ValidatedApiKey validatedToken;
                foreach (var validator in Options.SecurityValidators)
                {
                    if (validator.CanReadApiKey(apiKey))
                    {
                        ClaimsPrincipal principal;
                        try
                        {
                            principal = validator.ValidateApiKey(new ApiKeyValidationContext { Options = Options }, apiKey, out validatedToken);
                        }
                        catch (Exception ex)
                        {
                            Logger.ApiKeyValidationFailed(apiKey, ex);

                            if (validationFailures == null)
                            {
                                validationFailures = new List<Exception>(1);
                            }
                            validationFailures.Add(ex);
                            continue;
                        }

                        Logger.ApiKeyValidationSucceeded();

                        var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), Options.AuthenticationScheme);
                        var tokenValidatedContext = new ApiKeyValidatedContext(Context, Options)
                        {
                            Ticket = ticket,
                            ApiKey = validatedToken,
                        };

                        await Options.Events.ApiKeyValidated(tokenValidatedContext);
                        if (tokenValidatedContext.CheckEventResult(out result))
                        {
                            return result;
                        }
                        ticket = tokenValidatedContext.Ticket;

                        return AuthenticateResult.Success(ticket);
                    }
                }

                if (validationFailures != null)
                {
                    var authenticationFailedContext = new AuthenticationFailedContext(Context, Options)
                    {
                        Exception = (validationFailures.Count == 1) ? validationFailures[0] : new AggregateException(validationFailures)
                    };

                    await Options.Events.AuthenticationFailed(authenticationFailedContext);
                    if (authenticationFailedContext.CheckEventResult(out result))
                    {
                        return result;
                    }

                    return AuthenticateResult.Fail(authenticationFailedContext.Exception);
                }

                return AuthenticateResult.Fail("No SecurityTokenValidator available for token: " + apiKey ?? "[null]");
            }
            catch (Exception ex)
            {
                Logger.ErrorProcessingMessage(ex);

                var authenticationFailedContext = new AuthenticationFailedContext(Context, Options)
                {
                    Exception = ex
                };

                await Options.Events.AuthenticationFailed(authenticationFailedContext);
                if (authenticationFailedContext.CheckEventResult(out result))
                {
                    return result;
                }

                throw;
            }
        }

        protected override async Task<bool> HandleUnauthorizedAsync(ChallengeContext context)
        {
            var authResult = await HandleAuthenticateOnceSafeAsync();

            var eventContext = new ApiKeyChallengeContext(Context, Options, new AuthenticationProperties(context.Properties))
            {
                AuthenticateFailure = authResult?.Failure
            };

            // Avoid returning error=invalid_token if the error is not caused by an authentication failure (e.g missing token).
            if (Options.IncludeErrorDetails && eventContext.AuthenticateFailure != null)
            {
                eventContext.Error = "invalid_api_key";
                eventContext.ErrorDescription = CreateErrorDescription(eventContext.AuthenticateFailure);
            }

            await Options.Events.Challenge(eventContext);
            if (eventContext.HandledResponse)
            {
                return true;
            }
            if (eventContext.Skipped)
            {
                return false;
            }

            Response.StatusCode = 401;

            if (string.IsNullOrEmpty(eventContext.Error) &&
                string.IsNullOrEmpty(eventContext.ErrorDescription) &&
                string.IsNullOrEmpty(eventContext.ErrorUri))
            {
                Response.Headers.Append(HeaderNames.WWWAuthenticate, Options.Challenge);
            }
            else
            {
                // https://tools.ietf.org/html/rfc6750#section-3.1
                // WWW-Authenticate: Bearer realm="example", error="invalid_api_key", error_description="something"
                var builder = new StringBuilder(Options.Challenge);
                if (Options.Challenge.IndexOf(" ", StringComparison.Ordinal) > 0)
                {
                    // Only add a comma after the first param, if any
                    builder.Append(',');
                }
                if (!string.IsNullOrEmpty(eventContext.Error))
                {
                    builder.Append(" error=\"");
                    builder.Append(eventContext.Error);
                    builder.Append("\"");
                }
                if (!string.IsNullOrEmpty(eventContext.ErrorDescription))
                {
                    if (!string.IsNullOrEmpty(eventContext.Error))
                    {
                        builder.Append(",");
                    }

                    builder.Append(" error_description=\"");
                    builder.Append(eventContext.ErrorDescription);
                    builder.Append('\"');
                }
                if (!string.IsNullOrEmpty(eventContext.ErrorUri))
                {
                    if (!string.IsNullOrEmpty(eventContext.Error) ||
                        !string.IsNullOrEmpty(eventContext.ErrorDescription))
                    {
                        builder.Append(",");
                    }

                    builder.Append(" error_uri=\"");
                    builder.Append(eventContext.ErrorUri);
                    builder.Append('\"');
                }

                Response.Headers.Append(HeaderNames.WWWAuthenticate, builder.ToString());
            }

            return false;
        }

        private static string CreateErrorDescription(Exception authFailure)
        {
            IEnumerable<Exception> exceptions;
            if (authFailure is AggregateException)
            {
                var agEx = authFailure as AggregateException;
                exceptions = agEx.InnerExceptions;
            }
            else
            {
                exceptions = new[] { authFailure };
            }

            var messages = new List<string>();

            foreach (var ex in exceptions)
            {
                //// Order sensitive, some of these exceptions derive from others
                //// and we want to display the most specific message possible.
                if (ex is ApiKeyNotFoundException)
                {
                    messages.Add("Could not find the API Key");
                }
            }

            return string.Join("; ", messages);
        }

        protected override Task HandleSignOutAsync(SignOutContext context)
        {
            throw new NotSupportedException();
        }

        protected override Task HandleSignInAsync(SignInContext context)
        {
            throw new NotSupportedException();
        }
    }
}