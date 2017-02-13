using Carable.AspNetCore.Authentication.ApiKey;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using NUnit.Framework;
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Net.Http;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Tests
{
    [TestFixture]
    public class ApiKeyMiddlewareTests
    {
        [Test]
        public void ApiKeyValidation()
        {
            var options = GetOptions();
            var server = CreateServer(options);

            var newApiKeyHeader = "Apikey 1";
            var response = server.SendAsyncWithAuth("http://example.com/oauth", newApiKeyHeader).Result;
            Assert.AreEqual(HttpStatusCode.OK, response.Response.StatusCode);
        }

        [Test]
        public void SignInThrows()
        {
            var server = CreateServer(new ApiKeyOptions());
            var transaction = server.SendAsync("https://example.com/signIn").Result;
            Assert.AreEqual(HttpStatusCode.OK, transaction.Response.StatusCode);
        }

        [Test]
        public void SignOutThrows()
        {
            var server = CreateServer(new ApiKeyOptions());
            var transaction = server.SendAsync("https://example.com/signOut").Result;
            Assert.AreEqual(HttpStatusCode.OK, transaction.Response.StatusCode);
        }

        [Test]
        public void ThrowAtAuthenticationFailedEvent()
        {
            var options = new ApiKeyOptions
            {
                Events = new ApiKeyEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        context.Response.StatusCode = 401;
                        throw new Exception();
                    },
                    OnMessageReceived = context =>
                    {
                        context.Token = "something";
                        return Task.FromResult(0);
                    }
                }
            };
            options.SecurityValidators.Clear();
            options.SecurityValidators.Insert(0, new InvalidApiKeyValidator());

            var server = CreateServer(options, async (context, next) =>
            {
                try
                {
                    await next();
                    Assert.False(true, "Expected exception is not thrown");
                }
                catch (Exception)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("i got this");
                }
            });

            var transaction = server.SendAsync("https://example.com/signIn").Result;

            Assert.AreEqual(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Test]
        public void NoHeaderReceived()
        {
            var server = CreateServer(new ApiKeyOptions());
            var response = server.SendAsyncWithAuth("http://example.com/oauth").Result;
            Assert.AreEqual(HttpStatusCode.Unauthorized, response.Response.StatusCode);
        }

        [Test]
        public void HeaderWithoutApiKeyReceived()
        {
            var server = CreateServer(new ApiKeyOptions());
            var response = server.SendAsyncWithAuth("http://example.com/oauth", "Token").Result;
            Assert.AreEqual(HttpStatusCode.Unauthorized, response.Response.StatusCode);
        }

        [Test]
        public void UnrecognizedApiKeyReceived()
        {
            var server = CreateServer(new ApiKeyOptions());

            var response = server.SendAsyncWithAuth("http://example.com/oauth", "Apikey someblob").Result;
            Assert.AreEqual(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.AreEqual("", response.ResponseText);
        }

        [Test]
        public void InvalidApiKeyReceived()
        {
            var options = new ApiKeyOptions();
            options.SecurityValidators.Clear();
            options.SecurityValidators.Add(new InvalidApiKeyValidator());
            var server = CreateServer(options);

            var response = server.SendAsyncWithAuth("http://example.com/oauth", "Apikey someblob").Result;
            Assert.AreEqual(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.AreEqual("Apikey error=\"invalid_api_key\"", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.AreEqual("", response.ResponseText);
        }


        [Test]
        [TestCase(typeof(ArgumentException))]
        public void ExceptionNotReportedInHeaderForOtherFailures(Type errorType)
        {
            var options = new ApiKeyOptions();
            options.SecurityValidators.Clear();
            options.SecurityValidators.Add(new InvalidApiKeyValidator(errorType));
            var server = CreateServer(options);

            var response = server.SendAsyncWithAuth("http://example.com/oauth", "Apikey someblob").Result;
            Assert.AreEqual(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.AreEqual("Apikey error=\"invalid_api_key\"", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.AreEqual("", response.ResponseText);
        }


        [Test]
        public void ExceptionNotReportedInHeaderWhenIncludeErrorDetailsIsFalse()
        {
            var server = CreateServer(new ApiKeyOptions
            {
                IncludeErrorDetails = false
            });

            var response = server.SendAsyncWithAuth("http://example.com/oauth", "Apikey someblob").Result;
            Assert.AreEqual(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.AreEqual("Apikey", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.AreEqual("", response.ResponseText);
        }

        [Test]
        public void ExceptionNotReportedInHeaderWhenTokenWasMissing()
        {
            var server = CreateServer(new ApiKeyOptions());

            var response = server.SendAsyncWithAuth( "http://example.com/oauth").Result;
            Assert.AreEqual(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.AreEqual("Apikey", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.AreEqual("", response.ResponseText);
        }

        [Test]
        public void CustomTokenValidated()
        {
            var options = new ApiKeyOptions
            {
                Events = new ApiKeyEvents()
                {
                    OnApiKeyValidated = context =>
                    {
                        // Retrieve the NameIdentifier claim from the identity
                        // returned by the custom security token validator.
                        var identity = (ClaimsIdentity)context.Ticket.Principal.Identity;
                        var identifier = identity.FindFirst(ClaimTypes.NameIdentifier);

                        Assert.AreEqual("Bob le Tout Puissant", identifier.Value);

                        // Remove the existing NameIdentifier claim and replace it
                        // with a new one containing a different value.
                        identity.RemoveClaim(identifier);
                        // Make sure to use a different name identifier
                        // than the one defined by BlobTokenValidator.
                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Bob le Magnifique"));

                        return Task.FromResult<object>(null);
                    }
                }
            };
            options.SecurityValidators.Clear();
            options.SecurityValidators.Add(new BlobTokenValidator());
            var server = CreateServer(options);

            var response = server.SendAsyncWithAuth( "http://example.com/oauth", "apikey someblob").Result;
            Assert.AreEqual(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.AreEqual("Bob le Magnifique", response.ResponseText);
        }

        [Test]
        public void ApikeyTurns401To403IfAuthenticated()
        {
            var options = new ApiKeyOptions();
            options.SecurityValidators.Clear();
            options.SecurityValidators.Add(new BlobTokenValidator());
            var server = CreateServer(options);

            var response = server.SendAsyncWithAuth( "http://example.com/unauthorized", "ApiKey Key").Result;
            Assert.AreEqual(HttpStatusCode.Forbidden, response.Response.StatusCode);
        }

        [Test]
        public void ApikeyDoesNothingTo401IfNotAuthenticated()
        {
            var server = CreateServer(new ApiKeyOptions());

            var response = server.SendAsyncWithAuth( "http://example.com/unauthorized").Result;
            Assert.AreEqual(HttpStatusCode.Unauthorized, response.Response.StatusCode);
        }

        [Test]
        public void EventOnMessageReceivedSkipped_NoMoreEventsExecuted()
        {
            var server = CreateServer(new ApiKeyOptions
            {
                Events = new ApiKeyEvents()
                {
                    OnMessageReceived = context =>
                    {
                        context.SkipToNextMiddleware();
                        return Task.FromResult(0);
                    },
                    OnApiKeyValidated = context =>
                    {
                        throw new NotImplementedException();
                    },
                    OnAuthenticationFailed = context =>
                    {
                        throw new NotImplementedException(context.Exception.ToString());
                    },
                    OnChallenge = context =>
                    {
                        throw new NotImplementedException();
                    },
                }
            });

            var response = server.SendAsyncWithAuth( "http://example.com/checkforerrors", "ApiKey Key").Result;
            Assert.AreEqual(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.AreEqual(string.Empty, response.ResponseText);
        }

        [Test]
        public void EventOnMessageReceivedHandled_NoMoreEventsExecuted()
        {
            var server = CreateServer(new ApiKeyOptions
            {
                Events = new ApiKeyEvents()
                {
                    OnMessageReceived = context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = StatusCodes.Status202Accepted;
                        return Task.FromResult(0);
                    },
                    OnApiKeyValidated = context =>
                    {
                        throw new NotImplementedException();
                    },
                    OnAuthenticationFailed = context =>
                    {
                        throw new NotImplementedException(context.Exception.ToString());
                    },
                    OnChallenge = context =>
                    {
                        throw new NotImplementedException();
                    },
                }
            });

            var response = server.SendAsyncWithAuth( "http://example.com/checkforerrors", "ApiKey Key").Result;
            Assert.AreEqual(HttpStatusCode.Accepted, response.Response.StatusCode);
            Assert.AreEqual(string.Empty, response.ResponseText);
        }

        [Test]
        public void EventOnTokenValidatedSkipped_NoMoreEventsExecuted()
        {
            var options = new ApiKeyOptions
            {
                Events = new ApiKeyEvents()
                {
                    OnApiKeyValidated = context =>
                    {
                        context.SkipToNextMiddleware();
                        return Task.FromResult(0);
                    },
                    OnAuthenticationFailed = context =>
                    {
                        throw new NotImplementedException(context.Exception.ToString());
                    },
                    OnChallenge = context =>
                    {
                        throw new NotImplementedException();
                    },
                }
            };
            options.SecurityValidators.Clear();
            options.SecurityValidators.Add(new BlobTokenValidator());
            var server = CreateServer(options);

            var response = server.SendAsyncWithAuth( "http://example.com/checkforerrors", "ApiKey Key").Result;
            Assert.AreEqual(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.AreEqual(string.Empty, response.ResponseText);
        }

        [Test]
        public void EventOnTokenValidatedHandled_NoMoreEventsExecuted()
        {
            var options = new ApiKeyOptions
            {
                Events = new ApiKeyEvents()
                {
                    OnApiKeyValidated = context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = StatusCodes.Status202Accepted;
                        return Task.FromResult(0);
                    },
                    OnAuthenticationFailed = context =>
                    {
                        throw new NotImplementedException(context.Exception.ToString());
                    },
                    OnChallenge = context =>
                    {
                        throw new NotImplementedException();
                    },
                }
            };
            options.SecurityValidators.Clear();
            options.SecurityValidators.Add(new BlobTokenValidator());
            var server = CreateServer(options);

            var response = server.SendAsyncWithAuth( "http://example.com/checkforerrors", "ApiKey Key").Result;
            Assert.AreEqual(HttpStatusCode.Accepted, response.Response.StatusCode);
            Assert.AreEqual(string.Empty, response.ResponseText);
        }

        [Test]
        public void EventOnAuthenticationFailedSkipped_NoMoreEventsExecuted()
        {
            var options = new ApiKeyOptions
            {
                Events = new ApiKeyEvents()
                {
                    OnApiKeyValidated = context =>
                    {
                        throw new Exception("Test Exception");
                    },
                    OnAuthenticationFailed = context =>
                    {
                        context.SkipToNextMiddleware();
                        return Task.FromResult(0);
                    },
                    OnChallenge = context =>
                    {
                        throw new NotImplementedException();
                    },
                }
            };
            options.SecurityValidators.Clear();
            options.SecurityValidators.Add(new BlobTokenValidator());
            var server = CreateServer(options);

            var response = server.SendAsyncWithAuth( "http://example.com/checkforerrors", "ApiKey Key").Result;
            Assert.AreEqual(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.AreEqual(string.Empty, response.ResponseText);
        }

        [Test]
        public void EventOnAuthenticationFailedHandled_NoMoreEventsExecuted()
        {
            var options = new ApiKeyOptions
            {
                Events = new ApiKeyEvents()
                {
                    OnApiKeyValidated = context =>
                    {
                        throw new Exception("Test Exception");
                    },
                    OnAuthenticationFailed = context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = StatusCodes.Status202Accepted;
                        return Task.FromResult(0);
                    },
                    OnChallenge = context =>
                    {
                        throw new NotImplementedException();
                    },
                }
            };
            options.SecurityValidators.Clear();
            options.SecurityValidators.Add(new BlobTokenValidator());
            var server = CreateServer(options);

            var response = server.SendAsyncWithAuth( "http://example.com/checkforerrors", "ApiKey Key").Result;
            Assert.AreEqual(HttpStatusCode.Accepted, response.Response.StatusCode);
            Assert.AreEqual(string.Empty, response.ResponseText);
        }

        [Test]
        public void EventOnChallengeSkipped_ResponseNotModified()
        {
            var server = CreateServer(new ApiKeyOptions
            {
                Events = new ApiKeyEvents()
                {
                    OnChallenge = context =>
                    {
                        context.SkipToNextMiddleware();
                        return Task.FromResult(0);
                    },
                }
            });

            var response = server.SendAsyncWithAuth( "http://example.com/unauthorized", "ApiKey Key").Result;
            Assert.AreEqual(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.IsEmpty(response.Response.Headers.WwwAuthenticate);
            Assert.AreEqual(string.Empty, response.ResponseText);
        }

        [Test]
        public void EventOnChallengeHandled_ResponseNotModified()
        {
            var server = CreateServer(new ApiKeyOptions
            {
                Events = new ApiKeyEvents()
                {
                    OnChallenge = context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = StatusCodes.Status202Accepted;
                        return Task.FromResult(0);
                    },
                }
            });

            var response = server.SendAsyncWithAuth( "http://example.com/unauthorized", "ApiKey Key").Result;
            Assert.AreEqual(HttpStatusCode.Accepted, response.Response.StatusCode);
            Assert.IsEmpty(response.Response.Headers.WwwAuthenticate);
            Assert.AreEqual(string.Empty, response.ResponseText);
        }

        private static TestServer CreateServer(ApiKeyOptions options)
        {
            return CreateServer(options, handlerBeforeAuth: null);
        }

        private static TestServer CreateServer(ApiKeyOptions options, Func<HttpContext, Func<Task>, Task> handlerBeforeAuth)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
                {
                    if (handlerBeforeAuth != null)
                    {
                        app.Use(handlerBeforeAuth);
                    }

                    if (options != null)
                    {
                        app.UseApiKeyAuthentication(options);
                    }

                    app.Use(async (context, next) =>
                    {
                        if (context.Request.Path == new PathString("/checkforerrors"))
                        {
                            var authContext = new AuthenticateContext(Microsoft.AspNetCore.Http.Authentication.AuthenticationManager.AutomaticScheme);
                            await context.Authentication.AuthenticateAsync(authContext);
                            if (authContext.Error != null)
                            {
                                throw new Exception("Failed to authenticate", authContext.Error);
                            }
                            return;
                        }
                        else if (context.Request.Path == new PathString("/oauth"))
                        {
                            if (context.User == null ||
                                context.User.Identity == null ||
                                !context.User.Identity.IsAuthenticated)
                            {
                                context.Response.StatusCode = 401;

                                return;
                            }

                            var identifier = context.User.FindFirst(ClaimTypes.NameIdentifier);
                            if (identifier == null)
                            {
                                context.Response.StatusCode = 500;

                                return;
                            }

                            await context.Response.WriteAsync(identifier.Value);
                        }
                        else if (context.Request.Path == new PathString("/unauthorized"))
                        {
                            // Simulate Authorization failure 
                            var result = await context.Authentication.AuthenticateAsync(ApiKeyDefaults.AuthenticationScheme);
                            await context.Authentication.ChallengeAsync(ApiKeyDefaults.AuthenticationScheme);
                        }
                        else if (context.Request.Path == new PathString("/signIn"))
                        {
                            Assert.ThrowsAsync<NotSupportedException>(() => context.Authentication.SignInAsync(ApiKeyDefaults.AuthenticationScheme, new ClaimsPrincipal()));
                        }
                        else if (context.Request.Path == new PathString("/signOut"))
                        {
                            Assert.ThrowsAsync<NotSupportedException>(() => context.Authentication.SignOutAsync(ApiKeyDefaults.AuthenticationScheme));
                        }
                        else
                        {
                            await next();
                        }
                    });
                })
                .ConfigureServices(services => services.AddAuthentication());

            return new TestServer(builder);
        }
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

        private static ApiKeyOptions GetOptions()
        {
            return new ApiKeyOptions
            {
                ApiKeys = { { "1", new ApiKeyInfo { Claims = new[] { new Claim(ClaimTypes.NameIdentifier, "Chet") } } } }
            };
        }

    }
}
