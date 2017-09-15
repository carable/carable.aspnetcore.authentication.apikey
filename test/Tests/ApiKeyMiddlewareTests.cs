using Carable.AspNetCore.Authentication.ApiKey;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Security.Claims;
using Xunit;
using System.Net.Http;
using System.Xml.Linq;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;

namespace Tests
{
    public class ApiKeyMiddlewareTests
    {
        [Fact]
        public void ApiKeyValidation()
        {
            var options = GetOptions();
            var server = CreateServer(options);

            var newApiKeyHeader = "Apikey 1";
            var response = server.SendAsyncWithAuth("http://example.com/oauth", newApiKeyHeader).Result;
            Assert.Equal(HttpStatusCode.OK, response.Response.StatusCode);
        }

        [Fact]
        public void SignInThrows()
        {
            var server = CreateServer();
            var transaction = server.SendAsync("https://example.com/signIn").Result;
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
        }

        [Fact]
        public void SignOutThrows()
        {
            var server = CreateServer();
            var transaction = server.SendAsync("https://example.com/signOut").Result;
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
        }

        [Fact]
        public void ThrowAtAuthenticationFailedEvent()
        {

            var server = CreateServer(options =>
            {
                options.Events = new ApiKeyEvents
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
                };
                options.SecurityValidators.Clear();
                options.SecurityValidators.Insert(0, new InvalidApiKeyValidator());
            }, async (context, next) =>
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

            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public void NoHeaderReceived()
        {
            var server = CreateServer();
            var response = server.SendAsyncWithAuth("http://example.com/oauth").Result;
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
        }

        [Fact]
        public void HeaderWithoutApiKeyReceived()
        {
            var server = CreateServer();
            var response = server.SendAsyncWithAuth("http://example.com/oauth", "Token").Result;
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
        }

        [Fact]
        public void UnrecognizedApiKeyReceived()
        {
            var server = CreateServer();

            var response = server.SendAsyncWithAuth("http://example.com/oauth", "Apikey someblob").Result;
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal("", response.ResponseText);
        }

        [Fact]
        public void InvalidApiKeyReceived()
        {
            var server = CreateServer(options =>
            {
                options.SecurityValidators.Clear();
                options.SecurityValidators.Add(new InvalidApiKeyValidator());
            });

            var response = server.SendAsyncWithAuth("http://example.com/oauth", "Apikey someblob").Result;
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal("Apikey error=\"invalid_api_key\"", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.Equal("", response.ResponseText);
        }


        [Theory]
        [InlineData(typeof(ArgumentException))]
        public void ExceptionNotReportedInHeaderForOtherFailures(Type errorType)
        {
            var server = CreateServer(options =>
            {
                options.SecurityValidators.Clear();
                options.SecurityValidators.Add(new InvalidApiKeyValidator(errorType));
            });

            var response = server.SendAsyncWithAuth("http://example.com/oauth", "Apikey someblob").Result;
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal("Apikey error=\"invalid_api_key\"", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.Equal("", response.ResponseText);
        }


        [Fact]
        public void ExceptionNotReportedInHeaderWhenIncludeErrorDetailsIsFalse()
        {
            var server = CreateServer(opts =>
            {
                opts.IncludeErrorDetails = false;
            });

            var response = server.SendAsyncWithAuth("http://example.com/oauth", "Apikey someblob").Result;
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal("Apikey", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.Equal("", response.ResponseText);
        }

        [Fact]
        public void ExceptionNotReportedInHeaderWhenTokenWasMissing()
        {
            var server = CreateServer();

            var response = server.SendAsyncWithAuth("http://example.com/oauth").Result;
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal("Apikey", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.Equal("", response.ResponseText);
        }

        [Fact]
        public void CustomTokenValidated()
        {
            var server = CreateServer(options =>
            {
                options.Events = new ApiKeyEvents()
                {
                    OnApiKeyValidated = context =>
                    {
                        // Retrieve the NameIdentifier claim from the identity
                        // returned by the custom security token validator.
                        var identity = (ClaimsIdentity)context.Principal.Identity;
                        var identifier = identity.FindFirst(ClaimTypes.NameIdentifier);

                        Assert.Equal("Bob le Tout Puissant", identifier.Value);

                        // Remove the existing NameIdentifier claim and replace it
                        // with a new one containing a different value.
                        identity.RemoveClaim(identifier);
                        // Make sure to use a different name identifier
                        // than the one defined by BlobTokenValidator.
                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Bob le Magnifique"));

                        return Task.FromResult<object>(null);
                    }
                };
                options.SecurityValidators.Clear();
                options.SecurityValidators.Add(new BlobTokenValidator());
            });

            var response = server.SendAsyncWithAuth("http://example.com/oauth", "apikey someblob").Result;
            Assert.Equal(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.Equal("Bob le Magnifique", response.ResponseText);
        }

        [Fact]
        public void ApikeyDoesNothingTo401IfNotAuthenticated()
        {
            var server = CreateServer();

            var response = server.SendAsyncWithAuth("http://example.com/unauthorized").Result;
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
        }

        [Fact]
        public void EventOnMessageReceivedSkipped_NoMoreEventsExecuted()
        {
            var server = CreateServer(opts =>
            {
                opts.Events = new ApiKeyEvents()
                {
                    OnMessageReceived = context =>
                    {
                        context.NoResult();
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
                };
            });

            var response = server.SendAsyncWithAuth("http://example.com/checkforerrors", "ApiKey Key").Result;
            Assert.Equal(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.Equal(string.Empty, response.ResponseText);
        }

        [Fact]
        public async Task EventOnMessageReceivedReject_NoMoreEventsExecuted()
        {
            var server = CreateServer(opts =>
            {
                opts.Events = new ApiKeyEvents()
                {
                    OnMessageReceived = context =>
                    {
                        context.Fail("Authentication was aborted from user code.");
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
                };
            });
            var exception = await Assert.ThrowsAsync<Exception>(delegate
            {
                return SendAsync(server, "http://example.com/checkforerrors", "ApiKey Key");
            });

            Assert.Equal("Authentication was aborted from user code.", exception.InnerException.Message);
        }

        [Fact]
        public void EventOnTokenValidatedSkipped_NoMoreEventsExecuted()
        {
            var server = CreateServer(options =>
            {
                options.Events = new ApiKeyEvents()
                {
                    OnApiKeyValidated = context =>
                    {
                        context.NoResult();
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
                };
                options.SecurityValidators.Clear();
                options.SecurityValidators.Add(new BlobTokenValidator());
            });

            var response = server.SendAsyncWithAuth("http://example.com/checkforerrors", "ApiKey Key").Result;
            Assert.Equal(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.Equal(string.Empty, response.ResponseText);
        }

        [Fact]
        public void EventOnTokenValidatedHandled_NoMoreEventsExecuted()
        {
            var server = CreateServer(options =>
            {
                options.Events = new ApiKeyEvents()
                {
                    OnApiKeyValidated = context =>
                    {
                        context.NoResult();
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
                };
                options.SecurityValidators.Clear();
                options.SecurityValidators.Add(new BlobTokenValidator());
            });

            var response = server.SendAsyncWithAuth("http://example.com/checkforerrors", "ApiKey Key").Result;
            Assert.Equal(HttpStatusCode.Accepted, response.Response.StatusCode);
            Assert.Equal(string.Empty, response.ResponseText);
        }

        [Fact]
        public void EventOnAuthenticationFailedSkipped_NoMoreEventsExecuted()
        {

            var server = CreateServer(options =>
            {
                options.Events = new ApiKeyEvents()
                {
                    OnApiKeyValidated = context =>
                    {
                        throw new Exception("Test Exception");
                    },
                    OnAuthenticationFailed = context =>
                    {
                        context.NoResult();
                        return Task.FromResult(0);
                    },
                    OnChallenge = context =>
                    {
                        throw new NotImplementedException();
                    },
                };
                options.SecurityValidators.Clear();
                options.SecurityValidators.Add(new BlobTokenValidator());

            });

            var response = server.SendAsyncWithAuth("http://example.com/checkforerrors", "ApiKey Key").Result;
            Assert.Equal(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.Equal(string.Empty, response.ResponseText);
        }

        [Fact]
        public void EventOnAuthenticationFailedSkip_NoMoreEventsExecuted()
        {
            var server = CreateServer(options =>
            {
                options.Events = new ApiKeyEvents()
                {
                    OnApiKeyValidated = context =>
                    {
                        throw new Exception("Test Exception");
                    },
                    OnAuthenticationFailed = context =>
                    {
                        context.NoResult();
                        return Task.FromResult(0);
                    },
                    OnChallenge = context =>
                    {
                        throw new NotImplementedException();
                    },
                };
                options.SecurityValidators.Clear();
                options.SecurityValidators.Add(new BlobTokenValidator());

            });

            var response = server.SendAsyncWithAuth("http://example.com/checkforerrors", "ApiKey Key").Result;
            Assert.Equal(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.Equal(string.Empty, response.ResponseText);
        }

        [Fact]
        public void EventOnChallengeSkipped_ResponseNotModified()
        {
            var server = CreateServer(opts =>
            {
                opts.Events = new ApiKeyEvents()
                {
                    OnChallenge = context =>
                    {
                        context.HandleResponse();
                        return Task.FromResult(0);
                    },
                };
            });

            var response = server.SendAsyncWithAuth("http://example.com/unauthorized", "ApiKey Key").Result;
            Assert.Equal(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.Empty(response.Response.Headers.WwwAuthenticate);
            Assert.Equal(string.Empty, response.ResponseText);
        }

        [Fact]
        public void EventOnChallengeHandled_ResponseNotModified()
        {
            var server = CreateServer(opt =>
            {
                opt.Events = new ApiKeyEvents()
                {
                    OnChallenge = context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = StatusCodes.Status202Accepted;
                        return Task.FromResult(0);
                    },
                };
            });

            var response = server.SendAsyncWithAuth("http://example.com/unauthorized", "ApiKey Key").Result;
            Assert.Equal(HttpStatusCode.Accepted, response.Response.StatusCode);
            Assert.Empty(response.Response.Headers.WwwAuthenticate);
            Assert.Equal(string.Empty, response.ResponseText);
        }

        private static TestServer CreateServer(Action<ApiKeyOptions> options = null,
            Func<HttpContext, Func<Task>, Task> handlerBeforeAuth = null,
            AuthenticationProperties properties = null)
        {
            return TestServerBuilder.CreateServer(options, handlerBeforeAuth, properties);
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

        private static Action<ApiKeyOptions> GetOptions()
        {
            return opt =>
            {
                opt.ApiKeys = new Dictionary<string, ApiKeyInfo>() { { "1", new ApiKeyInfo { Claims = new[] { new Claim(ClaimTypes.NameIdentifier, "Chet") } } } };
            };
        }

        // TODO: see if we can share the TestExtensions SendAsync method (only diff is auth header)
        private static async Task<Transaction> SendAsync(TestServer server, string uri, string authorizationHeader = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            if (!string.IsNullOrEmpty(authorizationHeader))
            {
                request.Headers.Add("Authorization", authorizationHeader);
            }

            var transaction = new Transaction
            {
                Request = request,
                Response = await server.CreateClient().SendAsync(request),
            };

            transaction.ResponseText = await transaction.Response.Content.ReadAsStringAsync();

            if (transaction.Response.Content != null &&
                transaction.Response.Content.Headers.ContentType != null &&
                transaction.Response.Content.Headers.ContentType.MediaType == "text/xml")
            {
                transaction.ResponseElement = XElement.Parse(transaction.ResponseText);
            }

            return transaction;
        }
    }
}
