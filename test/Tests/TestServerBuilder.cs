using System;
using Carable.AspNetCore.Authentication.ApiKey;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace Tests
{
    public class TestServerBuilder
    {
        public static TestServer CreateServer(Action<ApiKeyOptions> options,
            Func<HttpContext, Func<Task>, Task> handlerBeforeAuth,
            AuthenticationProperties properties)
        {
            var builder = new WebHostBuilder()
              .Configure(app =>
              {
                  if (handlerBeforeAuth != null)
                  {
                      app.Use(handlerBeforeAuth);
                  }

                  app.UseAuthentication();
                  app.Use(async (context, next) =>
                  {
                      var req = context.Request;
                      var res = context.Response;

                      if (context.Request.Path == new PathString("/checkforerrors"))
                      {
                          var result = await context.AuthenticateAsync(ApiKeyDefaults.AuthenticationScheme); // this used to be "Automatic"
                          if (result.Failure != null)
                          {
                              throw new Exception("Failed to authenticate", result.Failure);
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
                              // REVIEW: no more automatic challenge
                              await context.ChallengeAsync(ApiKeyDefaults.AuthenticationScheme);
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
                          var result = await context.AuthenticateAsync(ApiKeyDefaults.AuthenticationScheme);
                          await context.ChallengeAsync(ApiKeyDefaults.AuthenticationScheme);
                      }
                      else if (context.Request.Path == new PathString("/signIn"))
                      {
                          await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(ApiKeyDefaults.AuthenticationScheme, new ClaimsPrincipal()));
                      }
                      else if (context.Request.Path == new PathString("/signOut"))
                      {
                          await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync(ApiKeyDefaults.AuthenticationScheme));
                      }
                      else
                      {
                          await next();
                      }
                  });
              })
              .ConfigureServices(services =>
              {
                  services.AddAuthentication(ApiKeyDefaults.AuthenticationScheme)
                      .AddApiKey(options);
              });

            return new TestServer(builder);
        }
    }
}
