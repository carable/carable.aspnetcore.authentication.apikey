using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Net.Http.Headers;

namespace Tests
{
    public static class TestExtensions
    {
        public const string CookieAuthenticationScheme = "External";

        public static async Task<Transaction> SendAsync(this TestServer server, string uri, string cookieHeader = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            var transaction = new Transaction
            {
                Request = request,
                Response = await server.CreateClient().SendAsync(request),
            };
            transaction.ResponseText = await transaction.Response.Content.ReadAsStringAsync();

            return transaction;
        }
        // TODO: see if we can share the TestExtensions SendAsync method (only diff is auth header)
        public static async Task<Transaction> SendAsyncWithAuth(this TestServer server, string uri, string authorizationHeader = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            if (!string.IsNullOrEmpty(authorizationHeader))
            {
                var h = authorizationHeader.Split(' ');
                if (h.Length != 2) // just set the auth value directly
                {
                    request.Headers.Add("Authorization", authorizationHeader);
                }
                else
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue(h[0], h[1]);
                }
            }
            using (var client = server.CreateClient())
            {
                var transaction = new Transaction
                {
                    Request = request,
                    Response = await client.SendAsync(request),
                };
                transaction.ResponseText = await transaction.Response.Content.ReadAsStringAsync();
                return transaction;
            }
        }
        public static void Describe(this HttpResponse res, ClaimsPrincipal principal)
        {
            res.StatusCode = 200;
            res.ContentType = "text/xml";
            var xml = new XElement("xml");
            if (principal != null)
            {
                foreach (var identity in principal.Identities)
                {
                    xml.Add(identity.Claims.Select(claim =>
                        new XElement("claim", new XAttribute("type", claim.Type),
                        new XAttribute("value", claim.Value),
                        new XAttribute("issuer", claim.Issuer))));
                }
            }
            var xmlBytes = Encoding.UTF8.GetBytes(xml.ToString());
            res.Body.Write(xmlBytes, 0, xmlBytes.Length);
        }

        public static void Describe(this HttpResponse res, IEnumerable<AuthenticationToken> tokens)
        {
            res.StatusCode = 200;
            res.ContentType = "text/xml";
            var xml = new XElement("xml");
            if (tokens != null)
            {
                foreach (var token in tokens)
                {
                    xml.Add(new XElement("token", new XAttribute("name", token.Name),
                        new XAttribute("value", token.Value)));
                }
            }
            var xmlBytes = Encoding.UTF8.GetBytes(xml.ToString());
            res.Body.Write(xmlBytes, 0, xmlBytes.Length);
        }

    }
}
