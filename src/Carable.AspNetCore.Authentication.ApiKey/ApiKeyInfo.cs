using System.Collections.Generic;
using System.Security.Claims;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    public class ApiKeyInfo
    {
        public Claim[] Claims { get; set; } = new Claim[0];
    }
}