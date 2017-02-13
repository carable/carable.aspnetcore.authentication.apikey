using System;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    public class ApiKeyNotFoundException : Exception
    {
        public ApiKeyNotFoundException()
        {
        }

        public ApiKeyNotFoundException(string message) : base(message)
        {
        }

        public ApiKeyNotFoundException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public string ApiKey { get; set; }
    }
}