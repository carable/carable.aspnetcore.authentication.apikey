// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    public class ApiKeyValidatedContext : ResultContext<ApiKeyOptions>
    {
        public ApiKeyValidatedContext(
            HttpContext context, 
            AuthenticationScheme scheme,
            ApiKeyOptions options)
            : base(context, scheme, options)
        {
        }

        public ValidatedApiKey ApiKey { get; set; }
    }
}
