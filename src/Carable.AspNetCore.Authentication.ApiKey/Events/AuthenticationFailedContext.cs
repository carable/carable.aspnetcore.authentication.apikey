// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    public class AuthenticationFailedContext : ResultContext<ApiKeyOptions>
    {
        public AuthenticationFailedContext(HttpContext context, AuthenticationScheme scheme, ApiKeyOptions options)
            : base(context, scheme, options)
        {
        }

        public Exception Exception { get; set; }
    }
}