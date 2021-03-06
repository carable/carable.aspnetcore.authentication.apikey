// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    public class MessageReceivedContext : ResultContext<ApiKeyOptions>
    {
        public MessageReceivedContext(
             HttpContext context, 
             AuthenticationScheme scheme,
             ApiKeyOptions options)
            : base(context, scheme, options)
        {
        }

        /// <summary>
        /// Bearer Token. This will give application an opportunity to retrieve token from an alternation location.
        /// </summary>
        public string Token { get; set; }
    }
}