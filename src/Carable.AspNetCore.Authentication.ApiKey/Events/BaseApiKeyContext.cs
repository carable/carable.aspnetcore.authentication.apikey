// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    public class BaseApiKeyContext : BaseControlContext
    {
        public BaseApiKeyContext(HttpContext context, ApiKeyOptions options)
            : base(context)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            Options = options;
        }

        public ApiKeyOptions Options { get; }
    }
}