// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Http;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    public class ApiKeyValidatedContext : BaseApiKeyContext
    {
        public ApiKeyValidatedContext(HttpContext context, ApiKeyOptions options)
            : base(context, options)
        {
        }

        public ValidatedApiKey ApiKey { get; set; }
    }
}
