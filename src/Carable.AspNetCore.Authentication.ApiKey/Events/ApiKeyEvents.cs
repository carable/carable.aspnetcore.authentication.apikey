// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Internal;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    /// <summary>
    /// Specifies events which the <see cref="ApiKeyMiddleware"/> invokes to enable developer control over the authentication process.
    /// </summary>
    public class ApiKeyEvents : IApiKeyEvents
    {
        private static readonly Task CompletedTask =
#if NET451
            Task.FromResult(0);
#else
            Task.CompletedTask;
#endif

        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => CompletedTask;

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = context => CompletedTask;

        /// <summary>
        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public Func<ApiKeyValidatedContext, Task> OnApiKeyValidated { get; set; } = context => CompletedTask;

        /// <summary>
        /// Invoked before a challenge is sent back to the caller.
        /// </summary>
        public Func<ApiKeyChallengeContext, Task> OnChallenge { get; set; } = context => CompletedTask;

        public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

        public virtual Task MessageReceived(MessageReceivedContext context) => OnMessageReceived(context);

        public virtual Task ApiKeyValidated(ApiKeyValidatedContext context) => OnApiKeyValidated(context);

        public virtual Task Challenge(ApiKeyChallengeContext context) => OnChallenge(context);
    }
}
