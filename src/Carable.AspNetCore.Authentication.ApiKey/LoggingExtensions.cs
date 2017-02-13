using Microsoft.Extensions.Logging;
using System;

namespace Carable.AspNetCore.Authentication.ApiKey
{
    internal static class LoggingExtensions
    {
        private static Action<ILogger, string, Exception> _apiKeyValidationFailed;
        private static Action<ILogger, Exception> _apiKeyValidationSucceeded;
        private static Action<ILogger, Exception> _errorProcessingMessage;

        static LoggingExtensions()
        {
            _apiKeyValidationFailed = LoggerMessage.Define<string>(
                eventId: 1,
                logLevel: LogLevel.Information,
                formatString: "Failed to validate the api key {ApiKey}.");
            _apiKeyValidationSucceeded = LoggerMessage.Define(
                eventId: 2,
                logLevel: LogLevel.Information,
                formatString: "Successfully validated the api key.");
            _errorProcessingMessage = LoggerMessage.Define(
                eventId: 3,
                logLevel: LogLevel.Error,
                formatString: "Exception occurred while processing message.");
        }

        public static void ApiKeyValidationFailed(this ILogger logger, string apiKey, Exception ex)
        {
            _apiKeyValidationFailed(logger, apiKey, ex);
        }

        public static void ApiKeyValidationSucceeded(this ILogger logger)
        {
            _apiKeyValidationSucceeded(logger, null);
        }

        public static void ErrorProcessingMessage(this ILogger logger, Exception ex)
        {
            _errorProcessingMessage(logger, ex);
        }
    }
}
