# README #

This is an alternative way to connect to an API. Can be used for testing purposes.

# Get Started

In order to start use the API you follow the instructions below:
## Setup the authentication between the API and client application.

To be able to consume the API you application has to have a unique GUID represting the application id, the rooturl to the API and the APIKey. 
The AppId together with the shared secret APIKey authenticate the Consumer to the API.
## Generate API key

Use ``` GenerateApiKey.exe ``` to generate a new key

You can also generate a new key using F# Interactive: 

```
open System
open System.Security.Cryptography

let cryptoProvider = new RNGCryptoServiceProvider()
let secretKeyByteArray = Array.create 32 0uy //256 bit
cryptoProvider.GetBytes secretKeyByteArray
Convert.ToBase64String secretKeyByteArray;;
```

## SERVER

### Install the asp.net core NuGet package

Go to the defined NuGet feed and install the AspNetCore package (Carable.AspNetCore.Authentication.ApiKey).

### Register in StartUp

```
public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
{
...
    app.UseApiKeyAuthentication(new ApiKeyOptions
    {
        ApiKeys = Options.ApiKeys.GetAsDictionary()
    });

```
