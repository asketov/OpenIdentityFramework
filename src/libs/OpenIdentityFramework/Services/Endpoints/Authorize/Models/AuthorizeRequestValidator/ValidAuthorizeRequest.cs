using System;
using System.Collections.Generic;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceService;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;

public class ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
{
    public ValidAuthorizeRequest(
        DateTimeOffset initialRequestDate,
        string issuer,
        TClient client,
        string redirectUri,
        ValidResources<TScope, TResource, TResourceSecret> requestedResources,
        string codeChallenge,
        string codeChallengeMethod,
        IReadOnlySet<string> responseType,
        string? state,
        string responseMode,
        IReadOnlyDictionary<string, StringValues> raw)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(issuer));
        }

        ArgumentNullException.ThrowIfNull(client);

        if (string.IsNullOrWhiteSpace(redirectUri))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(redirectUri));
        }

        ArgumentNullException.ThrowIfNull(requestedResources);

        if (string.IsNullOrWhiteSpace(codeChallenge))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(codeChallenge));
        }

        if (string.IsNullOrWhiteSpace(codeChallengeMethod))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(codeChallengeMethod));
        }

        ArgumentNullException.ThrowIfNull(responseType);

        if (string.IsNullOrWhiteSpace(responseMode))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(responseMode));
        }

        InitialRequestDate = initialRequestDate;
        Issuer = issuer;
        Client = client;
        RedirectUri = redirectUri;
        RequestedResources = requestedResources;
        CodeChallenge = codeChallenge;
        CodeChallengeMethod = codeChallengeMethod;
        ResponseType = responseType;
        State = state;
        ResponseMode = responseMode;
        Raw = raw;
        IsOpenIdRequest = false;
    }

    public ValidAuthorizeRequest(
        DateTimeOffset initialRequestDate,
        string issuer,
        TClient client,
        string redirectUri,
        ValidResources<TScope, TResource, TResourceSecret> requestedResources,
        string codeChallenge,
        string codeChallengeMethod,
        IReadOnlySet<string> responseType,
        string? state,
        string responseMode,
        string? nonce,
        string? display,
        IReadOnlySet<string>? prompt,
        long? maxAge,
        string? uiLocales,
        string? loginHint,
        string[]? acrValues,
        IReadOnlyDictionary<string, StringValues> raw)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(issuer));
        }

        ArgumentNullException.ThrowIfNull(client);

        if (string.IsNullOrWhiteSpace(redirectUri))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(redirectUri));
        }

        ArgumentNullException.ThrowIfNull(requestedResources);

        if (string.IsNullOrWhiteSpace(codeChallenge))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(codeChallenge));
        }

        if (string.IsNullOrWhiteSpace(codeChallengeMethod))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(codeChallengeMethod));
        }

        ArgumentNullException.ThrowIfNull(responseType);

        if (string.IsNullOrWhiteSpace(responseMode))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(responseMode));
        }

        InitialRequestDate = initialRequestDate;
        Issuer = issuer;
        Client = client;
        RedirectUri = redirectUri;
        RequestedResources = requestedResources;
        CodeChallenge = codeChallenge;
        CodeChallengeMethod = codeChallengeMethod;
        ResponseType = responseType;
        State = state;
        ResponseMode = responseMode;
        Nonce = nonce;
        Display = display;
        Prompt = prompt;
        MaxAge = maxAge;
        UiLocales = uiLocales;
        LoginHint = loginHint;
        AcrValues = acrValues;
        Raw = raw;
        IsOpenIdRequest = true;
    }

    public DateTimeOffset InitialRequestDate { get; }

    public string Issuer { get; }

    public TClient Client { get; }

    public string RedirectUri { get; }

    public ValidResources<TScope, TResource, TResourceSecret> RequestedResources { get; }

    public string CodeChallenge { get; }

    public string CodeChallengeMethod { get; }

    public IReadOnlySet<string> ResponseType { get; }

    public string? State { get; }

    public string ResponseMode { get; }

    public bool IsOpenIdRequest { get; }

    public string? Nonce { get; }

    public string? Display { get; }

    public IReadOnlySet<string>? Prompt { get; }

    public long? MaxAge { get; }

    public string? UiLocales { get; }

    public string? LoginHint { get; }

    public string[]? AcrValues { get; }

    public IReadOnlyDictionary<string, StringValues> Raw { get; }
}
