using System;
using System.Collections.Generic;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;

public class ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public ValidAuthorizeRequest(
        DateTimeOffset initialRequestDate,
        string issuer,
        TClient client,
        string actualRedirectUri,
        string? originalRedirectUri,
        ValidResources<TScope, TResource, TResourceSecret> requestedResources,
        string codeChallenge,
        string codeChallengeMethod,
        string responseType,
        string authorizationFlow,
        string? state,
        string responseMode,
        IReadOnlyDictionary<string, StringValues> raw)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(issuer));
        }

        ArgumentNullException.ThrowIfNull(client);

        if (string.IsNullOrWhiteSpace(actualRedirectUri))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(actualRedirectUri));
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

        if (string.IsNullOrWhiteSpace(responseType))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(responseType));
        }

        if (string.IsNullOrWhiteSpace(authorizationFlow))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(authorizationFlow));
        }

        if (string.IsNullOrWhiteSpace(responseMode))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(responseMode));
        }

        InitialRequestDate = initialRequestDate;
        Issuer = issuer;
        Client = client;
        ActualRedirectUri = actualRedirectUri;
        OriginalRedirectUri = originalRedirectUri;
        RequestedResources = requestedResources;
        CodeChallenge = codeChallenge;
        CodeChallengeMethod = codeChallengeMethod;
        ResponseType = responseType;
        AuthorizationFlow = authorizationFlow;
        State = state;
        ResponseMode = responseMode;
        Raw = raw;
        IsOpenIdRequest = false;
    }

    public ValidAuthorizeRequest(
        DateTimeOffset initialRequestDate,
        string issuer,
        TClient client,
        string actualRedirectUri,
        string? originalRedirectUri,
        ValidResources<TScope, TResource, TResourceSecret> requestedResources,
        string codeChallenge,
        string codeChallengeMethod,
        string responseType,
        string authorizationFlow,
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

        if (string.IsNullOrWhiteSpace(actualRedirectUri))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(actualRedirectUri));
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

        if (string.IsNullOrWhiteSpace(responseType))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(responseType));
        }

        if (string.IsNullOrWhiteSpace(authorizationFlow))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(authorizationFlow));
        }

        if (string.IsNullOrWhiteSpace(responseMode))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(responseMode));
        }

        InitialRequestDate = initialRequestDate;
        Issuer = issuer;
        Client = client;
        ActualRedirectUri = actualRedirectUri;
        OriginalRedirectUri = originalRedirectUri;
        RequestedResources = requestedResources;
        CodeChallenge = codeChallenge;
        CodeChallengeMethod = codeChallengeMethod;
        ResponseType = responseType;
        AuthorizationFlow = authorizationFlow;
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

    public string ActualRedirectUri { get; }

    public string? OriginalRedirectUri { get; }

    public ValidResources<TScope, TResource, TResourceSecret> RequestedResources { get; }

    public string CodeChallenge { get; }

    public string CodeChallengeMethod { get; }

    public string ResponseType { get; }

    public string? State { get; }

    public string ResponseMode { get; }

    public string AuthorizationFlow { get; }

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
