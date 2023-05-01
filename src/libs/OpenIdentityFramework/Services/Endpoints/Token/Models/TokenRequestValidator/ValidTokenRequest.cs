using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.TokenRequestValidator;

public class ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    public ValidTokenRequest(
        TClient client,
        ValidResources<TScope, TResource, TResourceSecret> requestedResources,
        string authorizationCodeHandle,
        TAuthorizationCode authorizationCode,
        string issuer)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(requestedResources);
        ArgumentNullException.ThrowIfNull(authorizationCodeHandle);
        ArgumentNullException.ThrowIfNull(authorizationCode);
        ArgumentNullException.ThrowIfNull(issuer);
        GrantType = DefaultGrantTypes.AuthorizationCode;
        Client = client;
        RequestedResources = requestedResources;
        AuthorizationCodeHandle = authorizationCodeHandle;
        AuthorizationCode = authorizationCode;
        Issuer = issuer;
        IsAuthorizationCodeGrant = true;
    }

    public string GrantType { get; }

    public TClient Client { get; }

    public string Issuer { get; }

    public ValidResources<TScope, TResource, TResourceSecret> RequestedResources { get; }
    public TAuthorizationCode? AuthorizationCode { get; }
    public string? AuthorizationCodeHandle { get; }

    [MemberNotNullWhen(true, nameof(AuthorizationCode))]
    [MemberNotNullWhen(true, nameof(AuthorizationCodeHandle))]
    public bool IsAuthorizationCodeGrant { get; }
}
