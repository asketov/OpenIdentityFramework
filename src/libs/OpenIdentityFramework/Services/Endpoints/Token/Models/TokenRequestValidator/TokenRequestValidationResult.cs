using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.TokenRequestValidator;

public class TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
    where TRefreshToken : AbstractRefreshToken
{
    public TokenRequestValidationResult(ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken> validRequest)
    {
        ArgumentNullException.ThrowIfNull(validRequest);
        ValidRequest = validRequest;
    }

    public TokenRequestValidationResult(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        ProtocolError = protocolError;
        HasError = true;
    }

    public ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken>? ValidRequest { get; }

    public ProtocolError? ProtocolError { get; }

    [MemberNotNullWhen(true, nameof(ProtocolError))]
    [MemberNotNullWhen(false, nameof(ValidRequest))]
    public bool HasError { get; }
}
