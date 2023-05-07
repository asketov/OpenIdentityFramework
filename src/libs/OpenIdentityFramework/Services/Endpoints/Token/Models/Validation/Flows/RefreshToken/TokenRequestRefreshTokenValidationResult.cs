using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.RefreshToken;

public class TokenRequestRefreshTokenValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TRefreshToken : AbstractRefreshToken
{
    public TokenRequestRefreshTokenValidationResult(ValidRefreshTokenTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken> validTokenRequest)
    {
        ArgumentNullException.ThrowIfNull(validTokenRequest);
        ValidTokenRequest = validTokenRequest;
    }

    public TokenRequestRefreshTokenValidationResult(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        ProtocolError = protocolError;
        HasError = true;
    }

    public ValidRefreshTokenTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken>? ValidTokenRequest { get; }

    public ProtocolError? ProtocolError { get; }

    [MemberNotNullWhen(true, nameof(ProtocolError))]
    [MemberNotNullWhen(false, nameof(ValidTokenRequest))]
    public bool HasError { get; }
}
