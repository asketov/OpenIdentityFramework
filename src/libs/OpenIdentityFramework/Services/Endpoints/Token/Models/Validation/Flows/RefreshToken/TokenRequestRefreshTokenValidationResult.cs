using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.RefreshToken;

public class TokenRequestRefreshTokenValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public TokenRequestRefreshTokenValidationResult(ValidRefreshTokenTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> validTokenRequest)
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

    public ValidRefreshTokenTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? ValidTokenRequest { get; }

    public ProtocolError? ProtocolError { get; }

    [MemberNotNullWhen(true, nameof(ProtocolError))]
    [MemberNotNullWhen(false, nameof(ValidTokenRequest))]
    public bool HasError { get; }
}
