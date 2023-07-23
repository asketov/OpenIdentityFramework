using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;

public class TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public TokenRequestValidationResult(ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> validRequest)
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

    public ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? ValidRequest { get; }

    public ProtocolError? ProtocolError { get; }

    [MemberNotNullWhen(true, nameof(ProtocolError))]
    [MemberNotNullWhen(false, nameof(ValidRequest))]
    public bool HasError { get; }
}
