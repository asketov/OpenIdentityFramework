using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.AuthorizationCode;

public class TokenRequestAuthorizationCodeValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    public TokenRequestAuthorizationCodeValidationResult(ValidAuthorizationCodeTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> validTokenRequest)
    {
        ArgumentNullException.ThrowIfNull(validTokenRequest);
        ValidTokenRequest = validTokenRequest;
    }

    public TokenRequestAuthorizationCodeValidationResult(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        ProtocolError = protocolError;
        HasError = true;
    }

    public ValidAuthorizationCodeTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>? ValidTokenRequest { get; }

    public ProtocolError? ProtocolError { get; }

    [MemberNotNullWhen(true, nameof(ProtocolError))]
    [MemberNotNullWhen(false, nameof(ValidTokenRequest))]
    public bool HasError { get; }
}
