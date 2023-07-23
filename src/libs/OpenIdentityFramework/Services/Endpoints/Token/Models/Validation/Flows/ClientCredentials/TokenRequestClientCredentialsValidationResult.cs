using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.ClientCredentials;

public class TokenRequestClientCredentialsValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
{
    public TokenRequestClientCredentialsValidationResult(ValidClientCredentialsTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> validTokenRequest)
    {
        ArgumentNullException.ThrowIfNull(validTokenRequest);
        ValidTokenRequest = validTokenRequest;
    }

    public TokenRequestClientCredentialsValidationResult(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        ProtocolError = protocolError;
        HasError = true;
    }

    public ValidClientCredentialsTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>? ValidTokenRequest { get; }

    public ProtocolError? ProtocolError { get; }

    [MemberNotNullWhen(true, nameof(ProtocolError))]
    [MemberNotNullWhen(false, nameof(ValidTokenRequest))]
    public bool HasError { get; }
}
