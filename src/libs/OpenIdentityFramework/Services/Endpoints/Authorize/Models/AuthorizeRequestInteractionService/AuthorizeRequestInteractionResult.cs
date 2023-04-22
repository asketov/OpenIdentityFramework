using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestInteractionService;

public class AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public AuthorizeRequestInteractionResult(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        ProtocolError = protocolError;
        HasError = true;
    }

    public AuthorizeRequestInteractionResult(string requiredInteraction)
    {
        ArgumentNullException.ThrowIfNull(requiredInteraction);
        RequiredInteraction = requiredInteraction;
        HasRequiredInteraction = true;
    }

    public AuthorizeRequestInteractionResult(ValidAuthorizeRequestInteraction<TClient, TClientSecret, TScope, TResource, TResourceSecret> validRequest)
    {
        ArgumentNullException.ThrowIfNull(validRequest);
        ValidRequest = validRequest;
        HasValidRequest = true;
    }

    [MemberNotNullWhen(true, nameof(ProtocolError))]
    public bool HasError { get; }

    [MemberNotNullWhen(true, nameof(RequiredInteraction))]
    public bool HasRequiredInteraction { get; }

    [MemberNotNullWhen(true, nameof(ValidRequest))]
    public bool HasValidRequest { get; }

    public ProtocolError? ProtocolError { get; }

    public string? RequiredInteraction { get; }

    public ValidAuthorizeRequestInteraction<TClient, TClientSecret, TScope, TResource, TResourceSecret>? ValidRequest { get; }
}
