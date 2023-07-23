using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core.Models.AccessTokenService;

public class AccessTokenCreationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public AccessTokenCreationResult(CreatedAccessToken<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> accessToken)
    {
        ArgumentNullException.ThrowIfNull(accessToken);
        AccessToken = accessToken;
    }

    public AccessTokenCreationResult(string errorDescription)
    {
        ArgumentNullException.ThrowIfNull(errorDescription);
        ErrorDescription = errorDescription;
        HasError = true;
    }

    public CreatedAccessToken<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? AccessToken { get; }

    public string? ErrorDescription { get; }

    [MemberNotNullWhen(true, nameof(ErrorDescription))]
    [MemberNotNullWhen(false, nameof(AccessToken))]
    public bool HasError { get; }
}
