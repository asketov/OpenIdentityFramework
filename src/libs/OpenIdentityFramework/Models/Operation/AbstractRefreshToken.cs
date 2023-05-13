using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Models.Operation;

public abstract class AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public abstract string GetClientId();
    public abstract TResourceOwnerEssentialClaims GetEssentialResourceOwnerClaims();
    public abstract IReadOnlySet<string> GetGrantedScopes();
    public abstract string? GetReferenceAccessTokenHandle();
    public abstract string? GetParentRefreshTokenHandle();
    public abstract DateTimeOffset GetIssueDate();
    public abstract DateTimeOffset GetExpirationDate();
    public abstract DateTimeOffset? GetAbsoluteExpirationDate();
}
