using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Models.Operation;

public abstract class AbstractRefreshToken
{
    public abstract string GetClientId();
    public abstract EssentialResourceOwnerClaims GetEssentialResourceOwnerClaims();
    public abstract IReadOnlySet<string> GetGrantedScopes();
    public abstract string? GetReferenceAccessTokenHandle();
    public abstract string? GetParentRefreshTokenHandle();
    public abstract DateTimeOffset GetIssueDate();
    public abstract DateTimeOffset GetExpirationDate();
    public abstract DateTimeOffset? GetAbsoluteExpirationDate();
}
