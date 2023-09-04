using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Models.Operation;

public abstract class AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public abstract string GetClientId();
    public abstract TResourceOwnerEssentialClaims GetEssentialResourceOwnerClaims();
    public abstract IReadOnlySet<string> GetGrantedScopes();
    public abstract string GetCodeChallenge();
    public abstract string GetCodeChallengeMethod();
    public abstract DateTimeOffset GetIssueDate();
    public abstract DateTimeOffset GetExpirationDate();
}
