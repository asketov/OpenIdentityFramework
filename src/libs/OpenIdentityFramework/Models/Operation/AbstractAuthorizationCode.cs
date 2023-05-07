using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Authentication;

namespace OpenIdentityFramework.Models.Operation;

public abstract class AbstractAuthorizationCode
{
    public abstract string GetClientId();
    public abstract EssentialResourceOwnerClaims GetEssentialResourceOwnerClaims();
    public abstract IReadOnlySet<string> GetGrantedScopes();
    public abstract string? GetAuthorizeRequestRedirectUri();
    public abstract string GetCodeChallenge();
    public abstract string GetCodeChallengeMethod();
    public abstract DateTimeOffset GetIssueDate();
    public abstract DateTimeOffset GetExpirationDate();
}
