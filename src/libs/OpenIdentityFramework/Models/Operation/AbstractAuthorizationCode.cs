using System;
using System.Collections.Generic;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Models.Operation;

public abstract class AbstractAuthorizationCode
{
    public abstract UserAuthentication GetUserAuthentication();
    public abstract string GetClientId();
    public abstract string? GetOriginalRedirectUri();
    public abstract IReadOnlySet<string> GetGrantedScopes();
    public abstract string GetCodeChallenge();
    public abstract string GetCodeChallengeMethod();
    public abstract string? GetNonce();
    public abstract string? GetState();
    public abstract string GetIssuer();
    public abstract DateTimeOffset GetExpirationDate();
}
