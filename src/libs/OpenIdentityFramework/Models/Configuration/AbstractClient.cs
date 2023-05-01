﻿using System;
using System.Collections.Generic;
using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Models.Configuration;

public abstract class AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public abstract string GetClientId();
    public abstract IReadOnlySet<string> GetPreRegisteredRedirectUris();
    public abstract string GetClientType();
    public abstract IReadOnlySet<string> GetAllowedScopes();
    public abstract IReadOnlySet<string> GetAllowedAuthorizationFlows();
    public abstract IReadOnlySet<string> GetAllowedCodeChallengeMethods();
    public abstract bool IsConsentRequired();
    public abstract bool CanRememberConsent();
    public abstract TimeSpan? GetConsentLifetime();
    public abstract TimeSpan GetAuthorizationCodeLifetime();
    public abstract bool ShouldAlwaysIncludeUserClaimsInIdToken();
    public abstract IReadOnlySet<string> GetAllowedIdTokenSigningAlgorithms();
    public abstract TimeSpan GetIdTokenLifetime();
    public abstract string GetAuthenticationMethod();
    public abstract IReadOnlyCollection<TClientSecret> GetSecrets();
    public abstract string GetAccessTokenFormat();
    public abstract bool ShouldIncludeJwtIdIntoAccessToken();
    public abstract TimeSpan GetAccessTokenLifetime();
    public abstract TimeSpan GetRefreshTokenAbsoluteLifetime();
    public abstract TimeSpan GetRefreshTokenSlidingLifetime();
    public abstract string GetRefreshTokenExpirationType();

    public bool IsConfidential()
    {
        return string.Equals(DefaultClientTypes.Confidential, GetClientType(), StringComparison.Ordinal);
    }
}
