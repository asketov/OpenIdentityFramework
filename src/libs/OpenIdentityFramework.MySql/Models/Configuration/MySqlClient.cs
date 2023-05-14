using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.MySql.Models.Configuration;

public class MySqlClient : AbstractClient<MySqlClientSecret>
{
    public MySqlClient(
        string clientId,
        IReadOnlySet<string> preRegisteredRedirectUris,
        string clientType,
        IReadOnlySet<string> scopes,
        IReadOnlySet<string> authorizationFlows,
        IReadOnlySet<string> codeChallengeMethods,
        bool consentRequired,
        bool rememberConsent,
        TimeSpan? consentLifetime,
        TimeSpan authorizationCodeLifetime,
        bool includeUserClaimsInIdTokenAuthorizeResponse,
        bool includeUserClaimsInIdTokenTokenResponse,
        IReadOnlySet<string> idTokenSigningAlgorithms,
        IReadOnlySet<string> accessTokenSigningAlgorithms,
        TimeSpan idTokenLifetime,
        string clientAuthenticationMethod,
        IReadOnlyCollection<MySqlClientSecret> secrets,
        string accessTokenFormat,
        bool includeJwtIdIntoAccessToken,
        TimeSpan accessTokenLifetime,
        TimeSpan refreshTokenAbsoluteLifetime,
        TimeSpan refreshTokenSlidingLifetime,
        string refreshTokenExpirationType)
    {
        if (string.IsNullOrEmpty(clientId))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(clientId));
        }

        if (string.IsNullOrEmpty(clientType))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(clientType));
        }

        if (string.IsNullOrEmpty(clientAuthenticationMethod))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(clientAuthenticationMethod));
        }

        if (string.IsNullOrEmpty(accessTokenFormat))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(accessTokenFormat));
        }

        if (string.IsNullOrEmpty(refreshTokenExpirationType))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(refreshTokenExpirationType));
        }

        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(accessTokenSigningAlgorithms);
        ArgumentNullException.ThrowIfNull(idTokenSigningAlgorithms);
        ArgumentNullException.ThrowIfNull(codeChallengeMethods);
        ArgumentNullException.ThrowIfNull(authorizationFlows);
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(preRegisteredRedirectUris);

        ClientId = clientId;
        PreRegisteredRedirectUris = preRegisteredRedirectUris;
        ClientType = clientType;
        Scopes = scopes;
        AuthorizationFlows = authorizationFlows;
        CodeChallengeMethods = codeChallengeMethods;
        ConsentRequired = consentRequired;
        RememberConsent = rememberConsent;
        ConsentLifetime = consentLifetime;
        AuthorizationCodeLifetime = authorizationCodeLifetime;
        IncludeUserClaimsInIdTokenAuthorizeResponse = includeUserClaimsInIdTokenAuthorizeResponse;
        IncludeUserClaimsInIdTokenTokenResponse = includeUserClaimsInIdTokenTokenResponse;
        IdTokenSigningAlgorithms = idTokenSigningAlgorithms;
        AccessTokenSigningAlgorithms = accessTokenSigningAlgorithms;
        IdTokenLifetime = idTokenLifetime;
        ClientAuthenticationMethod = clientAuthenticationMethod;
        Secrets = secrets;
        AccessTokenFormat = accessTokenFormat;
        IncludeJwtIdIntoAccessToken = includeJwtIdIntoAccessToken;
        AccessTokenLifetime = accessTokenLifetime;
        RefreshTokenAbsoluteLifetime = refreshTokenAbsoluteLifetime;
        RefreshTokenSlidingLifetime = refreshTokenSlidingLifetime;
        RefreshTokenExpirationType = refreshTokenExpirationType;
    }

    public string ClientId { get; }
    public IReadOnlySet<string> PreRegisteredRedirectUris { get; }
    public string ClientType { get; }
    public IReadOnlySet<string> Scopes { get; }
    public IReadOnlySet<string> AuthorizationFlows { get; }
    public IReadOnlySet<string> CodeChallengeMethods { get; }
    public bool ConsentRequired { get; }
    public bool RememberConsent { get; }
    public TimeSpan? ConsentLifetime { get; }
    public TimeSpan AuthorizationCodeLifetime { get; }
    public bool IncludeUserClaimsInIdTokenAuthorizeResponse { get; }
    public bool IncludeUserClaimsInIdTokenTokenResponse { get; }
    public IReadOnlySet<string> IdTokenSigningAlgorithms { get; }
    public IReadOnlySet<string> AccessTokenSigningAlgorithms { get; }
    public TimeSpan IdTokenLifetime { get; }
    public string ClientAuthenticationMethod { get; }
    public IReadOnlyCollection<MySqlClientSecret> Secrets { get; }
    public string AccessTokenFormat { get; }
    public bool IncludeJwtIdIntoAccessToken { get; }
    public TimeSpan AccessTokenLifetime { get; }
    public TimeSpan RefreshTokenAbsoluteLifetime { get; }
    public TimeSpan RefreshTokenSlidingLifetime { get; }
    public string RefreshTokenExpirationType { get; }


    public override string GetClientId()
    {
        return ClientId;
    }

    public override IReadOnlySet<string> GetPreRegisteredRedirectUris()
    {
        return PreRegisteredRedirectUris;
    }

    public override string GetClientType()
    {
        return ClientType;
    }

    public override IReadOnlySet<string> GetAllowedScopes()
    {
        return Scopes;
    }

    public override IReadOnlySet<string> GetAllowedAuthorizationFlows()
    {
        return AuthorizationFlows;
    }

    public override IReadOnlySet<string> GetAllowedCodeChallengeMethods()
    {
        return CodeChallengeMethods;
    }

    public override bool IsConsentRequired()
    {
        return ConsentRequired;
    }

    public override bool CanRememberConsent()
    {
        return RememberConsent;
    }

    public override TimeSpan? GetConsentLifetime()
    {
        return ConsentLifetime;
    }

    public override TimeSpan GetAuthorizationCodeLifetime()
    {
        return AuthorizationCodeLifetime;
    }

    public override bool ShouldIncludeUserClaimsInIdTokenAuthorizeResponse()
    {
        return IncludeUserClaimsInIdTokenAuthorizeResponse;
    }

    public override bool ShouldIncludeUserClaimsInIdTokenTokenResponse()
    {
        return IncludeUserClaimsInIdTokenTokenResponse;
    }

    public override IReadOnlySet<string> GetAllowedIdTokenSigningAlgorithms()
    {
        return IdTokenSigningAlgorithms;
    }

    public override IReadOnlySet<string> GetAllowedAccessTokenSigningAlgorithms()
    {
        return AccessTokenSigningAlgorithms;
    }

    public override TimeSpan GetIdTokenLifetime()
    {
        return IdTokenLifetime;
    }

    public override string GetClientAuthenticationMethod()
    {
        return ClientAuthenticationMethod;
    }

    public override IReadOnlyCollection<MySqlClientSecret> GetSecrets()
    {
        return Secrets;
    }

    public override string GetAccessTokenFormat()
    {
        return AccessTokenFormat;
    }

    public override bool ShouldIncludeJwtIdIntoAccessToken()
    {
        return IncludeJwtIdIntoAccessToken;
    }

    public override TimeSpan GetAccessTokenLifetime()
    {
        return AccessTokenLifetime;
    }

    public override TimeSpan GetRefreshTokenAbsoluteLifetime()
    {
        return RefreshTokenAbsoluteLifetime;
    }

    public override TimeSpan GetRefreshTokenSlidingLifetime()
    {
        return RefreshTokenSlidingLifetime;
    }

    public override string GetRefreshTokenExpirationType()
    {
        return RefreshTokenExpirationType;
    }
}
