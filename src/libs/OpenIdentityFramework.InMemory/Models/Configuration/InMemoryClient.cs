using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Implementations;

namespace OpenIdentityFramework.InMemory.Models.Configuration;

public class InMemoryClient : AbstractClient<InMemoryClientSecret>
{
    private readonly long _accessTokenLifetime;
    private readonly string? _accessTokenSignedResponseAlg;
    private readonly string _accessTokenStrategy;
    private readonly IReadOnlySet<string> _allowedCodeChallengeMethods;
    private readonly string? _applicationType;
    private readonly long _authorizationCodeLifetime;
    private readonly bool _canRememberConsent;
    private readonly bool _canSkipConsentScreen;

    private readonly string _clientId;
    private readonly long _clientIdIssuedAt;
    private readonly IReadOnlyDictionary<string, string> _clientName;
    private readonly IReadOnlyDictionary<string, Uri> _clientUri;
    private readonly long? _consentLifetime;
    private readonly IReadOnlySet<string> _contacts;
    private readonly IReadOnlySet<string> _defaultAcrValues;
    private readonly long? _defaultMaxAge;
    private readonly IReadOnlySet<string> _grantTypes;
    private readonly string? _idTokenEncryptedResponseAlg;
    private readonly string? _idTokenEncryptedResponseEnc;
    private readonly long _idTokenLifetime;
    private readonly string? _idTokenSignedResponseAlg;
    private readonly Uri? _initiateLoginUri;
    private readonly JsonWebKeySet? _jwks;
    private readonly Uri? _jwksUri;
    private readonly IReadOnlyDictionary<string, Uri> _logoUri;
    private readonly IReadOnlyDictionary<string, Uri> _policyUri;
    private readonly IReadOnlySet<Uri> _redirectUris;
    private readonly long _refreshTokenAbsoluteLifetime;
    private readonly string _refreshTokenExpirationStrategy;
    private readonly long _refreshTokenSlidingLifetime;
    private readonly string? _requestObjectEncryptionAlg;
    private readonly string? _requestObjectEncryptionEnc;
    private readonly string? _requestObjectSigningAlg;
    private readonly IReadOnlySet<Uri> _requestUris;
    private readonly bool? _requireAuthTime;
    private readonly IReadOnlySet<string> _responseTypes;
    private readonly IReadOnlySet<string> _scopes;
    private readonly IReadOnlySet<InMemoryClientSecret> _secrets;
    private readonly Uri? _sectorIdentifierUri;
    private readonly bool _shouldIncludeJwtIdIntoAccessToken;
    private readonly bool _shouldIncludeUserClaimsInIdTokenAuthorizeResponse;
    private readonly bool _shouldIncludeUserClaimsInIdTokenTokenResponse;
    private readonly string? _softwareId;
    private readonly string? _softwareVersion;
    private readonly string? _subjectType;
    private readonly string? _tokenEndpointAuthMethod;
    private readonly string? _tokenEndpointAuthSigningAlg;
    private readonly IReadOnlyDictionary<string, Uri> _tosUri;
    private readonly string? _userinfoEncryptedResponseAlg;
    private readonly string? _userinfoEncryptedResponseEnc;
    private readonly string? _userinfoSignedResponseAlg;

    public InMemoryClient(
        string clientId,
        long clientIdIssuedAt,
        IReadOnlySet<InMemoryClientSecret> secrets,
        IReadOnlySet<Uri> redirectUris,
        string? tokenEndpointAuthMethod,
        IReadOnlySet<string> grantTypes,
        IReadOnlySet<string> responseTypes,
        IReadOnlyDictionary<string, string> clientName,
        IReadOnlyDictionary<string, Uri> clientUri,
        IReadOnlyDictionary<string, Uri> logoUri,
        IReadOnlySet<string> scopes,
        IReadOnlySet<string> contacts,
        IReadOnlyDictionary<string, Uri> tosUri,
        IReadOnlyDictionary<string, Uri> policyUri,
        Uri? jwksUri,
        JsonWebKeySet? jwks,
        string? softwareId,
        string? softwareVersion,
        string? applicationType,
        Uri? sectorIdentifierUri,
        string? subjectType,
        string? idTokenSignedResponseAlg,
        string? idTokenEncryptedResponseAlg,
        string? idTokenEncryptedResponseEnc,
        string? userinfoSignedResponseAlg,
        string? userinfoEncryptedResponseAlg,
        string? userinfoEncryptedResponseEnc,
        string? requestObjectSigningAlg,
        string? requestObjectEncryptionAlg,
        string? requestObjectEncryptionEnc,
        string? tokenEndpointAuthSigningAlg,
        long? defaultMaxAge,
        bool? requireAuthTime,
        IReadOnlySet<string> defaultAcrValues,
        Uri? initiateLoginUri,
        IReadOnlySet<Uri> requestUris,
        IReadOnlySet<string> allowedCodeChallengeMethods,
        string? accessTokenSignedResponseAlg,
        bool canSkipConsentScreen,
        bool canRememberConsent,
        long? consentLifetime,
        long authorizationCodeLifetime,
        bool shouldIncludeUserClaimsInIdTokenAuthorizeResponse,
        bool shouldIncludeUserClaimsInIdTokenTokenResponse,
        long idTokenLifetime,
        string accessTokenStrategy,
        bool shouldIncludeJwtIdIntoAccessToken,
        long accessTokenLifetime,
        long refreshTokenAbsoluteLifetime,
        long refreshTokenSlidingLifetime,
        string refreshTokenExpirationStrategy)
    {
        _clientId = clientId;
        _clientIdIssuedAt = clientIdIssuedAt;
        _secrets = secrets;
        _redirectUris = redirectUris;
        _tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        _grantTypes = grantTypes;
        _responseTypes = responseTypes;
        _clientName = clientName;
        _clientUri = clientUri;
        _logoUri = logoUri;
        _scopes = scopes;
        _contacts = contacts;
        _tosUri = tosUri;
        _policyUri = policyUri;
        _jwksUri = jwksUri;
        _jwks = jwks;
        _softwareId = softwareId;
        _softwareVersion = softwareVersion;
        _applicationType = applicationType;
        _sectorIdentifierUri = sectorIdentifierUri;
        _subjectType = subjectType;
        _idTokenSignedResponseAlg = idTokenSignedResponseAlg;
        _idTokenEncryptedResponseAlg = idTokenEncryptedResponseAlg;
        _idTokenEncryptedResponseEnc = idTokenEncryptedResponseEnc;
        _userinfoSignedResponseAlg = userinfoSignedResponseAlg;
        _userinfoEncryptedResponseAlg = userinfoEncryptedResponseAlg;
        _userinfoEncryptedResponseEnc = userinfoEncryptedResponseEnc;
        _requestObjectSigningAlg = requestObjectSigningAlg;
        _requestObjectEncryptionAlg = requestObjectEncryptionAlg;
        _requestObjectEncryptionEnc = requestObjectEncryptionEnc;
        _tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg;
        _defaultMaxAge = defaultMaxAge;
        _requireAuthTime = requireAuthTime;
        _defaultAcrValues = defaultAcrValues;
        _initiateLoginUri = initiateLoginUri;
        _requestUris = requestUris;
        _allowedCodeChallengeMethods = allowedCodeChallengeMethods;
        _accessTokenSignedResponseAlg = accessTokenSignedResponseAlg;
        _canSkipConsentScreen = canSkipConsentScreen;
        _canRememberConsent = canRememberConsent;
        _consentLifetime = consentLifetime;
        _authorizationCodeLifetime = authorizationCodeLifetime;
        _shouldIncludeUserClaimsInIdTokenAuthorizeResponse = shouldIncludeUserClaimsInIdTokenAuthorizeResponse;
        _shouldIncludeUserClaimsInIdTokenTokenResponse = shouldIncludeUserClaimsInIdTokenTokenResponse;
        _idTokenLifetime = idTokenLifetime;
        _accessTokenStrategy = accessTokenStrategy;
        _shouldIncludeJwtIdIntoAccessToken = shouldIncludeJwtIdIntoAccessToken;
        _accessTokenLifetime = accessTokenLifetime;
        _refreshTokenAbsoluteLifetime = refreshTokenAbsoluteLifetime;
        _refreshTokenSlidingLifetime = refreshTokenSlidingLifetime;
        _refreshTokenExpirationStrategy = refreshTokenExpirationStrategy;
    }

    public static InMemoryClient ClientCredentials(
        string clientId,
        string clientSecret,
        DateTimeOffset clientIdIssuedAt,
        IEnumerable<string> scopes,
        string accessTokenStrategy = DefaultAccessTokenStrategy.Jwt,
        long accessTokenLifetime = 3600)
    {
        var issuedAtUnixTime = clientIdIssuedAt.ToUnixTimeSeconds();
        var secrets = new HashSet<InMemoryClientSecret>
        {
            new(DefaultClientSecretHasher.Instance.ComputeHash(clientSecret), issuedAtUnixTime, 0)
        };
        return new(
            clientId,
            issuedAtUnixTime,
            secrets,
            new HashSet<Uri>(0),
            DefaultClientAuthenticationMethods.ClientSecretPost,
            new HashSet<string>(StringComparer.Ordinal)
            {
                DefaultGrantTypes.ClientCredentials
            },
            new HashSet<string>(StringComparer.Ordinal),
            new Dictionary<string, string>(),
            new Dictionary<string, Uri>(),
            new Dictionary<string, Uri>(),
            scopes.ToHashSet(StringComparer.Ordinal),
            new HashSet<string>(StringComparer.Ordinal),
            new Dictionary<string, Uri>(),
            new Dictionary<string, Uri>(),
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            new HashSet<string>(StringComparer.Ordinal),
            null,
            new HashSet<Uri>(),
            new HashSet<string>(),
            null,
            false,
            false,
            null,
            0,
            false,
            false,
            0,
            accessTokenStrategy,
            false,
            accessTokenLifetime,
            86400,
            0,
            DefaultRefreshTokenExpirationStrategy.Hybrid);
    }

    public override string GetClientId()
    {
        return _clientId;
    }

    public override long GetClientIdIssuedAt()
    {
        return _clientIdIssuedAt;
    }

    public override IReadOnlySet<InMemoryClientSecret> GetSecrets()
    {
        return _secrets;
    }

    public override IReadOnlySet<Uri> GetRedirectUris()
    {
        return _redirectUris;
    }

    public override string? GetTokenEndpointAuthMethod()
    {
        return _tokenEndpointAuthMethod;
    }

    public override IReadOnlySet<string> GetGrantTypes()
    {
        return _grantTypes;
    }

    public override IReadOnlySet<string> GetResponseTypes()
    {
        return _responseTypes;
    }

    public override string? GetClientName(CultureInfo cultureInfo)
    {
        ArgumentNullException.ThrowIfNull(cultureInfo);
        if (_clientName.TryGetValue(cultureInfo.Name, out var localizedClientName))
        {
            return localizedClientName;
        }

        if (_clientName.TryGetValue(CultureInfo.InvariantCulture.Name, out var invariantClientName))
        {
            return invariantClientName;
        }

        return _clientId;
    }

    public override Uri? GetClientUri(CultureInfo cultureInfo)
    {
        ArgumentNullException.ThrowIfNull(cultureInfo);
        if (_clientUri.TryGetValue(cultureInfo.Name, out var localizedClientUri))
        {
            return localizedClientUri;
        }

        if (_clientUri.TryGetValue(CultureInfo.InvariantCulture.Name, out var invariantClientUri))
        {
            return invariantClientUri;
        }

        return null;
    }

    public override Uri? GetLogoUri(CultureInfo cultureInfo)
    {
        ArgumentNullException.ThrowIfNull(cultureInfo);
        if (_logoUri.TryGetValue(cultureInfo.Name, out var localizedLogoUri))
        {
            return localizedLogoUri;
        }

        if (_logoUri.TryGetValue(CultureInfo.InvariantCulture.Name, out var invariantLogoUri))
        {
            return invariantLogoUri;
        }

        return null;
    }

    public override IReadOnlySet<string> GetScopes()
    {
        return _scopes;
    }

    public override IReadOnlySet<string> GetContacts()
    {
        return _contacts;
    }

    public override Uri? GetTosUri(CultureInfo cultureInfo)
    {
        ArgumentNullException.ThrowIfNull(cultureInfo);
        if (_tosUri.TryGetValue(cultureInfo.Name, out var localizedTosUri))
        {
            return localizedTosUri;
        }

        if (_tosUri.TryGetValue(CultureInfo.InvariantCulture.Name, out var invariantTosUri))
        {
            return invariantTosUri;
        }

        return null;
    }

    public override Uri? GetPolicyUri(CultureInfo cultureInfo)
    {
        ArgumentNullException.ThrowIfNull(cultureInfo);
        if (_policyUri.TryGetValue(cultureInfo.Name, out var localizedPolicyUri))
        {
            return localizedPolicyUri;
        }

        if (_policyUri.TryGetValue(CultureInfo.InvariantCulture.Name, out var invariantPolicyUri))
        {
            return invariantPolicyUri;
        }

        return null;
    }

    public override Uri? GetJwksUri()
    {
        return _jwksUri;
    }

    public override JsonWebKeySet? GetJwks()
    {
        return _jwks;
    }

    public override string? GetSoftwareId()
    {
        return _softwareId;
    }

    public override string? GetSoftwareVersion()
    {
        return _softwareVersion;
    }

    public override string? GetApplicationType()
    {
        return _applicationType;
    }

    public override Uri? GetSectorIdentifierUri()
    {
        return _sectorIdentifierUri;
    }

    public override string? GetSubjectType()
    {
        return _subjectType;
    }

    public override string? GetIdTokenSignedResponseAlg()
    {
        return _idTokenSignedResponseAlg;
    }

    public override string? GetIdTokenEncryptedResponseAlg()
    {
        return _idTokenEncryptedResponseAlg;
    }

    public override string? GetIdTokenEncryptedResponseEnc()
    {
        return _idTokenEncryptedResponseEnc;
    }

    public override string? GetUserinfoSignedResponseAlg()
    {
        return _userinfoSignedResponseAlg;
    }

    public override string? GetUserinfoEncryptedResponseAlg()
    {
        return _userinfoEncryptedResponseAlg;
    }

    public override string? GetUserinfoEncryptedResponseEnc()
    {
        return _userinfoEncryptedResponseEnc;
    }

    public override string? GetRequestObjectSigningAlg()
    {
        return _requestObjectSigningAlg;
    }

    public override string? GetRequestObjectEncryptionAlg()
    {
        return _requestObjectEncryptionAlg;
    }

    public override string? GetRequestObjectEncryptionEnc()
    {
        return _requestObjectEncryptionEnc;
    }

    public override string? GetTokenEndpointAuthSigningAlg()
    {
        return _tokenEndpointAuthSigningAlg;
    }

    public override long? GetDefaultMaxAge()
    {
        return _defaultMaxAge;
    }

    public override bool? GetRequireAuthTime()
    {
        return _requireAuthTime;
    }

    public override IReadOnlySet<string> GetDefaultAcrValues()
    {
        return _defaultAcrValues;
    }

    public override Uri? GetInitiateLoginUri()
    {
        return _initiateLoginUri;
    }

    public override IReadOnlySet<Uri> GetRequestUris()
    {
        return _requestUris;
    }

    public override IReadOnlySet<string> GetAllowedCodeChallengeMethods()
    {
        return _allowedCodeChallengeMethods;
    }

    public override string? GetAccessTokenSignedResponseAlg()
    {
        return _accessTokenSignedResponseAlg;
    }

    public override bool CanSkipConsentScreen()
    {
        return _canSkipConsentScreen;
    }

    public override bool CanRememberConsent()
    {
        return _canRememberConsent;
    }

    public override long? GetConsentLifetime()
    {
        return _consentLifetime;
    }

    public override long GetAuthorizationCodeLifetime()
    {
        return _authorizationCodeLifetime;
    }

    public override bool ShouldIncludeUserClaimsInIdTokenAuthorizeResponse()
    {
        return _shouldIncludeUserClaimsInIdTokenAuthorizeResponse;
    }

    public override bool ShouldIncludeUserClaimsInIdTokenTokenResponse()
    {
        return _shouldIncludeUserClaimsInIdTokenTokenResponse;
    }

    public override long GetIdTokenLifetime()
    {
        return _idTokenLifetime;
    }

    public override string GetAccessTokenStrategy()
    {
        return _accessTokenStrategy;
    }

    public override bool ShouldIncludeJwtIdIntoAccessToken()
    {
        return _shouldIncludeJwtIdIntoAccessToken;
    }

    public override long GetAccessTokenLifetime()
    {
        return _accessTokenLifetime;
    }

    public override long GetRefreshTokenAbsoluteLifetime()
    {
        return _refreshTokenAbsoluteLifetime;
    }

    public override long GetRefreshTokenSlidingLifetime()
    {
        return _refreshTokenSlidingLifetime;
    }

    public override string GetRefreshTokenExpirationStrategy()
    {
        return _refreshTokenExpirationStrategy;
    }
}
