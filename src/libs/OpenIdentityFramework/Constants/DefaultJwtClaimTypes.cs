using System.Collections.Generic;

namespace OpenIdentityFramework.Constants;

public static class DefaultJwtClaimTypes
{
    public const string Subject = "sub";
    public const string ClientId = "client_id";
    public const string Scope = "scope";
    public const string AuthenticationTime = "auth_time";
    public const string IdentityProvider = "idp"; // Authentication Scheme
    public const string AuthenticationMethod = "amr"; // AuthenticationMethods "pwd" or "external"
    public const string AuthenticationContextClassReference = "acr";
    public const string AccessTokenHash = "at_hash";
    public const string Audience = "aud";
    public const string AuthorizedParty = "azp";
    public const string AuthorizationCodeHash = "c_hash";
    public const string Expiration = "exp";
    public const string IssuedAt = "iat";
    public const string Issuer = "iss";
    public const string JwtId = "jti";
    public const string Nonce = "nonce";
    public const string NotBefore = "nbf";
    public const string ReferenceTokenId = "reference_token_id";
    public const string SessionId = "sid";
    public const string Confirmation = "cnf";

    public static readonly IReadOnlySet<string> Restrictions = new HashSet<string>
    {
        AccessTokenHash,
        Audience,
        AuthenticationMethod,
        AuthenticationTime,
        AuthorizedParty,
        AuthorizationCodeHash,
        ClientId,
        Expiration,
        IdentityProvider,
        IssuedAt,
        Issuer,
        JwtId,
        Nonce,
        NotBefore,
        ReferenceTokenId,
        SessionId,
        Subject,
        Scope,
        Confirmation
    };
}
