using System.Collections.Generic;

namespace OpenIdentityFramework.Constants;

public static class DefaultJwtClaimTypes
{
    public static readonly string Subject = "sub";
    public static readonly string ClientId = "client_id";
    public static readonly string Scope = "scope";
    public static readonly string AuthenticationTime = "auth_time";
    public static readonly string IdentityProvider = "idp"; // Authentication Scheme
    public static readonly string AuthenticationMethod = "amr"; // AuthenticationMethods "pwd" or "external"
    public static readonly string AuthenticationContextClassReference = "acr";
    public static readonly string AccessTokenHash = "at_hash";
    public static readonly string Audience = "aud";
    public static readonly string AuthorizedParty = "azp";
    public static readonly string AuthorizationCodeHash = "c_hash";
    public static readonly string Expiration = "exp";
    public static readonly string IssuedAt = "iat";
    public static readonly string Issuer = "iss";
    public static readonly string JwtId = "jti";
    public static readonly string Nonce = "nonce";
    public static readonly string NotBefore = "nbf";
    public static readonly string ReferenceTokenId = "reference_token_id";
    public static readonly string SessionId = "sid";
    public static readonly string Confirmation = "cnf";

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
