using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Constants;

[SuppressMessage("ReSharper", "IdentifierTypo")]
public static class DefaultRoutes
{
    public const string Error = "/error";
    public const string Login = "/login";
    public const string Consent = "/consent";

    public const string Authorize = "/connect/authorize";
    public const string AuthorizeCallback = "/connect/authorize/callback";
    public const string Token = "/connect/token";
    public const string Discovery = "/.well-known/openid-configuration";
    public const string Jwks = "/.well-known/openid-configuration/jwks";
    public const string UserInfo = "/connect/userinfo";
}
