namespace OpenIdentityFramework.Constants;

public static class DefaultAccessTokenStrategy
{
    /// <summary>
    ///     A string with a random set of characters
    /// </summary>
    public const string Opaque = "opaque";

    /// <summary>
    ///     <a href="https://www.rfc-editor.org/rfc/rfc7519.html">JSON Web Token (JWT)</a>
    /// </summary>
    public const string Jwt = "jwt";
}
