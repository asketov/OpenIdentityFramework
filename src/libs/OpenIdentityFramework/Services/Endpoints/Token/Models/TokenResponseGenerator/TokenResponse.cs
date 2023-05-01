namespace OpenIdentityFramework.Services.Endpoints.Token.Models.TokenResponseGenerator;

public class TokenResponse
{
    public TokenResponse(
        string accessToken,
        string issuedTokenType,
        string? refreshToken,
        long expiresIn,
        string? idToken,
        string? scope,
        string issuer)
    {
        AccessToken = accessToken;
        IssuedTokenType = issuedTokenType;
        RefreshToken = refreshToken;
        ExpiresIn = expiresIn;
        IdToken = idToken;
        Scope = scope;
        Issuer = issuer;
    }

    public string AccessToken { get; }

    public string IssuedTokenType { get; }

    public string? RefreshToken { get; }

    public long ExpiresIn { get; }

    public string? IdToken { get; }

    public string? Scope { get; }

    public string Issuer { get; }
}
