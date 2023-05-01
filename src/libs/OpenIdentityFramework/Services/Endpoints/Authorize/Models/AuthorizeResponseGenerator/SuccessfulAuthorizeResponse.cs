namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeResponseGenerator;

public class SuccessfulAuthorizeResponse
{
    public SuccessfulAuthorizeResponse(string code, string? state, string issuer, string? idToken)
    {
        Code = code;
        State = state;
        Issuer = issuer;
        IdToken = idToken;
    }

    public string Code { get; }

    public string? State { get; }

    public string Issuer { get; }

    public string? IdToken { get; }
}
