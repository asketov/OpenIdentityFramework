namespace OpenIdentityFramework.Services.Endpoints.Token;

public interface ICodeVerifierValidator
{
    bool IsValid(string codeChallenge, string codeChallengeMethod, string codeVerifier);
}
