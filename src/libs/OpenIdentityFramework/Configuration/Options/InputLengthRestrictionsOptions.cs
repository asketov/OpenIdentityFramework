namespace OpenIdentityFramework.Configuration.Options;

public class InputLengthRestrictionsOptions
{
    /// <summary>
    ///     Max length for "client_id".
    /// </summary>
    public int ClientId { get; set; } = 100;

    /// <summary>
    ///     Max length for "client_secret".
    /// </summary>
    public int ClientSecret { get; set; } = 300;

    /// <summary>
    ///     Max overall length for "scope".
    /// </summary>
    public int Scope { get; set; } = 500;

    /// <summary>
    ///     Single "scope" entry.
    /// </summary>
    public int ScopeSingleEntry { get; set; } = 100;

    /// <summary>
    ///     Max length for "state".
    /// </summary>
    public int State { get; set; } = 2000;

    /// <summary>
    ///     Max length for "redirect_uri".
    /// </summary>
    public int RedirectUri { get; set; } = 400;

    /// <summary>
    ///     Max length for "nonce".
    /// </summary>
    public int Nonce { get; set; } = 300;

    /// <summary>
    ///     Max length for "login_hint".
    /// </summary>
    public int LoginHint { get; set; } = 100;

    /// <summary>
    ///     Max length for "acr_values".
    /// </summary>
    public int AcrValues { get; set; } = 300;

    /// <summary>
    ///     Max length for "ui_locales".
    /// </summary>
    public int UiLocales { get; set; } = 100;

    /// <summary>
    ///     Min length for "code_verifier". https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.17
    /// </summary>
    public int CodeVerifierMinLength { get; set; } = 43;

    /// <summary>
    ///     Max length for "code_verifier". https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.17
    /// </summary>
    public int CodeVerifierMaxLength { get; set; } = 128;

    /// <summary>
    ///     Min length for "code_challenge". https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.18
    /// </summary>
    public int CodeChallengeMinLength { get; set; } = 43;

    /// <summary>
    ///     Max length for "code_challenge". https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.18
    /// </summary>
    public int CodeChallengeMaxLength { get; set; } = 128;

    /// <summary>
    ///     Max length for "code".
    /// </summary>
    public int Code { get; set; } = 300;

    /// <summary>
    ///     Max length for "refresh_token".
    /// </summary>
    public int RefreshToken { get; set; } = 300;
}
