using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizationCodeService;

public class AuthorizationCodeRequest<TClient, TClientSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public AuthorizationCodeRequest(
        UserAuthentication userAuthentication,
        TClient client,
        string? originalRedirectUri,
        IReadOnlySet<string> grantedScopes,
        string codeChallenge,
        string codeChallengeMethod,
        string? nonce,
        string? state,
        string issuer,
        DateTimeOffset issuedAt)
    {
        UserAuthentication = userAuthentication;
        Client = client;
        OriginalRedirectUri = originalRedirectUri;
        GrantedScopes = grantedScopes;
        CodeChallenge = codeChallenge;
        CodeChallengeMethod = codeChallengeMethod;
        Nonce = nonce;
        State = state;
        Issuer = issuer;
        IssuedAt = issuedAt;
    }

    public UserAuthentication UserAuthentication { get; }

    public TClient Client { get; }

    public string? OriginalRedirectUri { get; }

    public IReadOnlySet<string> GrantedScopes { get; }

    public string CodeChallenge { get; }

    public string CodeChallengeMethod { get; }

    public string? Nonce { get; }

    public string? State { get; }

    public string Issuer { get; }

    public DateTimeOffset IssuedAt { get; }
}
