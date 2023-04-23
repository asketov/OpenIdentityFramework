using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizationCodeService;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Implementations;

public class DefaultAuthorizationCodeService<TClient, TClientSecret> : IAuthorizationCodeService<TClient, TClientSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public DefaultAuthorizationCodeService(IAuthorizationCodeStorage storage)
    {
        ArgumentNullException.ThrowIfNull(storage);
        Storage = storage;
    }

    protected IAuthorizationCodeStorage Storage { get; }

    public virtual async Task<string> CreateAsync(
        HttpContext httpContext,
        AuthorizationCodeRequest<TClient, TClientSecret> codeRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(codeRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var expiresAt = codeRequest.IssuedAt.Add(codeRequest.Client.GetAuthorizationCodeLifetime());
        return await Storage.CreateAsync(
            httpContext,
            codeRequest.UserAuthentication,
            codeRequest.Client.GetClientId(),
            codeRequest.RedirectUri,
            codeRequest.GrantedScopes,
            codeRequest.CodeChallenge,
            codeRequest.CodeChallengeMethod,
            codeRequest.Nonce,
            codeRequest.State,
            codeRequest.Issuer,
            codeRequest.IssuedAt,
            expiresAt,
            cancellationToken);
    }
}
