using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizationCodeService;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizationCodeService<TClient, TClientSecret, TAuthorizationCode>
    : IAuthorizationCodeService<TClient, TClientSecret, TAuthorizationCode>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    public DefaultAuthorizationCodeService(IAuthorizationCodeStorage<TAuthorizationCode> storage, ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(systemClock);
        Storage = storage;
        SystemClock = systemClock;
    }

    protected IAuthorizationCodeStorage<TAuthorizationCode> Storage { get; }
    protected ISystemClock SystemClock { get; }

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
            codeRequest.OriginalRedirectUri,
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

    public virtual async Task<TAuthorizationCode?> FindAsync(HttpContext httpContext, string authorizationCode, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var code = await Storage.FindAsync(httpContext, authorizationCode, cancellationToken);
        if (code != null)
        {
            var expiresAt = code.GetExpirationDate();
            if (SystemClock.UtcNow < expiresAt)
            {
                return code;
            }

            await Storage.DeleteAsync(httpContext, authorizationCode, cancellationToken);
        }

        return null;
    }

    public virtual async Task DeleteAsync(HttpContext httpContext, string authorizationCode, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Storage.DeleteAsync(httpContext, authorizationCode, cancellationToken);
    }
}
