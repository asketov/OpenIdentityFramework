using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizationCodeService;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode>
    : IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    public DefaultAuthorizationCodeService(IAuthorizationCodeStorage<TRequestContext, TAuthorizationCode> storage, ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(systemClock);
        Storage = storage;
        SystemClock = systemClock;
    }

    protected IAuthorizationCodeStorage<TRequestContext, TAuthorizationCode> Storage { get; }
    protected ISystemClock SystemClock { get; }

    public virtual async Task<string> CreateAsync(
        TRequestContext requestContext,
        AuthorizationCodeRequest<TClient, TClientSecret> codeRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(codeRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var expiresAt = codeRequest.IssuedAt.Add(codeRequest.Client.GetAuthorizationCodeLifetime());
        return await Storage.CreateAsync(
            requestContext,
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

    public virtual async Task<TAuthorizationCode?> FindAsync(TRequestContext requestContext, string authorizationCode, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var code = await Storage.FindAsync(requestContext, authorizationCode, cancellationToken);
        if (code != null)
        {
            var expiresAt = code.GetExpirationDate();
            if (SystemClock.UtcNow < expiresAt)
            {
                return code;
            }

            await Storage.DeleteAsync(requestContext, authorizationCode, cancellationToken);
        }

        return null;
    }

    public virtual async Task DeleteAsync(TRequestContext requestContext, string authorizationCode, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Storage.DeleteAsync(requestContext, authorizationCode, cancellationToken);
    }
}
