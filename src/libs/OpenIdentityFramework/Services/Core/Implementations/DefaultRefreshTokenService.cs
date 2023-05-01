using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.RefreshTokenService;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken>
    : IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TRefreshToken : AbstractRefreshToken
{
    public Task<RefreshTokenCreationResult> CreateAsync(
        TRequestContext requestContext,
        CreateRefreshTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createRefreshTokenRequest,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<TRefreshToken?> FindAsync(
        TRequestContext requestContext,
        string issuer,
        string refreshToken,
        string clientId,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<RefreshTokenCreationResult> DeleteAsync(
        TRequestContext requestContext,
        string refreshTokenHandle,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
