using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.RefreshTokenService;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultRefreshTokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken>
    : IRefreshTokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TRefreshToken : AbstractRefreshToken
{
    public Task<RefreshTokenCreationResult> CreateAsync(
        HttpContext httpContext,
        CreateRefreshTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createRefreshTokenRequest,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<TRefreshToken?> FindAsync(
        HttpContext httpContext,
        string issuer,
        string refreshToken,
        string clientId,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<RefreshTokenCreationResult> DeleteAsync(HttpContext httpContext, string refreshTokenHandle, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
