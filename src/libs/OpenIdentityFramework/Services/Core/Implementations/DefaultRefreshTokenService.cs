using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.RefreshTokenService;
using OpenIdentityFramework.Storages.Operation;

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
    public DefaultRefreshTokenService(IRefreshTokenStorage<TRequestContext, TRefreshToken> storage, ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(systemClock);
        Storage = storage;
        SystemClock = systemClock;
    }

    protected IRefreshTokenStorage<TRequestContext, TRefreshToken> Storage { get; }
    protected ISystemClock SystemClock { get; }

    public async Task<RefreshTokenCreationResult> CreateAsync(
        TRequestContext requestContext,
        CreateRefreshTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken> createRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createRequest);
        cancellationToken.ThrowIfCancellationRequested();
        string? referenceAccessTokenHandle = null;
        if (createRequest.AccessToken.AccessTokenFormat == DefaultAccessTokenFormat.Reference)
        {
            referenceAccessTokenHandle = createRequest.AccessToken.Handle;
        }

        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(createRequest.IssuedAt.ToUnixTimeSeconds());
        if (!TryComputeTokenLifetime(createRequest.Client, out var lifetime))
        {
            return new("Unable to compute refresh token lifetime");
        }

        var expiresAt = issuedAt.Add(lifetime.Value);
        DateTimeOffset? absoluteExpirationDate = null;
        if (HasAbsoluteExpirationDate(createRequest.Client, expiresAt, createRequest.PreviousRefreshToken, out var possibleAbsoluteExpirationDate))
        {
            absoluteExpirationDate = possibleAbsoluteExpirationDate.Value;
        }

        var refreshTokenHandle = await Storage.CreateAsync(
            requestContext,
            createRequest.Issuer,
            createRequest.Client.GetClientId(),
            createRequest.AccessToken.UserAuthentication,
            createRequest.AccessToken.RequestedResources.RawScopes,
            createRequest.AccessToken.Claims,
            referenceAccessTokenHandle,
            issuedAt,
            expiresAt,
            absoluteExpirationDate,
            cancellationToken);
        return new(new CreatedRefreshToken(refreshTokenHandle));
    }


    public virtual async Task<TRefreshToken?> FindAsync(
        TRequestContext requestContext,
        TClient client,
        string issuer,
        string refreshTokenHandle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        var clientId = client.GetClientId();
        var refreshToken = await Storage.FindAsync(requestContext, refreshTokenHandle, issuer, clientId, cancellationToken);
        if (refreshToken == null)
        {
            return null;
        }

        if (refreshToken.GetClientId() == clientId)
        {
            var expiresAt = refreshToken.GetExpirationDate();
            if (SystemClock.UtcNow > expiresAt)
            {
                await Storage.DeleteAsync(requestContext, refreshTokenHandle, cancellationToken);
                return null;
            }

            if (client.GetAllowedAuthorizationFlows().Contains(DefaultAuthorizationFlows.RefreshToken))
            {
                return refreshToken;
            }
        }

        return null;
    }


    public virtual async Task DeleteAsync(
        TRequestContext requestContext,
        string refreshTokenHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Storage.DeleteAsync(requestContext, refreshTokenHandle, cancellationToken);
    }

    protected virtual bool TryComputeTokenLifetime(TClient client, [NotNullWhen(true)] out TimeSpan? result)
    {
        ArgumentNullException.ThrowIfNull(client);
        var expirationType = client.GetRefreshTokenExpirationType();
        var absoluteLifetime = client.GetRefreshTokenAbsoluteLifetime();
        var slidingLifetime = client.GetRefreshTokenSlidingLifetime();
        if (expirationType == DefaultRefreshTokenExpirationType.Sliding)
        {
            if (absoluteLifetime > TimeSpan.Zero && slidingLifetime > absoluteLifetime)
            {
                result = absoluteLifetime;
                return true;
            }

            result = slidingLifetime;
            return true;
        }

        if (expirationType == DefaultRefreshTokenExpirationType.Absolute)
        {
            result = absoluteLifetime;
            return true;
        }

        result = null;
        return false;
    }

    protected virtual bool HasAbsoluteExpirationDate(
        TClient client,
        DateTimeOffset currentExpiresAt,
        TRefreshToken? previousRefreshToken,
        [NotNullWhen(true)] out DateTimeOffset? absoluteExpirationDate)
    {
        ArgumentNullException.ThrowIfNull(client);
        DateTimeOffset? previousAbsoluteExpirationDate;
        if (previousRefreshToken is not null && (previousAbsoluteExpirationDate = previousRefreshToken.GetAbsoluteExpirationDate()).HasValue)
        {
            absoluteExpirationDate = previousAbsoluteExpirationDate.Value;
            return true;
        }

        var expirationType = client.GetRefreshTokenExpirationType();
        if (expirationType == DefaultRefreshTokenExpirationType.Absolute)
        {
            absoluteExpirationDate = currentExpiresAt;
            return true;
        }

        absoluteExpirationDate = null;
        return false;
    }
}
