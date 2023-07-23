using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.AccessTokenService;
using OpenIdentityFramework.Services.Core.Models.RefreshTokenService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    : IRefreshTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public DefaultRefreshTokenService(
        OpenIdentityFrameworkOptions frameworkOptions,
        TimeProvider timeProvider,
        IRefreshTokenStorage<TRequestContext, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> storage)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(storage);
        FrameworkOptions = frameworkOptions;
        TimeProvider = timeProvider;
        Storage = storage;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected TimeProvider TimeProvider { get; }
    protected IRefreshTokenStorage<TRequestContext, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> Storage { get; }

    public virtual async Task<RefreshTokenCreationResult> CreateAsync(
        TRequestContext requestContext,
        string issuer,
        ValidRefreshToken<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? previousRefreshToken,
        CreatedAccessToken<TClient, TClientSecret, TScope, TResource, TResourceSecret, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> createdAccessToken,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createdAccessToken);
        cancellationToken.ThrowIfCancellationRequested();
        var referenceAccessTokenHandle = createdAccessToken.AccessTokenFormat == DefaultAccessTokenStrategy.Opaque
            ? createdAccessToken.Handle
            : null;
        if (createdAccessToken.ResourceOwnerProfile is null)
        {
            return new("Can't create refresh token. Resource Owner data is missing.");
        }

        return await CreateRefreshTokenAsync(
            requestContext,
            createdAccessToken.Client,
            createdAccessToken.ResourceOwnerProfile.EssentialClaims,
            createdAccessToken.GrantedResources,
            createdAccessToken.ActualIssuedAt,
            referenceAccessTokenHandle,
            previousRefreshToken,
            cancellationToken);
    }

    public virtual async Task<TRefreshToken?> FindAsync(
        TRequestContext requestContext,
        TClient client,
        string refreshTokenHandle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();

        var refreshToken = await Storage.FindAsync(requestContext, refreshTokenHandle, cancellationToken);
        if (refreshToken == null)
        {
            return null;
        }

        if (refreshToken.GetClientId() == client.GetClientId())
        {
            var expiresAt = refreshToken.GetExpirationDate();
            if (TimeProvider.GetUtcNow() > expiresAt)
            {
                await Storage.DeleteAsync(requestContext, refreshTokenHandle, cancellationToken);
                return null;
            }

            if (client.GetGrantTypes().Contains(DefaultGrantTypes.RefreshToken))
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

    protected virtual async Task<RefreshTokenCreationResult> CreateRefreshTokenAsync(
        TRequestContext requestContext,
        TClient client,
        TResourceOwnerEssentialClaims essentialClaims,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources,
        DateTimeOffset issuedAt,
        string? referenceAccessTokenHandle,
        ValidRefreshToken<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? previousRefreshToken,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(grantedResources);
        cancellationToken.ThrowIfCancellationRequested();
        var roundIssuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAt.ToUnixTimeSeconds());
        if (!TryComputeTokenLifetime(client, out var lifetime))
        {
            return new("Unable to compute refresh token lifetime");
        }

        var roundExpiresAt = DateTimeOffset.FromUnixTimeSeconds(roundIssuedAt.Add(lifetime.Value).ToUnixTimeSeconds());
        DateTimeOffset? absoluteExpirationDate = null;
        if (HasAbsoluteExpirationDate(client, roundExpiresAt, previousRefreshToken, out var possibleAbsoluteExpirationDate))
        {
            absoluteExpirationDate = possibleAbsoluteExpirationDate.Value;
            if (possibleAbsoluteExpirationDate.Value < roundExpiresAt)
            {
                roundExpiresAt = possibleAbsoluteExpirationDate.Value;
            }
        }

        if (previousRefreshToken is not null)
        {
            await Storage.DeleteAsync(requestContext, previousRefreshToken.Handle, cancellationToken);
        }

        var refreshTokenHandle = await Storage.CreateAsync(
            requestContext,
            client.GetClientId(),
            essentialClaims,
            grantedResources.RawScopes,
            referenceAccessTokenHandle,
            previousRefreshToken?.Handle,
            roundIssuedAt,
            roundExpiresAt,
            absoluteExpirationDate,
            cancellationToken);
        var createdRefreshToken = new CreatedRefreshToken(refreshTokenHandle);
        return new(createdRefreshToken);
    }

    protected virtual bool TryComputeTokenLifetime(TClient client, [NotNullWhen(true)] out TimeSpan? result)
    {
        ArgumentNullException.ThrowIfNull(client);
        var expirationStrategy = client.GetRefreshTokenExpirationStrategy();
        var absoluteLifetime = TimeSpan.FromSeconds(client.GetRefreshTokenAbsoluteLifetime());
        var slidingLifetime = TimeSpan.FromSeconds(client.GetRefreshTokenSlidingLifetime());
        if (expirationStrategy == DefaultRefreshTokenExpirationStrategy.Sliding)
        {
            if (absoluteLifetime > TimeSpan.Zero && slidingLifetime > absoluteLifetime)
            {
                result = absoluteLifetime;
                return true;
            }

            result = slidingLifetime;
            return true;
        }

        if (expirationStrategy == DefaultRefreshTokenExpirationStrategy.Absolute)
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
        ValidRefreshToken<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>? previousRefreshToken,
        [NotNullWhen(true)] out DateTimeOffset? absoluteExpirationDate)
    {
        ArgumentNullException.ThrowIfNull(client);
        DateTimeOffset? previousAbsoluteExpirationDate;
        if (previousRefreshToken is not null && (previousAbsoluteExpirationDate = previousRefreshToken.Token.GetAbsoluteExpirationDate()).HasValue)
        {
            absoluteExpirationDate = DateTimeOffset.FromUnixTimeSeconds(previousAbsoluteExpirationDate.Value.ToUnixTimeSeconds());
            return true;
        }

        var expirationStrategy = client.GetRefreshTokenExpirationStrategy();
        if (expirationStrategy == DefaultRefreshTokenExpirationStrategy.Absolute)
        {
            absoluteExpirationDate = DateTimeOffset.FromUnixTimeSeconds(currentExpiresAt.ToUnixTimeSeconds());
            return true;
        }

        absoluteExpirationDate = null;
        return false;
    }
}
