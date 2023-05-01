using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.IdTokenService;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : IIdTokenService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public DefaultIdTokenService(
        ITokenClaimsService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> tokenClaims,
        IKeyMaterialService<TRequestContext> keyMaterial,
        IJwtService<TRequestContext> jwtService)
    {
        ArgumentNullException.ThrowIfNull(tokenClaims);
        ArgumentNullException.ThrowIfNull(keyMaterial);
        ArgumentNullException.ThrowIfNull(jwtService);
        TokenClaims = tokenClaims;
        KeyMaterial = keyMaterial;
        JwtService = jwtService;
    }

    protected ITokenClaimsService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> TokenClaims { get; }
    protected IKeyMaterialService<TRequestContext> KeyMaterial { get; }
    protected IJwtService<TRequestContext> JwtService { get; }

    public virtual async Task<IdTokenCreationResult> CreateIdTokenAsync(
        TRequestContext requestContext,
        CreateIdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createIdTokenRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createIdTokenRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var signingCredentials = await KeyMaterial.GetSigningCredentialsAsync(
            requestContext,
            createIdTokenRequest.Issuer,
            createIdTokenRequest.Client.GetAllowedIdTokenSigningAlgorithms(),
            cancellationToken);
        var claims = await TokenClaims.GetIdentityTokenClaimsAsync(requestContext, createIdTokenRequest, signingCredentials, cancellationToken);
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(createIdTokenRequest.IssuedAt.ToUnixTimeSeconds());
        var expiresAt = issuedAt.Add(createIdTokenRequest.Client.GetIdTokenLifetime());
        var idTokenHandle = await JwtService.CreateIdTokenAsync(
            requestContext,
            signingCredentials,
            issuedAt,
            expiresAt,
            claims,
            cancellationToken);
        return new(new CreatedIdToken(idTokenHandle));
    }
}
