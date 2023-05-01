using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.IdTokenService;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultIdTokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : IIdTokenService<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public DefaultIdTokenService(
        ITokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret> tokenClaims,
        IKeyMaterialService keyMaterial,
        IJwtService jwtService)
    {
        ArgumentNullException.ThrowIfNull(tokenClaims);
        ArgumentNullException.ThrowIfNull(keyMaterial);
        ArgumentNullException.ThrowIfNull(jwtService);
        TokenClaims = tokenClaims;
        KeyMaterial = keyMaterial;
        JwtService = jwtService;
    }

    protected ITokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret> TokenClaims { get; }
    protected IKeyMaterialService KeyMaterial { get; }
    protected IJwtService JwtService { get; }

    public async Task<IdTokenCreationResult> CreateIdTokenAsync(
        HttpContext httpContext,
        CreateIdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> createIdTokenRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createIdTokenRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var signingCredentials = await KeyMaterial.GetSigningCredentialsAsync(httpContext, createIdTokenRequest.Issuer, createIdTokenRequest.Client.GetAllowedIdTokenSigningAlgorithms(), cancellationToken);
        var claims = await TokenClaims.GetIdentityTokenClaimsAsync(httpContext, createIdTokenRequest, signingCredentials, cancellationToken);
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(createIdTokenRequest.IssuedAt.ToUnixTimeSeconds());
        var expiresAt = issuedAt.Add(createIdTokenRequest.Client.GetIdTokenLifetime());
        var idTokenHandle = await JwtService.CreateIdTokenAsync(
            httpContext,
            signingCredentials,
            issuedAt,
            expiresAt,
            claims,
            cancellationToken);
        return new(new CreatedIdToken(idTokenHandle));
    }
}
