using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.TokenService;

namespace OpenIdentityFramework.Services.Core;

public interface ITokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    Task<HashSet<LightweightClaim>> GetIdentityTokenClaimsAsync(
        HttpContext httpContext,
        IdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> idTokenRequest,
        SigningCredentials signingCredentials,
        CancellationToken cancellationToken);

    Task<HashSet<LightweightClaim>> GetAccessTokenClaimsAsync(
        HttpContext httpContext,
        AccessTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> accessTokenRequest,
        CancellationToken cancellationToken);
}
