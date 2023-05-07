using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.RefreshToken;

namespace OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.RefreshToken;

public interface ITokenRequestRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TRefreshToken : AbstractRefreshToken
{
    Task<TokenRequestRefreshTokenValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken>> ValidateAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        CancellationToken cancellationToken);
}
