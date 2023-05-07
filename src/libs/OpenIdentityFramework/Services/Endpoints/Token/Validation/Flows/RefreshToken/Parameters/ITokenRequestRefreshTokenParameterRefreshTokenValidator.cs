using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.RefreshToken.Parameters;

namespace OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.RefreshToken.Parameters;

public interface ITokenRequestRefreshTokenParameterRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TRefreshToken>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TRefreshToken : AbstractRefreshToken
{
    Task<TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken>> ValidateRefreshTokenAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        CancellationToken cancellationToken);
}
