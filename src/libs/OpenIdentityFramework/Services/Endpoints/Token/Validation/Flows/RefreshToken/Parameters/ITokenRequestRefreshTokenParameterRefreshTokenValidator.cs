using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.RefreshToken.Parameters;

namespace OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.RefreshToken.Parameters;

public interface ITokenRequestRefreshTokenParameterRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<TokenRequestRefreshTokenParameterRefreshTokenValidationResult<TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> ValidateRefreshTokenAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        CancellationToken cancellationToken);
}
