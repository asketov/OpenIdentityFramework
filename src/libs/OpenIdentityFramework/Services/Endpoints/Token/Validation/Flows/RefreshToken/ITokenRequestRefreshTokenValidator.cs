using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.RefreshToken;

namespace OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.RefreshToken;

public interface ITokenRequestRefreshTokenValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
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
    Task<TokenRequestRefreshTokenValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> ValidateAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        CancellationToken cancellationToken);
}
