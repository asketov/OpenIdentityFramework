using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.TokenResponseGenerator;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;

namespace OpenIdentityFramework.Services.Endpoints.Token;

public interface ITokenResponseGenerator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<TokenResponseGenerationResult> CreateResponseAsync(
        TRequestContext requestContext,
        ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> request,
        CancellationToken cancellationToken);
}
