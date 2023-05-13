using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.TokenRequestValidator;

namespace OpenIdentityFramework.Services.Endpoints.Token.Validation;

public interface ITokenRequestValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRefreshToken : AbstractRefreshToken<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<TokenRequestValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TRefreshToken, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> ValidateAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        string clientAuthenticationMethod,
        string issuer,
        CancellationToken cancellationToken);
}
