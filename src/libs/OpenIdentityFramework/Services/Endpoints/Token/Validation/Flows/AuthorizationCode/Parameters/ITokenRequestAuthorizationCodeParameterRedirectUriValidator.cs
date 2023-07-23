using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.AuthorizationCode.Parameters;

namespace OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.AuthorizationCode.Parameters;

public interface ITokenRequestAuthorizationCodeParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    Task<TokenRequestAuthorizationCodeParameterRedirectUriValidationResult> ValidateRedirectUriAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        TAuthorizationCode authorizationCode,
        CancellationToken cancellationToken);
}
