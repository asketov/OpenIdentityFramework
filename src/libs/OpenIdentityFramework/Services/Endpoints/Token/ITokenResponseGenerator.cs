using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Token.Models.TokenRequestValidator;
using OpenIdentityFramework.Services.Endpoints.Token.Models.TokenResponseGenerator;

namespace OpenIdentityFramework.Services.Endpoints.Token;

public interface ITokenResponseGenerator<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    Task<TokenResponse> CreateResponseAsync(
        HttpContext httpContext,
        ValidTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> request,
        CancellationToken cancellationToken);
}
