using System;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestInteractionService;

public class ValidAuthorizeRequestInteraction<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public ValidAuthorizeRequestInteraction(
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        UserAuthentication userAuthentication,
        ValidResources<TScope, TResource, TResourceSecret> grantedResources)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(userAuthentication);
        ArgumentNullException.ThrowIfNull(grantedResources);
        AuthorizeRequest = authorizeRequest;
        UserAuthentication = userAuthentication;
        GrantedResources = grantedResources;
    }

    public ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> AuthorizeRequest { get; }

    public UserAuthentication UserAuthentication { get; }

    public ValidResources<TScope, TResource, TResourceSecret> GrantedResources { get; }
}
