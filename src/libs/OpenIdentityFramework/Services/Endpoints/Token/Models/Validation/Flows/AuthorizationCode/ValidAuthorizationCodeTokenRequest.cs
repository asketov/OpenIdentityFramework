using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.AuthorizationCode;

public class ValidAuthorizationCodeTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    public ValidAuthorizationCodeTokenRequest(TClient client, ValidResources<TScope, TResource, TResourceSecret> allowedResources, string authorizationCodeHandle, TAuthorizationCode authorizationCode, ResourceOwnerProfile resourceOwnerProfile)
    {
        Client = client;
        AllowedResources = allowedResources;
        AuthorizationCodeHandle = authorizationCodeHandle;
        AuthorizationCode = authorizationCode;
        ResourceOwnerProfile = resourceOwnerProfile;
    }

    public TClient Client { get; }
    public ValidResources<TScope, TResource, TResourceSecret> AllowedResources { get; }
    public string AuthorizationCodeHandle { get; }
    public TAuthorizationCode AuthorizationCode { get; }
    public ResourceOwnerProfile ResourceOwnerProfile { get; }
}
