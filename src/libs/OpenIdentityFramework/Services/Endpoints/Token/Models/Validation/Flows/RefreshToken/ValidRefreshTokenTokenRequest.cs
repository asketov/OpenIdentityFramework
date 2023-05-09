using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerProfileService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.RefreshToken;

public class ValidRefreshTokenTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRefreshToken>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TRefreshToken : AbstractRefreshToken
{
    public ValidRefreshTokenTokenRequest(TClient client, ValidResources<TScope, TResource, TResourceSecret> allowedResources, string refreshTokenHandle, TRefreshToken refreshToken, ResourceOwnerProfile resourceOwnerProfile)
    {
        Client = client;
        AllowedResources = allowedResources;
        RefreshTokenHandle = refreshTokenHandle;
        RefreshToken = refreshToken;
        ResourceOwnerProfile = resourceOwnerProfile;
    }

    public TClient Client { get; }
    public ValidResources<TScope, TResource, TResourceSecret> AllowedResources { get; }
    public string RefreshTokenHandle { get; }
    public TRefreshToken RefreshToken { get; }
    public ResourceOwnerProfile ResourceOwnerProfile { get; }
}
