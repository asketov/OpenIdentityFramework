using System;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceService;

namespace OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.ClientCredentials;

public class ValidClientCredentialsTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
{
    public ValidClientCredentialsTokenRequest(TClient client, ValidResources<TScope, TResource, TResourceSecret> allowedResources)
    {
        Client = client;
        AllowedResources = allowedResources;
    }

    public TClient Client { get; }
    public ValidResources<TScope, TResource, TResourceSecret> AllowedResources { get; }
}
