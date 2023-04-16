using System.Collections.Generic;

namespace OpenIdentityFramework.Models.Configuration;

public abstract class AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    /// <summary>
    ///     The unique name of the resource (API) that will be used with OAuth/OIDC protocols.
    /// </summary>
    /// <returns></returns>
    public abstract string GetProtocolName();

    /// <summary>
    ///     Returns the scopes this resource (API) allows.
    /// </summary>
    /// <returns></returns>
    public abstract IReadOnlySet<string> GetAccessTokenScopes();

    /// <summary>
    ///     The resource (API) secret is used for the introspection endpoint. The resource (API) can authenticate with introspection by using the unique name and one of its secrets.
    /// </summary>
    /// <returns></returns>
    public abstract IReadOnlyCollection<TResourceSecret> GetSecrets();
}
