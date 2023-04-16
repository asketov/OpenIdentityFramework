namespace OpenIdentityFramework.Models.Configuration;

public abstract class AbstractScope
{
    /// <summary>
    ///     The unique name of the access token scope that will be used with OAuth/OIDC protocols.
    /// </summary>
    /// <returns></returns>
    public abstract string GetProtocolName();

    /// <summary>
    ///     The type of token with which the scope can be used.
    /// </summary>
    /// <returns></returns>
    public abstract string GetScopeTokenType();
}
