using System.Collections.Generic;

namespace OpenIdentityFramework.Models.Configuration;

public abstract class AbstractScope
{
    /// <summary>
    ///     Returns the unique identifier of the scope that will be used with the OAuth/OIDC protocols.
    /// </summary>
    /// <returns>A <see cref="string" /> that contains a non-null and non-empty value.</returns>
    public abstract string GetScopeId();

    /// <summary>
    ///     Returns the token type with which the scope can be used.
    /// </summary>
    /// <returns>A <see cref="string" /> that contains a non-null and non-empty value.</returns>
    public abstract string GetScopeTokenType();

    /// <summary>
    ///     Returns a flag indicating the scope's requirement. If it returns <see langword="true" />, it means that on the consent screen, the user cannot deselect this scope if it was requested. If it returns <see langword="false" />, the user can deselect this scope on the consent
    ///     screen.
    /// </summary>
    /// <returns>A <see cref="bool" /> value.</returns>
    public abstract bool IsRequired();

    /// <summary>
    ///     Returns a flag indicating the requirement for displaying the scope in the discovery document.
    /// </summary>
    /// <returns>A <see cref="bool" /> value.</returns>
    public abstract bool ShowInDiscoveryEndpoint();

    /// <summary>
    ///     Returns a set of user claims that should be included in the corresponding token if this scope was requested.
    /// </summary>
    /// <returns>A set that contains 0 or more values. Cannot be <see langword="null" />.</returns>
    public abstract IReadOnlySet<string> GetUserClaimTypes();
}
