using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.Models.Configuration;

/// <summary>
///     OAuth 2.1 / OpenID Connect 1.0 resource model.
/// </summary>
/// <typeparam name="TResourceSecret">Implementation of <see cref="TResourceSecret" />.</typeparam>
public abstract class AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
{
    /// <summary>
    ///     Returns the unique identifier of the resource (API) that will be used with the OAuth/OIDC protocols.
    /// </summary>
    /// <returns>A <see cref="string" /> that contains a non-null and non-empty value.</returns>
    public abstract string GetResourceId();

    /// <summary>
    ///     Returns the time at which the unique identifier of the resource was issued. The time is represented as the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time of issuance.
    /// </summary>
    /// <returns>An <see cref="long" /> value that is greater than 0.</returns>
    public abstract long GetResourceIdIssuedAt();

    /// <summary>
    ///     Returns the set of scopes that the given resource can introspect.
    /// </summary>
    /// <returns>A set that contains 0 or more values. Cannot be <see langword="null" />.</returns>
    public abstract IReadOnlySet<string> GetSupportedAccessTokenScopes();

    /// <summary>
    ///     Returns a set of secrets that can be used by the API Resource for token introspection.
    /// </summary>
    /// <returns>A set that contains 0 or more values. Cannot be <see langword="null" />.</returns>
    public abstract IReadOnlyCollection<TResourceSecret> GetSecrets();
}
