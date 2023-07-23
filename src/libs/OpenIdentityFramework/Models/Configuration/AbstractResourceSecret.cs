namespace OpenIdentityFramework.Models.Configuration;

/// <summary>
///     OAuth 2.1 / OpenID Connect 1.0 resource secret model.
/// </summary>
public abstract class AbstractResourceSecret
{
    /// <summary>
    ///     Returns the resource (API) secret hash used by the resource to authenticate to the introspection endpoint.
    /// </summary>
    /// <returns>A non-empty <see cref="byte" /> array that is not equal to <see langword="null" />.</returns>
    public abstract byte[] GetHashedValue();

    /// <summary>
    ///     Returns the issue date of the resource secret. The date and time are represented as the number of seconds that have elapsed since 1970-01-01T00:00:00Z, as measured in UTC until the date/time of issuance.
    /// </summary>
    /// <returns>An <see cref="long" /> value that is greater than 0.</returns>
    public abstract long GetIssueDate();

    /// <summary>
    ///     Returns the expiration date of the resource secret. Time at which the resource secret will expire or 0 if it will not expire. The time is represented as the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time of expiration.
    /// </summary>
    /// <returns>An <see cref="long" /> value that is equal to or greater than 0</returns>
    public abstract long GetExpirationDate();
}
