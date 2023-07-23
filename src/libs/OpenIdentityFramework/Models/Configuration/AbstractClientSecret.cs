namespace OpenIdentityFramework.Models.Configuration;

/// <summary>
///     OAuth 2.1 / OpenID Connect 1.0 client secret model.
/// </summary>
public abstract class AbstractClientSecret
{
    /// <summary>
    ///     Returns the client secret ("client_secret") hash used by confidential clients to authenticate themselves to the token endpoint, as stated in <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.4.1">section 2.4.1 of the OAuth 2.1 specification</a>
    ///     . This value corresponds to the "client_secret" value specified in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">section 3.2.1 of the OAuth 2.0 Dynamic Client Registration Protocol specification</a>.
    /// </summary>
    /// <returns>A non-empty <see cref="byte" /> array that is not equal to <see langword="null" />.</returns>
    public abstract byte[] GetHashedValue();

    /// <summary>
    ///     Returns the issue date of the client secret. The date and time are represented as the number of seconds that have elapsed since 1970-01-01T00:00:00Z, as measured in UTC until the date/time of issuance.
    /// </summary>
    /// <returns>An <see cref="long" /> value that is greater than 0.</returns>
    public abstract long GetIssueDate();

    /// <summary>
    ///     Returns the expiration date of the client secret. Time at which the client secret will expire or 0 if it will not expire. The time is represented as the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time of expiration.
    /// </summary>
    /// <returns>An <see cref="long" /> value that is equal to or greater than 0</returns>
    public abstract long GetExpirationDate();
}
