namespace OpenIdentityFramework.Configuration.Options;

public class InputLengthRestrictionsOptions
{
    /// <summary>
    ///     Max length for "client_id".
    /// </summary>
    public int ClientId { get; set; } = 100;

    /// <summary>
    ///     Max overall length for "scope".
    /// </summary>
    public int Scope { get; set; } = 500;

    /// <summary>
    ///     Single "scope" entry.
    /// </summary>
    public int ScopeSingleEntry { get; set; } = 100;
}
