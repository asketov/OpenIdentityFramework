using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Configuration.Options;

[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
public class OpenIdentityFrameworkOptions
{
    public EndpointOptions Endpoints { get; set; } = new();

    public InputLengthRestrictionsOptions InputLengthRestrictions { get; set; } = new();

    public ErrorHandlingOptions ErrorHandling { get; set; } = new();

    public ContentSecurityPolicyOptions ContentSecurityPolicy { get; set; } = new();

    public UserInteractionOptions UserInteraction { get; set; } = new();

    public AuthenticationOptions Authentication { get; set; } = new();

    public bool EmitScopesAsSpaceDelimitedStringInJwt { get; set; }
}
