using OpenIdentityFramework.Configuration.Options.Enums;

namespace OpenIdentityFramework.Configuration.Options;

public class ContentSecurityPolicyOptions
{
    public ContentSecurityPolicyLevel Level { get; set; } = ContentSecurityPolicyLevel.Two;

    public bool AddDeprecatedHeader { get; set; } = true;
}
