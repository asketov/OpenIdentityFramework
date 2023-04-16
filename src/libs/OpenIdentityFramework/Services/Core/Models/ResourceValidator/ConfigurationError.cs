using System.Collections.Generic;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core.Models.ResourceValidator;

public class ConfigurationError<TScope> where TScope : AbstractScope
{
    public ConfigurationError(
        IReadOnlySet<string>? scopesDuplicates,
        IReadOnlySet<string>? resourcesDuplicates,
        IReadOnlySet<TScope>? misconfiguredScopes)
    {
        if (scopesDuplicates is { Count: > 0 })
        {
            ScopesDuplicates = scopesDuplicates;
        }

        if (resourcesDuplicates is { Count: > 0 })
        {
            ResourcesDuplicates = resourcesDuplicates;
        }

        if (misconfiguredScopes is { Count: > 0 })
        {
            MisconfiguredScopes = misconfiguredScopes;
        }
    }

    public IReadOnlySet<string>? ScopesDuplicates { get; }
    public IReadOnlySet<string>? ResourcesDuplicates { get; }
    public IReadOnlySet<TScope>? MisconfiguredScopes { get; }
}
