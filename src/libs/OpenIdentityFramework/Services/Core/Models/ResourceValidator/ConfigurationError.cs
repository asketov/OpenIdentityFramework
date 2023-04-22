using System.Collections.Generic;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core.Models.ResourceValidator;

public class ConfigurationError<TScope, TResource, TResourceSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public ConfigurationError(
        IReadOnlySet<string>? scopesDuplicates,
        IReadOnlySet<string>? resourcesDuplicates,
        IReadOnlySet<TScope>? misconfiguredScopes,
        IReadOnlySet<TResource>? misconfiguredResources)
    {
        MisconfiguredResources = misconfiguredResources;
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

        if (misconfiguredResources is { Count: > 0 })
        {
            MisconfiguredResources = misconfiguredResources;
        }
    }

    public IReadOnlySet<string>? ScopesDuplicates { get; }
    public IReadOnlySet<string>? ResourcesDuplicates { get; }
    public IReadOnlySet<TScope>? MisconfiguredScopes { get; }
    public IReadOnlySet<TResource>? MisconfiguredResources { get; }
}
