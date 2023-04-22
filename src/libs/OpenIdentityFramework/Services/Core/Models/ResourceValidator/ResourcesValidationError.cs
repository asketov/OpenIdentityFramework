using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core.Models.ResourceValidator;

public class ResourcesValidationError<TScope, TResource, TResourceSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public ResourcesValidationError(ConfigurationError<TScope, TResource, TResourceSecret> configurationError)
    {
        ArgumentNullException.ThrowIfNull(configurationError);
        ConfigurationError = configurationError;
        HasConfigurationError = true;
    }

    public ResourcesValidationError(IReadOnlySet<string> disallowedScopes)
    {
        ArgumentNullException.ThrowIfNull(disallowedScopes);
        DisallowedScopes = disallowedScopes;
    }

    public ConfigurationError<TScope, TResource, TResourceSecret>? ConfigurationError { get; }

    public IReadOnlySet<string>? DisallowedScopes { get; }

    [MemberNotNullWhen(true, nameof(ConfigurationError))]
    [MemberNotNullWhen(false, nameof(DisallowedScopes))]
    public bool HasConfigurationError { get; }
}
