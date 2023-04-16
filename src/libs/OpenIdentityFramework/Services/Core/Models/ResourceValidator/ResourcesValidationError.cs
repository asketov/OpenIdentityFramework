using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core.Models.ResourceValidator;

public class ResourcesValidationError<TScope>
    where TScope : AbstractScope
{
    public ResourcesValidationError(ConfigurationError<TScope> configurationError)
    {
        ArgumentNullException.ThrowIfNull(configurationError);
        ConfigurationError = configurationError;
        HasConfigurationError = true;
    }

    public ResourcesValidationError(IReadOnlySet<string> requestedScopesThatIncompatibleWithClient)
    {
        ArgumentNullException.ThrowIfNull(requestedScopesThatIncompatibleWithClient);
        RequestedScopesThatIncompatibleWithClient = requestedScopesThatIncompatibleWithClient;
    }

    public ConfigurationError<TScope>? ConfigurationError { get; }

    public IReadOnlySet<string>? RequestedScopesThatIncompatibleWithClient { get; }

    [MemberNotNullWhen(true, nameof(ConfigurationError))]
    [MemberNotNullWhen(false, nameof(RequestedScopesThatIncompatibleWithClient))]
    public bool HasConfigurationError { get; }
}
