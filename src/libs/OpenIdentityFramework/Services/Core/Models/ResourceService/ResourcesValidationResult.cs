using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core.Models.ResourceService;

public class ResourcesValidationResult<TScope, TResource, TResourceSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractResourceSecret, IEquatable<TResourceSecret>
{
    public ResourcesValidationResult(ValidResources<TScope, TResource, TResourceSecret> valid)
    {
        ArgumentNullException.ThrowIfNull(valid);
        Valid = valid;
    }

    public ResourcesValidationResult(ResourcesValidationError<TScope, TResource, TResourceSecret> error)
    {
        ArgumentNullException.ThrowIfNull(error);
        Error = error;
        HasError = true;
    }

    public ValidResources<TScope, TResource, TResourceSecret>? Valid { get; }

    public ResourcesValidationError<TScope, TResource, TResourceSecret>? Error { get; }

    [MemberNotNullWhen(false, nameof(Valid))]
    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
