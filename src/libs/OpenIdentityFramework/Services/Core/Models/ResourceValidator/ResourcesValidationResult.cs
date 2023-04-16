using System;
using System.Diagnostics.CodeAnalysis;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core.Models.ResourceValidator;

public class ResourcesValidationResult<TScope, TResource, TResourceSecret>
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public ResourcesValidationResult(ValidResources<TScope, TResource, TResourceSecret> valid)
    {
        ArgumentNullException.ThrowIfNull(valid);
        Valid = valid;
    }

    public ResourcesValidationResult(ResourcesValidationError<TScope> error)
    {
        ArgumentNullException.ThrowIfNull(error);
        Error = error;
        HasError = true;
    }

    public ValidResources<TScope, TResource, TResourceSecret>? Valid { get; }

    public ResourcesValidationError<TScope>? Error { get; }

    [MemberNotNullWhen(false, nameof(Valid))]
    [MemberNotNullWhen(true, nameof(Error))]
    public bool HasError { get; }
}
