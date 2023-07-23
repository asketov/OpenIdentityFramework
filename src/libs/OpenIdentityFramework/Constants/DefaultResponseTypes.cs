using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.Constants;

public static class DefaultResponseTypes
{
    public static readonly IReadOnlySet<string> Code = new HashSet<string>(new[] { DefaultResponseType.Code }, StringComparer.Ordinal);

    public static readonly IReadOnlySet<string> CodeIdToken = new HashSet<string>(new[]
    {
        DefaultResponseType.Code,
        DefaultResponseType.IdToken
    }, StringComparer.Ordinal);

    public static readonly IReadOnlySet<string> Supported = new HashSet<string>
    {
        DefaultResponseType.Code,
        DefaultResponseType.CodeIdToken
    };
}
