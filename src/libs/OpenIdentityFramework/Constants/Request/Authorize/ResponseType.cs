using System;
using System.Collections.Generic;
using System.Linq;

namespace OpenIdentityFramework.Constants.Request.Authorize;

public static class ResponseType
{
    public const string Code = "code";
    public const string CodeIdToken = "code id_token";

    public static readonly IReadOnlySet<string> HybridFlow = CodeIdToken.Split(' ').ToHashSet(StringComparer.Ordinal);

    public static readonly IReadOnlyDictionary<string, string> ToResponseMode =
        new Dictionary<string, string>
            {
                { Code, ResponseMode.Query },
                { CodeIdToken, ResponseMode.Fragment }
            }
            .AsReadOnly();
}
