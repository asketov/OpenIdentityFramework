using System.Collections.Generic;

namespace OpenIdentityFramework.Constants;

public static class DefaultSubjectTypes
{
    public const string Public = "public";
    public const string Pairwise = "pairwise";

    public static readonly IReadOnlySet<string> Supported = new HashSet<string>
    {
        Public
    };
}
