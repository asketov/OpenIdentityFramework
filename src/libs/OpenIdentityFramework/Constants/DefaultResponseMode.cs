using System.Collections.Generic;

namespace OpenIdentityFramework.Constants;

public static class DefaultResponseMode
{
    public const string Query = "query";
    public const string Fragment = "fragment";
    public const string FormPost = "form_post";

    public static readonly IReadOnlySet<string> Supported = new HashSet<string>
    {
        Query,
        Fragment,
        FormPost
    };
}
