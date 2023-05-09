using System.Collections.Generic;

namespace OpenIdentityFramework.Constants;

public static class DefaultDisplay
{
    public const string Page = "page";
    public const string Popup = "popup";
    public const string Touch = "touch";
    public const string Wap = "wap";

    public static readonly IReadOnlySet<string> Supported = new HashSet<string>
    {
        Page,
        Popup,
        Touch,
        Wap
    };
}
