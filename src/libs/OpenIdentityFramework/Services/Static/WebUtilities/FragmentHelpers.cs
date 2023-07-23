using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Encodings.Web;

namespace OpenIdentityFramework.Services.Static.WebUtilities;

public static class FragmentHelpers
{
    public static string AddAnchorQueryString(
        string uri,
        IEnumerable<KeyValuePair<string, string?>> anchorQueryString)
    {
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentNullException.ThrowIfNull(anchorQueryString);
        var hasAnchor = uri.IndexOf('#', StringComparison.Ordinal) != -1;
        var sb = new StringBuilder();
        sb.Append(uri);
        foreach (var parameter in anchorQueryString)
        {
            if (parameter.Value == null)
            {
                continue;
            }

            sb.Append(hasAnchor ? '&' : '#');
            sb.Append(UrlEncoder.Default.Encode(parameter.Key));
            sb.Append('=');
            sb.Append(UrlEncoder.Default.Encode(parameter.Value));
            hasAnchor = true;
        }

        return sb.ToString();
    }
}
