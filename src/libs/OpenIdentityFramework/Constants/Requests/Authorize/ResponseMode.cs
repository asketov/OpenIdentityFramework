using System.Collections.Generic;

namespace OpenIdentityFramework.Constants.Requests.Authorize;

public static class ResponseMode
{
    public static readonly string Query = "query";
    public static readonly string Fragment = "fragment";
    public static readonly string FormPost = "form_post";

    public static readonly IReadOnlyDictionary<string, string> ResponseTypeToResponseMode =
        new Dictionary<string, string>
            {
                { ResponseType.Code, Query },
                { ResponseType.CodeIdToken, Fragment }
            }
            .AsReadOnly();
}
