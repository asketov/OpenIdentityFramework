using System;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Responses;

namespace OpenIdentityFramework.Configuration.Options;

public class UserInteractionOptions
{
    public string ErrorUrl { get; set; } = DefaultRoutes.Error;

    public string LoginUrl { get; set; } = DefaultRoutes.Login;

    public string ConsentUrl { get; set; } = DefaultRoutes.Consent;
    public string ErrorId { get; set; } = DefaultRoutesParameters.ErrorId;
    public string AuthorizeRequestId { get; set; } = DefaultRoutesParameters.AuthorizeRequestId;

    public TimeSpan? AuthorizeRequestLifetime { get; set; } = TimeSpan.FromMinutes(15);
}
