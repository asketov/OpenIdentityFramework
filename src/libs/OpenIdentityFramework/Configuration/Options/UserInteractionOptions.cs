using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Configuration.Options;

public class UserInteractionOptions
{
    public string ErrorUrl { get; set; } = DefaultRoutes.Error;

    public string LoginUrl { get; set; } = DefaultRoutes.Login;

    public string ConsentUrl { get; set; } = DefaultRoutes.Consent;
    public string ErrorId { get; set; } = DefaultRoutesParameters.ErrorId;
    public string AuthorizeRequestIdParameterName { get; set; } = DefaultRoutesParameters.AuthorizeRequestId;
}
