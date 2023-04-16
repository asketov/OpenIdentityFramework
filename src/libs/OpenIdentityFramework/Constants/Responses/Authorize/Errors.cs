namespace OpenIdentityFramework.Constants.Responses.Authorize;

public static class Errors
{
    public static readonly string InvalidRequest = "invalid_request";
    public static readonly string UnauthorizedClient = "unauthorized_client";
    public static readonly string AccessDenied = "access_denied";
    public static readonly string UnsupportedResponseType = "unsupported_response_type";
    public static readonly string InvalidScope = "invalid_scope";
    public static readonly string ServerError = "server_error";
    public static readonly string TemporarilyUnavailable = "temporarily_unavailable";

    public static readonly string InteractionRequired = "interaction_required";
    public static readonly string LoginRequired = "login_required";
    public static readonly string AccountSelectionRequired = "account_selection_required";
    public static readonly string ConsentRequired = "consent_required";
    public static readonly string InvalidRequestUri = "invalid_request_uri";
    public static readonly string InvalidRequestObject = "invalid_request_object";
    public static readonly string RequestNotSupported = "request_not_supported";
    public static readonly string RequestUriNotSupported = "request_uri_not_supported";
    public static readonly string RegistrationNotSupported = "registration_not_supported";
}
