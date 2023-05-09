using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Constants.Response;

[SuppressMessage("ReSharper", "IdentifierTypo")]
public static class DiscoveryResponseParameters
{
    // OpenId Connect 1.0
    // https://openid.net/specs/openid-connect-discovery-1_0.html#rfc.section.3
    public const string Issuer = "issuer";
    public const string AuthorizationEndpoint = "authorization_endpoint";
    public const string TokenEndpoint = "token_endpoint";
    public const string UserinfoEndpoint = "userinfo_endpoint";
    public const string JwksUri = "jwks_uri";
    public const string RegistrationEndpoint = "registration_endpoint";
    public const string ScopesSupported = "scopes_supported";
    public const string ResponseTypesSupported = "response_types_supported";
    public const string ResponseModesSupported = "response_modes_supported";
    public const string GrantTypesSupported = "grant_types_supported";
    public const string AcrValuesSupported = "acr_values_supported";
    public const string SubjectTypesSupported = "subject_types_supported";
    public const string IdTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported";
    public const string IdTokenEncryptionAlgValuesSupported = "id_token_encryption_alg_values_supported";
    public const string IdTokenEncryptionEncValuesSupported = "id_token_encryption_enc_values_supported";
    public const string UserinfoSigningAlgValuesSupported = "userinfo_signing_alg_values_supported";
    public const string UserinfoEncryptionAlgValuesSupported = "userinfo_encryption_alg_values_supported";
    public const string UserinfoEncryptionEncValuesSupported = "userinfo_encryption_enc_values_supported";
    public const string RequestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported";
    public const string RequestObjectEncryptionAlgValuesSupported = "request_object_encryption_alg_values_supported";
    public const string RequestObjectEncryptionEncValuesSupported = "request_object_encryption_enc_values_supported";
    public const string TokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported";
    public const string TokenEndpointAuthSigningAlgValuesSupported = "token_endpoint_auth_signing_alg_values_supported";
    public const string DisplayValuesSupported = "display_values_supported";
    public const string ClaimTypesSupported = "claim_types_supported";
    public const string ClaimsSupported = "claims_supported";
    public const string ServiceDocumentation = "service_documentation";
    public const string ClaimsLocalesSupported = "claims_locales_supported";
    public const string UiLocalesSupported = "ui_locales_supported";
    public const string ClaimsParameterSupported = "claims_parameter_supported";
    public const string RequestParameterSupported = "request_parameter_supported";
    public const string RequestUriParameterSupported = "request_uri_parameter_supported";
    public const string RequireRequestUriRegistration = "require_request_uri_registration";
    public const string OpPolicyUri = "op_policy_uri";
    public const string OpTosUri = "op_tos_uri";
}
