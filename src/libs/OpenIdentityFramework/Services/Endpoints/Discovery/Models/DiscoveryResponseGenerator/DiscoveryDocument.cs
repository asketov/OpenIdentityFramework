using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Services.Endpoints.Discovery.Models.DiscoveryResponseGenerator;

[SuppressMessage("ReSharper", "IdentifierTypo")]
public class DiscoveryDocument
{
    public DiscoveryDocument(
        string issuer,
        string authorizationEndpoint,
        string tokenEndpoint,
        string? userinfoEndpoint,
        string jwksUri,
        string? registrationEndpoint,
        IReadOnlyCollection<string>? scopesSupported,
        IReadOnlyCollection<string> responseTypesSupported,
        IReadOnlyCollection<string>? responseModesSupported,
        IReadOnlyCollection<string>? grantTypesSupported,
        IReadOnlyCollection<string>? acrValuesSupported,
        IReadOnlyCollection<string> subjectTypesSupported,
        IReadOnlyCollection<string> idTokenSigningAlgValuesSupported,
        IReadOnlyCollection<string>? idTokenEncryptionAlgValuesSupported,
        IReadOnlyCollection<string>? idTokenEncryptionEncValuesSupported,
        IReadOnlyCollection<string>? userinfoSigningAlgValuesSupported,
        IReadOnlyCollection<string>? userinfoEncryptionAlgValuesSupported,
        IReadOnlyCollection<string>? userinfoEncryptionEncValuesSupported,
        IReadOnlyCollection<string>? requestObjectSigningAlgValuesSupported,
        IReadOnlyCollection<string>? requestObjectEncryptionAlgValuesSupported,
        IReadOnlyCollection<string>? requestObjectEncryptionEncValuesSupported,
        IReadOnlyCollection<string>? tokenEndpointAuthMethodsSupported,
        IReadOnlyCollection<string>? tokenEndpointAuthSigningAlgValuesSupported,
        IReadOnlyCollection<string>? displayValuesSupported,
        IReadOnlyCollection<string>? claimTypesSupported,
        IReadOnlyCollection<string>? claimsSupported,
        string? serviceDocumentation,
        IReadOnlyCollection<string>? claimsLocalesSupported,
        IReadOnlyCollection<string>? uiLocalesSupported,
        bool? claimsParameterSupported,
        bool? requestParameterSupported,
        bool? requestUriParameterSupported,
        bool? requireRequestUriRegistration,
        string? opPolicyUri,
        string? opTosUri,
        Dictionary<string, object>? additionalParameters)
    {
        Issuer = issuer;
        AuthorizationEndpoint = authorizationEndpoint;
        TokenEndpoint = tokenEndpoint;
        UserinfoEndpoint = userinfoEndpoint;
        JwksUri = jwksUri;
        RegistrationEndpoint = registrationEndpoint;
        ScopesSupported = scopesSupported;
        ResponseTypesSupported = responseTypesSupported;
        ResponseModesSupported = responseModesSupported;
        GrantTypesSupported = grantTypesSupported;
        AcrValuesSupported = acrValuesSupported;
        SubjectTypesSupported = subjectTypesSupported;
        IdTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
        IdTokenEncryptionAlgValuesSupported = idTokenEncryptionAlgValuesSupported;
        IdTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
        UserinfoSigningAlgValuesSupported = userinfoSigningAlgValuesSupported;
        UserinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported;
        UserinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported;
        RequestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported;
        RequestObjectEncryptionAlgValuesSupported = requestObjectEncryptionAlgValuesSupported;
        RequestObjectEncryptionEncValuesSupported = requestObjectEncryptionEncValuesSupported;
        TokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
        TokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
        DisplayValuesSupported = displayValuesSupported;
        ClaimTypesSupported = claimTypesSupported;
        ClaimsSupported = claimsSupported;
        ServiceDocumentation = serviceDocumentation;
        ClaimsLocalesSupported = claimsLocalesSupported;
        UiLocalesSupported = uiLocalesSupported;
        ClaimsParameterSupported = claimsParameterSupported;
        RequestParameterSupported = requestParameterSupported;
        RequestUriParameterSupported = requestUriParameterSupported;
        RequireRequestUriRegistration = requireRequestUriRegistration;
        OpPolicyUri = opPolicyUri;
        OpTosUri = opTosUri;
        AdditionalParameters = additionalParameters;
    }

    public string Issuer { get; }
    public string AuthorizationEndpoint { get; }
    public string TokenEndpoint { get; }
    public string? UserinfoEndpoint { get; }
    public string JwksUri { get; }
    public string? RegistrationEndpoint { get; }
    public IReadOnlyCollection<string>? ScopesSupported { get; }
    public IReadOnlyCollection<string> ResponseTypesSupported { get; }
    public IReadOnlyCollection<string>? ResponseModesSupported { get; }
    public IReadOnlyCollection<string>? GrantTypesSupported { get; }
    public IReadOnlyCollection<string>? AcrValuesSupported { get; }
    public IReadOnlyCollection<string> SubjectTypesSupported { get; }
    public IReadOnlyCollection<string> IdTokenSigningAlgValuesSupported { get; }
    public IReadOnlyCollection<string>? IdTokenEncryptionAlgValuesSupported { get; }
    public IReadOnlyCollection<string>? IdTokenEncryptionEncValuesSupported { get; }
    public IReadOnlyCollection<string>? UserinfoSigningAlgValuesSupported { get; }
    public IReadOnlyCollection<string>? UserinfoEncryptionAlgValuesSupported { get; }
    public IReadOnlyCollection<string>? UserinfoEncryptionEncValuesSupported { get; }
    public IReadOnlyCollection<string>? RequestObjectSigningAlgValuesSupported { get; }
    public IReadOnlyCollection<string>? RequestObjectEncryptionAlgValuesSupported { get; }
    public IReadOnlyCollection<string>? RequestObjectEncryptionEncValuesSupported { get; }
    public IReadOnlyCollection<string>? TokenEndpointAuthMethodsSupported { get; }
    public IReadOnlyCollection<string>? TokenEndpointAuthSigningAlgValuesSupported { get; }
    public IReadOnlyCollection<string>? DisplayValuesSupported { get; }
    public IReadOnlyCollection<string>? ClaimTypesSupported { get; }
    public IReadOnlyCollection<string>? ClaimsSupported { get; }
    public string? ServiceDocumentation { get; }
    public IReadOnlyCollection<string>? ClaimsLocalesSupported { get; }
    public IReadOnlyCollection<string>? UiLocalesSupported { get; }
    public bool? ClaimsParameterSupported { get; }
    public bool? RequestParameterSupported { get; }
    public bool? RequestUriParameterSupported { get; }
    public bool? RequireRequestUriRegistration { get; }
    public string? OpPolicyUri { get; }
    public string? OpTosUri { get; }
    public Dictionary<string, object>? AdditionalParameters { get; }
}
