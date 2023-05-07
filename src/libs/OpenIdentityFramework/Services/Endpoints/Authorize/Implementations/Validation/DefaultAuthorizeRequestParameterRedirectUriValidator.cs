using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation;
using OpenIdentityFramework.Services.Static.SyntaxValidation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation;

public class DefaultAuthorizeRequestParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public DefaultAuthorizeRequestParameterRedirectUriValidator(OpenIdentityFrameworkOptions frameworkOptions)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        FrameworkOptions = frameworkOptions;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    public virtual Task<AuthorizeRequestParameterRedirectUriValidationResult> ValidateRedirectUriAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.3.1
        // Authorization servers MUST require clients to register their complete redirect URI (including the path component).
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // This URI MUST exactly match one of the Redirection URI values for the Client pre-registered at the OpenID Provider
        var preRegisteredRedirectUris = client.GetPreRegisteredRedirectUris();
        if (preRegisteredRedirectUris.Count < 1)
        {
            return Task.FromResult(AuthorizeRequestParameterRedirectUriValidationResult.NoPreRegisteredRedirectUrisInClientConfiguration);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // "redirect_uri" - OPTIONAL
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "redirect_uri" - REQUIRED.
        if (!parameters.Raw.TryGetValue(AuthorizeRequestParameters.RedirectUri, out var redirectUriValues) || redirectUriValues.Count == 0)
        {
            return Task.FromResult(InferRedirectUri(parameters.IsOpenIdRequest, preRegisteredRedirectUris));
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (redirectUriValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestParameterRedirectUriValidationResult.MultipleRedirectUriValuesNotAllowed);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var originalRedirectUri = redirectUriValues.ToString();
        if (string.IsNullOrEmpty(originalRedirectUri))
        {
            return Task.FromResult(InferRedirectUri(parameters.IsOpenIdRequest, preRegisteredRedirectUris));
        }

        // length check
        if (originalRedirectUri.Length > FrameworkOptions.InputLengthRestrictions.RedirectUri)
        {
            return Task.FromResult(AuthorizeRequestParameterRedirectUriValidationResult.RedirectUriIsTooLong);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.3
        if (!ClientRedirectUriSyntaxValidator.IsValid(originalRedirectUri, out var typedRedirectUri))
        {
            return Task.FromResult(AuthorizeRequestParameterRedirectUriValidationResult.InvalidRedirectUriSyntax);
        }

        // OpenID Connect 1.0
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // redirect_uri - REQUIRED. This URI MUST exactly match one of the Redirection URI values for the Client pre-registered at the OpenID Provider,
        // with the matching performed as described in Section 6.2.1 of [RFC3986] (Simple String Comparison).
        // When using this flow, the Redirection URI SHOULD use the https scheme; however, it MAY use the http scheme, provided that the Client Type is confidential.
        // The Redirection URI MAY use an alternate scheme, such as one that is intended to identify a callback into a native application.
        // https://learn.microsoft.com/en-us/dotnet/standard/base-types/best-practices-strings#recommendations-for-string-usage
        // Use the non-linguistic StringComparison.Ordinal or StringComparison.OrdinalIgnoreCase values instead of string operations based on CultureInfo.InvariantCulture
        // when the comparison is linguistically irrelevant (symbolic, for example).
        if (parameters.IsOpenIdRequest)
        {
            // Exact match for OIDC
            if (preRegisteredRedirectUris.Contains(originalRedirectUri, StringComparer.Ordinal))
            {
                // http scheme only for confidential clients
                if (typedRedirectUri.Scheme == Uri.UriSchemeHttp && !client.IsConfidential())
                {
                    return Task.FromResult(AuthorizeRequestParameterRedirectUriValidationResult.InvalidRedirectUri);
                }

                return Task.FromResult(new AuthorizeRequestParameterRedirectUriValidationResult(originalRedirectUri, originalRedirectUri));
            }

            return Task.FromResult(AuthorizeRequestParameterRedirectUriValidationResult.InvalidRedirectUri);
        }

        // OAuth 2.1
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-1.5
        // OAuth URLs MUST use the https scheme except for loopback interface redirect URIs, which MAY use the http scheme.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.3.1
        // Authorization servers MUST require clients to register their complete redirect URI (including the path component).
        // Authorization servers MUST reject authorization requests that specify a redirect URI that doesn't exactly match one that was registered,
        // with an exception for loopback redirects, where an exact match is required except for the port URI component.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // In particular, the authorization server MUST validate the redirect_uri in the request if present,
        // ensuring that it matches one of the registered redirect URIs previously established during client registration (Section 2).
        // When comparing the two URIs the authorization server MUST using simple character-by-character string comparison as defined in [RFC3986], Section 6.2.1.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-7.5.1
        // Loopback interface redirect URIs MAY use the http scheme (i.e., without TLS). This is acceptable for loopback interface redirect URIs as the HTTP request never leaves the device.
        // Clients should use loopback IP literals rather than the string localhost as described in Section 8.4.2.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-8.4.2
        // While redirect URIs using the name localhost (i.e., http://localhost:{port}/{path}) function similarly to loopback IP redirects, the use of localhost is NOT RECOMMENDED.
        // The authorization server MUST allow any port to be specified at the time of the request for loopback IP redirect URIs,
        // to accommodate clients that obtain an available ephemeral port from the operating system at the time of the request.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-8.4.3
        // To perform an authorization request with a private-use URI scheme redirect, the native app launches the browser with a standard authorization request,
        // but one where the redirect URI utilizes a private-use URI scheme it registered with the operating system.
        if (typedRedirectUri.IsLoopback)
        {
            foreach (var preRegisteredRedirectUri in preRegisteredRedirectUris)
            {
                // Ignore port for loopback
                if (ClientRedirectUriSyntaxValidator.IsValid(preRegisteredRedirectUri, out var clientRedirectUri)
                    && clientRedirectUri.IsLoopback
                    && clientRedirectUri.IsWellFormedOriginalString()
                    && clientRedirectUri.Scheme == typedRedirectUri.Scheme
                    && clientRedirectUri.Host == typedRedirectUri.Host
                    && clientRedirectUri.PathAndQuery == typedRedirectUri.PathAndQuery
                    && string.IsNullOrEmpty(clientRedirectUri.Fragment)
                    && string.IsNullOrEmpty(typedRedirectUri.Fragment))
                {
                    return Task.FromResult(new AuthorizeRequestParameterRedirectUriValidationResult(originalRedirectUri, originalRedirectUri));
                }
            }

            return Task.FromResult(AuthorizeRequestParameterRedirectUriValidationResult.InvalidRedirectUri);
        }

        // OAuth 2.1 non-loopback didn't allow http
        if (!typedRedirectUri.IsLoopback
            && typedRedirectUri.Scheme != Uri.UriSchemeHttp
            && preRegisteredRedirectUris.Contains(originalRedirectUri, StringComparer.Ordinal))
        {
            return Task.FromResult(new AuthorizeRequestParameterRedirectUriValidationResult(originalRedirectUri, originalRedirectUri));
        }

        return Task.FromResult(AuthorizeRequestParameterRedirectUriValidationResult.InvalidRedirectUri);
    }

    protected virtual AuthorizeRequestParameterRedirectUriValidationResult InferRedirectUri(bool isOpenIdRequest, IReadOnlySet<string> clientRedirectUris)
    {
        ArgumentNullException.ThrowIfNull(clientRedirectUris);
        // OAuth 2.1 flow
        if (!isOpenIdRequest)
        {
            if (clientRedirectUris.Count == 1)
            {
                return new(clientRedirectUris.Single(), null);
            }

            // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.3.2
            // If multiple redirect URIs have been registered, the client MUST include a redirect URI with the authorization request using the redirect_uri request parameter.
            return AuthorizeRequestParameterRedirectUriValidationResult.InvalidRedirectUri;
        }

        // OpenID Connect 1.0
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // redirect_uri - REQUIRED. This URI MUST exactly match one of the Redirection URI values for the Client pre-registered at the OpenID Provider,
        return AuthorizeRequestParameterRedirectUriValidationResult.RedirectUriIsMissing;
    }
}
