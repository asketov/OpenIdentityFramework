using System;
using System.Collections.Generic;
using System.Globalization;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Models.Configuration;

/// <summary>
///     OAuth 2.1 / OpenID Connect 1.0 client model.
/// </summary>
/// <typeparam name="TClientSecret">Implementation of <see cref="AbstractClientSecret" />.</typeparam>
public abstract class AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
{
    //   ___    _         _   _     ____    _
    //  / _ \  / \  _   _| |_| |__ |___ \  / |
    // | | | |/ _ \| | | | __| '_ \  __) | | |
    // | |_| / ___ \ |_| | |_| | | |/ __/ _| |
    //  \___/_/   \_\__,_|\__|_| |_|_____(_)_|
    //

    /// <summary>
    ///     Returns <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.2">the client identifier ("client_id")</a>, which is a unique string that represents the registration information provided by the client. The value of the client identifier corresponds
    ///     to the "client_id" value described in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">section 3.2.1 of the OAuth 2.0 Dynamic Client Registration Protocol specification</a>. It is recommended that the client identifier should not be currently valid for any
    ///     other registered client.
    /// </summary>
    /// <returns>A <see cref="string" /> that contains a non-null and non-empty value.</returns>
    public abstract string GetClientId();

    /// <summary>
    ///     Returns time at which the client identifier was issued. Corresponds to the value of "client_id_issued_at" in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">section 3.2.1 of the OAuth 2.0 Dynamic Client Registration Protocol specification</a>. The time is
    ///     represented as the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time of issuance.
    /// </summary>
    /// <returns>An <see cref="long" /> value that is greater than 0.</returns>
    public abstract long GetClientIdIssuedAt();

    /// <summary>
    ///     Returns a set of client secrets that includes their values ("client_secret"), issue dates, expiration dates ("client_secret_expires_at"), and status information.
    /// </summary>
    /// <returns>A set that contains 0 or more values. Cannot be <see langword="null" />.</returns>
    public abstract IReadOnlySet<TClientSecret> GetSecrets();

    /// <summary>
    ///     Returns redirection URI strings for use in redirect-based flows such as the authorization code.<br />
    ///     <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.3.1">As required by section 2.3.1 of OAuth 2.1</a>, clients using flows with redirection must register their redirection URI values.<br />
    ///     The value should correspond to the "redirect_uris" value as described in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a>
    /// </summary>
    /// <returns>A set that contains 0 or more values. Cannot be <see langword="null" />.</returns>
    public abstract IReadOnlySet<Uri> GetRedirectUris();

    /// <summary>
    ///     Returns a string indicator of the requested authentication method for the token endpoint. The default value is "client_secret_basic"<br />
    ///     The value should correspond to the "token_endpoint_auth_method" value as described in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a><br />
    ///     Allowed values are:
    ///     <list type="bullet">
    ///         <item>
    ///             <term>"none"</term>
    ///             <description>
    ///                 The client is a public client as defined in <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.1">OAuth 2.1, section 2.1,</a> and does not have a client secret, because it does not authenticate itself at the token endpoint.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>"client_secret_post"</term>
    ///             <description>
    ///                 The client uses the HTTP POST parameters as defined in <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.4.1">OAuth 2.1, section 2.4.1.</a>
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>"client_secret_basic"</term>
    ///             <description>
    ///                 The client uses HTTP Basic as defined in <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-2.4.1">OAuth 2.1, section 2.4.1.</a>
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>"client_secret_jwt" (currently not supported)</term>
    ///             <description>
    ///                 The client authenticates using a JWT created with HMAC SHA algorithm. This is in accordance with <a href="https://www.rfc-editor.org/rfc/rfc7523.html">JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants</a> and
    ///                 <a href="https://www.rfc-editor.org/rfc/rfc7521.html">Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants.</a>
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>"private_key_jwt" (currently not supported)</term>
    ///             <description>
    ///                 Clients that have registered a public key sign a JWT using that key. The client authenticates in accordance with <a href="https://www.rfc-editor.org/rfc/rfc7523.html">JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants</a>
    ///                 and <a href="https://www.rfc-editor.org/rfc/rfc7521.html">Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants.</a>
    ///             </description>
    ///         </item>
    ///     </list>
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetTokenEndpointAuthMethod();

    /// <summary>
    ///     Returns OAuth 2.1 grant type strings that the client can use at the token endpoint.<br />
    ///     The value should correspond to the "grant_types" value as described in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a><br />
    ///     Allowed values are:
    ///     <list type="bullet">
    ///         <item>
    ///             <term>"authorization_code"</term>
    ///             <description>
    ///                 The authorization code grant type defined in <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.3">OAuth 2.1, Section 4.1.3</a>.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>"client_credentials"</term>
    ///             <description>
    ///                 The client credentials grant type defined in <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.2.1">OAuth 2.1, Section 4.2.1</a>.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>"refresh_token"</term>
    ///             <description>
    ///                 The refresh token grant type defined in <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.3.1">OAuth 2.1, Section 4.3.1</a>.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </summary>
    /// <returns>A set that contains 0 or more values. Cannot be <see langword="null" />.</returns>
    public abstract IReadOnlySet<string> GetGrantTypes();

    /// <summary>
    ///     Returns OAuth 2.1 response type strings that the client can use at the authorization endpoint.<br />
    ///     The value should correspond to the "response_types" value as described in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a><br />
    ///     Allowed values are:
    ///     <list type="bullet">
    ///         <item>
    ///             <term>"code"</term>
    ///             <description>
    ///                 The authorization code response type defined in <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1">OAuth 2.1, Section 4.1.1</a>.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </summary>
    /// <returns>A set that contains 0 or more values. Cannot be <see langword="null" />.</returns>
    public abstract IReadOnlySet<string> GetResponseTypes();

    /// <summary>
    ///     Returns human-readable string name of the client to be presented to the end-user during authorization. If omitted, the authorization server may display the raw "client_id" value to the end-user instead. The value may be internationalized. The value should correspond to the
    ///     "client_name" value as described in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a>
    /// </summary>
    /// <param name="cultureInfo">The culture for which a localized value is required.</param>
    /// <returns>A <see cref="string" /> that contains non-empty value or <see langword="null" />.</returns>
    public abstract string? GetClientName(CultureInfo cultureInfo);

    /// <summary>
    ///     Returns URL string of a web page providing information about the client. If present, the server should display this URL to the end-user in a clickable fashion. The value must point to a valid web page. The value may be internationalized. The value should correspond to the
    ///     "client_uri" value as described in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a>
    /// </summary>
    /// <param name="cultureInfo">The culture for which a localized value is required.</param>
    /// <returns><see cref="Uri" /> or <see langword="null" />.</returns>
    public abstract Uri? GetClientUri(CultureInfo cultureInfo);

    /// <summary>
    ///     Returns URL string that references a logo for the client. If present, the server should display this image to the end-user during approval. The value must point to a valid image file. The value may be internationalized. The value should correspond to the "logo_uri" value as
    ///     described in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a>
    /// </summary>
    /// <param name="cultureInfo">The culture for which a localized value is required.</param>
    /// <returns><see cref="Uri" /> or <see langword="null" />.</returns>
    public abstract Uri? GetLogoUri(CultureInfo cultureInfo);

    /// <summary>
    ///     Returns a set of scope values (<a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2.2.1">as described in section 3.2.2.1 of OAuth 2.1</a>) that the client can use when requesting access tokens. The value should correspond to the "scope" value as
    ///     described in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a>
    /// </summary>
    /// <returns>A set that contains 0 or more values. Cannot be <see langword="null" />.</returns>
    public abstract IReadOnlySet<string> GetScopes();

    /// <summary>
    ///     Returns a set of strings representing ways to contact people responsible for this client, typically email addresses. The authorization server may make these contact addresses available to end-users for support requests for the client. The value should correspond to the
    ///     "contacts" value as described in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a>
    /// </summary>
    /// <returns>A set that contains 0 or more values. Cannot be <see langword="null" />.</returns>
    public abstract IReadOnlySet<string> GetContacts();

    /// <summary>
    ///     Returns URL string that points to a human-readable terms of service document for the client that describes a contractual relationship between the end-user and the client that the end-user accepts when authorizing the client. The authorization server should display this URL
    ///     to the end-user if it is provided. The value must point to a valid web page. The value may be internationalized. The value should correspond to the "tos_uri" value as described in
    ///     <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a>
    /// </summary>
    /// <param name="cultureInfo">The culture for which a localized value is required.</param>
    /// <returns><see cref="Uri" /> or <see langword="null" />.</returns>
    public abstract Uri? GetTosUri(CultureInfo cultureInfo);

    /// <summary>
    ///     Returns URL string that points to a human-readable privacy policy document that describes how the deployment organization collects, uses, retains, and discloses personal data. The authorization server should display this URL to the end-user if it is provided. The value must
    ///     point to a valid web page. The value may be internationalized. The value should correspond to the "policy_uri" value as described in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a>
    /// </summary>
    /// <param name="cultureInfo">The culture for which a localized value is required.</param>
    /// <returns><see cref="Uri" /> or <see langword="null" />.</returns>
    public abstract Uri? GetPolicyUri(CultureInfo cultureInfo);

    /// <summary>
    ///     Returns URL string referencing the client's <a href="https://www.rfc-editor.org/rfc/rfc7517.html">JSON Web Key (JWK) Set document</a>, which contains the client's public keys. The value must point to a valid
    ///     <a href="https://www.rfc-editor.org/rfc/rfc7517.html">JSON Web Key (JWK) Set document</a>. These keys can be used by higher-level protocols that use signing or encryption. For instance, these keys might be used by some applications to validate signed requests made to the
    ///     token endpoint when <a href="https://www.rfc-editor.org/rfc/rfc7523.html">using JWTs for client authentication</a>. Use of this parameter is preferred over the "jwks" parameter, as it allows for easier key rotation. The value should correspond to the "jwks_uri" value, as
    ///     described in <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a> Currently not supported.
    /// </summary>
    /// <returns><see cref="Uri" /> or <see langword="null" />.</returns>
    public abstract Uri? GetJwksUri();

    /// <summary>
    ///     Returns the client's <a href="https://www.rfc-editor.org/rfc/rfc7517.html">JSON Web Key Set document</a> value, which contains the client's public keys. These keys can be used by higher-level protocols that require signing or encryption. This parameter is intended to be used
    ///     by clients that cannot use the "jwks_uri" parameter, such as native clients that cannot host public URLs. The value should correspond to the "jwks" value, as described in
    ///     <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a> Currently not supported.
    /// </summary>
    /// <returns><a href="https://www.rfc-editor.org/rfc/rfc7517.html">JSON Web Key Set document</a> or <see langword="null" />.</returns>
    public abstract JsonWebKeySet? GetJwks();

    /// <summary>
    ///     Returns a unique identifier string (e.g., a Universally Unique Identifier (UUID)) that is assigned by the client developer or software publisher and is used by registration endpoints to identify the client software for dynamic registration. Unlike the "client_id" parameter,
    ///     which is issued by the authorization server and should vary between instances, the "software_id" parameter should remain the same for all instances of the client software. The "software_id" parameter should remain the same across multiple updates or versions of the same
    ///     software. The value is not intended to be human-readable and is usually opaque to the client and authorization server. The value should correspond to the "software_id" value, as described in
    ///     <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a>
    /// </summary>
    /// <returns>A <see cref="string" /> that contains non-empty value or <see langword="null" />.</returns>
    public abstract string? GetSoftwareId();

    /// <summary>
    ///     Returns a version identifier string for the client software identified by "software_id". The value of the "software_version" should change on any update to the client software identified by the same "software_id". It is not intended to be human readable and is usually opaque
    ///     to the client and authorization server. The definition of what constitutes an update to the client software that would trigger a change to this value is specific to the software itself. The value should correspond to the "software_version" value, as described in
    ///     <a href="https://www.rfc-editor.org/rfc/rfc7591#section-2">section 2 of the OAuth 2.0 Dynamic Client Registration Protocol specification.</a>
    /// </summary>
    /// <returns>A <see cref="string" /> that contains non-empty value or <see langword="null" />.</returns>
    public abstract string? GetSoftwareVersion();

    //   ___                   ___ ____     ____                            _     _   ___
    //  / _ \ _ __   ___ _ __ |_ _|  _ \   / ___|___  _ __  _ __   ___  ___| |_  / | / _ \
    // | | | | '_ \ / _ \ '_ \ | || | | | | |   / _ \| '_ \| '_ \ / _ \/ __| __| | || | | |
    // | |_| | |_) |  __/ | | || || |_| | | |__| (_) | | | | | | |  __/ (__| |_  | || |_| |
    //  \___/| .__/ \___|_| |_|___|____/   \____\___/|_| |_|_| |_|\___|\___|\__| |_(_)___/
    //       |_|

    /// <summary>
    ///     Returns kind of the application. The default value is "web". The value should correspond to the "application_type" value as described in
    ///     <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a><br />
    ///     The defined values are:
    ///     <list type="bullet">
    ///         <item>
    ///             <term>"web"</term>
    ///             <description>
    ///                 Web clients are designed for web applications.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>"native"</term>
    ///             <description>
    ///                 Native clients must only register "redirect_uris" using custom URI schemes or URLs using the "http" scheme with "localhost" as the hostname. The authorization server may place additional constraints on native clients, including rejecting redirection URI values
    ///                 using the "http" scheme other than the "localhost" case. The authorization server must verify that all registered "redirect_uris" conform to these constraints.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetApplicationType();

    /// <summary>
    ///     Returns the <a href="https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.8.1">"sector_identifier_uri"</a>, which provides a way for a group of websites under common administrative control to have consistent pairwise sub-values independent of their individual
    ///     domain names. The value should correspond to the "sector_identifier_uri" value as described in <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently
    ///     not supported.
    /// </summary>
    /// <returns><see cref="Uri" /> or <see langword="null" />.</returns>
    public abstract Uri? GetSectorIdentifierUri();

    /// <summary>
    ///     Returns a subject identifier types. The value should correspond to the "subject_type" value as described in
    ///     <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a>
    ///     Allowed values are:
    ///     <list type="bullet">
    ///         <item>
    ///             <term>"public"</term>
    ///             <description>
    ///                 This provides the same "sub" (subject) value to all clients. It is the default.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>"pairwise" (currently not supported)</term>
    ///             <description>
    ///                 This provides a different sub value to each client, so as not to enable clients to correlate the end-user's activities without permission.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetSubjectType();

    /// <summary>
    ///     Returns the <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">JWS "alg" algorithm</a> utilized for signing the "id_token" issued to this client. The default algorithm is "RS256", if omitted. The value "none" must not be used as the "id_token" alg value unless
    ///     the client uses only response types that return no "id_token" from the authorization endpoint (such as when only using the authorization code flow). The value should correspond to the "id_token_signed_response_alg" value as described in
    ///     <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently not supported.
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetIdTokenSignedResponseAlg();

    /// <summary>
    ///     Returns the <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1">JWE "alg" algorithm</a> used for encrypting the "id_token" issued to this client. If requested, the response will be signed and then encrypted, resulting in a nested JWT, as defined in the
    ///     <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-11.2">JWT specification</a>. The default, if omitted, is that no encryption is performed. The value should correspond to the "id_token_encrypted_response_alg" value as described in
    ///     <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently not supported.
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetIdTokenEncryptedResponseAlg();

    /// <summary>
    ///     Returns the <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1">JWE "enc" algorithm</a> used for encrypting the "id_token" issued to this client. If "id_token_encrypted_response_alg" is specified, the default value for this parameter is "A128CBC-HS256". The
    ///     value should correspond to the "id_token_encrypted_response_enc" value as described in <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently not
    ///     supported.
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetIdTokenEncryptedResponseEnc();

    /// <summary>
    ///     Returns the <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">JWS "alg" algorithm</a> used for signing userinfo responses. If specified, the response will be <a href="https://www.rfc-editor.org/rfc/rfc7519.html">serialized as a JWT</a> and signed
    ///     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">using JWS</a>. The default algorithm, if omitted, is for the userinfo response to return the claims as a UTF-8 encoded JSON object using the 'application/json' content-type. The value should correspond to the
    ///     "userinfo_signed_response_alg" value as described in <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently not supported.
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetUserinfoSignedResponseAlg();

    /// <summary>
    ///     Returns the <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1">JWE "alg" algorithm</a> used for encrypting userinfo responses. If requested, the response will be signed and then encrypted, resulting in a nested JWT, as defined in the
    ///     <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-11.2">JWT specification</a>. The default, if omitted, is that no encryption is performed. The value should correspond to the "userinfo_encrypted_response_alg" value as described in
    ///     <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently not supported.
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetUserinfoEncryptedResponseAlg();

    /// <summary>
    ///     Returns the <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1">JWE "enc" algorithm</a> used for encrypting userinfo responses. If "userinfo_encrypted_response_alg" is specified, the default value for this parameter is "A128CBC-HS256". The value should
    ///     correspond to the "userinfo_encrypted_response_enc" value as described in <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently not supported.
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetUserinfoEncryptedResponseEnc();

    /// <summary>
    ///     Returns <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">JWS "alg" algorithm</a> that must be used for signing request objects sent to the OpenID Provider. All request objects from this client must be rejected, if not signed with this algorithm. This
    ///     algorithm must be used both when the request object is passed by value (using the "request" parameter) and when it is passed by reference (using the "request_uri" parameter). The value "none" may be used. The default, if omitted, is that any algorithm supported by the OpenID
    ///     Provider and the client may be used. The value should correspond to the "request_object_signing_alg" value as described in
    ///     <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently not supported.
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetRequestObjectSigningAlg();

    /// <summary>
    ///     Returns <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1">JWE "alg" algorithm</a> the client is declaring that it may use for encrypting request objects sent to the OpenID Provider. This parameter should be included when symmetric encryption will be used. The
    ///     client may still use other supported encryption algorithms or send unencrypted request objects, even when this parameter is present. If both signing and encryption are requested, the request object will be signed and then encrypted, resulting in a nested JWT, as defined in
    ///     the <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-11.2">JWT specification</a>. The default, if omitted, is that no encryption is performed. The value should correspond to the "request_object_encryption_alg" value as described in
    ///     <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently not supported.
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetRequestObjectEncryptionAlg();

    /// <summary>
    ///     Returns <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1">JWE "enc" algorithm</a>  the client is declaring that it may use for encrypting request objects sent to the OpenID Provider. If "request_object_encryption_alg" is specified, the default for this value
    ///     is "A128CBC-HS256". The value should correspond to the "request_object_encryption_enc" value as described in
    ///     <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently not supported.
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetRequestObjectEncryptionEnc();

    /// <summary>
    ///     Returns <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">JWS "alg" algorithm</a> that must be used for signing the JWT used to authenticate the client at the token endpoint for the "private_key_jwt" and "client_secret_jwt" authentication methods. All token
    ///     requests using these authentication methods from this client must be rejected, if the JWT is not signed with this algorithm. The value "none" must not be used. The value should correspond to the "token_endpoint_auth_signing_alg" value as described in
    ///     <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently not supported.
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetTokenEndpointAuthSigningAlg();

    /// <summary>
    ///     Returns default maximum authentication age. Specifies that the end-user must be actively authenticated if the end-user was authenticated longer ago than the specified number of seconds. The "max_age" request parameter overrides this default value. If omitted, no default
    ///     maximum authentication age is specified. If a value is specified, it should be equal to or greater than 0. The value should correspond to the "default_max_age" value as described in
    ///     <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a>
    /// </summary>
    /// <returns>An <see cref="long" /> value that is equal to or greater than 0, or <see langword="null" />.</returns>
    public abstract long? GetDefaultMaxAge();

    /// <summary>
    ///     Returns the value that specifies whether the "auth_time" claim in the "id_token" is required. If the value is <see langword="true" />, the claim is required. If the value is <see langword="false" />, the 'auth_time' claim can still be dynamically requested as an individual
    ///     claim for the "id_token" using the claims request parameter, as described in <a href="https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.5.1">section 5.5.1 of the OpenID Connect Core 1.0 specification.</a> If this parameter is omitted, the default value is
    ///     <see langword="false" />. The value should correspond to the "require_auth_time" value as described in <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a>
    /// </summary>
    /// <returns>A <see cref="bool" /> value or <see langword="null" />.</returns>
    public abstract bool? GetRequireAuthTime();

    /// <summary>
    ///     Returns default requested authentication context class reference (acr) values. This is a collection of strings that specifies the default "acr" values requested by the relying party (OAuth client application) for the OpenID Provider (OAuth Authorization Server) to use in
    ///     processing requests. The values should be listed in order of preference. The "acr" Claim Value in the "id_token" issued will reflect the authentication context class satisfied by the authentication process. The value should correspond to the "default_acr_values" value as
    ///     described in <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a>
    /// </summary>
    /// <returns>A set that contains 0 or more values. Cannot be <see langword="null" />.</returns>
    public abstract IReadOnlySet<string> GetDefaultAcrValues();

    /// <summary>
    ///     Returns the URI, using the https scheme, that a third party can use to initiate a login by the relying party (OAuth client application), as specified in
    ///     <a href="https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.4">section 4 of the OpenID Connect Core 1.0 specification.</a> The values should be listed in order of preference. The "acr" Claim Value in the "id_token" issued will reflect the authentication
    ///     context class satisfied by the authentication process. The value should correspond to the "initiate_login_uri" value as described in
    ///     <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently not supported.
    /// </summary>
    /// <returns><see cref="Uri" /> or <see langword="null" />.</returns>
    public abstract Uri? GetInitiateLoginUri();

    /// <summary>
    ///     Returns a set of "request_uri" values that are pre-registered by the relying party (OAuth client application) for use with the OpenID Provider (OAuth Authorization Server). The value should correspond to the "request_uris" value as described in
    ///     <a href="https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2">section 2 of the OpenID Connect Dynamic Client Registration 1.0 specification.</a> Currently not supported.
    /// </summary>
    /// <returns>A set that contains 0 or more values. Cannot be <see langword="null" />.</returns>
    public abstract IReadOnlySet<Uri> GetRequestUris();

    //   ____
    //  / ___|___  _ __ ___  _ __ ___   ___  _ __
    // | |   / _ \| '_ ` _ \| '_ ` _ \ / _ \| '_ \
    // | |__| (_) | | | | | | | | | | | (_) | | | |
    //  \____\___/|_| |_| |_|_| |_| |_|\___/|_| |_|
    //

    /// <summary>
    ///     Returns the set of pre-configured "code_challenge_method" values that this client can use in requests to the authorization endpoint. Allowed values
    ///     <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1">defined in the OAuth 2.1 specification</a> are "S256" and "plain".
    /// </summary>
    /// <returns>A set that contains 0 or more values. Cannot be <see langword="null" />.</returns>
    public abstract IReadOnlySet<string> GetAllowedCodeChallengeMethods();

    /// <summary>
    ///     Returns <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">JWS "alg" algorithm</a> that should be used to sign the access_token. The value "none" must not be used.
    /// </summary>
    /// <returns>A <see cref="string" /> corresponds to one of the values defined in the specifications or <see langword="null" />.</returns>
    public abstract string? GetAccessTokenSignedResponseAlg();

    /// <summary>
    ///     Returns a flag indicating whether the client can skip the consent screen. If the value is <see langword="true" />, then requests from this client will not display the consent screen to the user and will be automatically approved.
    /// </summary>
    /// <returns>A <see cref="bool" /> value.</returns>
    public abstract bool CanSkipConsentScreen();

    /// <summary>
    ///     Returns a flag indicating that for authorization requests from this client, the user-selected scopes on the consent screen can be remembered.
    /// </summary>
    /// <returns>A <see cref="bool" /> value.</returns>
    public abstract bool CanRememberConsent();

    /// <summary>
    ///     Returns the lifetime of the saved consent that the user gave to the client in seconds. The return value is strictly greater than 0 or <see langword="null" />. This is only applicable if <see cref="CanRememberConsent" /> returns <see langword="true" />. If the return value is
    ///     <see langword="null" />, the lifetime of the saved consent will be infinite.
    /// </summary>
    /// <returns>An <see cref="long" /> value that is strictly greater than 0 or <see langword="null" />.</returns>
    public abstract long? GetConsentLifetime();

    /// <summary>
    ///     Returns the lifetime of the authorization code in seconds. This is only applicable if the authorization code grant is being used.
    /// </summary>
    /// <returns>An <see cref="long" /> value. Lifetime in seconds.</returns>
    public abstract long GetAuthorizationCodeLifetime();

    /// <summary>
    ///     Returns a flag indicating whether to include user claims in the "id_token" returned from the authorization endpoint. This is only applicable when using the OpenID Connect 1.0 protocol.
    /// </summary>
    /// <returns>A <see cref="bool" /> value.</returns>
    public abstract bool ShouldIncludeUserClaimsInIdTokenAuthorizeResponse();

    /// <summary>
    ///     Returns a flag indicating whether to include user claims in the "id_token" returned from the token endpoint. This is only applicable when using the OpenID Connect 1.0 protocol.
    /// </summary>
    /// <returns>A <see cref="bool" /> value.</returns>
    public abstract bool ShouldIncludeUserClaimsInIdTokenTokenResponse();

    /// <summary>
    ///     Returns the "id_token" lifetime in seconds. The returned value will be used at the time of generating the "id_token".
    /// </summary>
    /// <returns>An <see cref="long" /> value. Lifetime in seconds.</returns>
    public abstract long GetIdTokenLifetime();

    /// <summary>
    ///     Returns the "access_token" format.
    /// </summary>
    /// <returns>A <see cref="string" /> that cannot be <see langword="null" />.</returns>
    public abstract string GetAccessTokenStrategy();

    /// <summary>
    ///     Returns a flag indicating whether to include the <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7">JWT ID ("jti") claim</a> in the "access_token".
    /// </summary>
    /// <returns>A <see cref="bool" /> value.</returns>
    public abstract bool ShouldIncludeJwtIdIntoAccessToken();

    /// <summary>
    ///     Returns the lifetime of the "access_token" in seconds. The returned value will be used at the time of generating the "access_token".
    /// </summary>
    /// <returns>An <see cref="long" /> value. Lifetime in seconds.</returns>
    public abstract long GetAccessTokenLifetime();

    /// <summary>
    ///     Returns the absolute lifetime of the "refresh_token" in seconds. The returned value will be used at the time of generating the "refresh_token" if the strategy with an absolute lifetime or a hybrid lifetime strategy (sliding expiration limited by the absolute lifetime) is
    ///     selected.
    /// </summary>
    /// <returns>An <see cref="long" /> value. Lifetime in seconds.</returns>
    public abstract long GetRefreshTokenAbsoluteLifetime();

    /// <summary>
    ///     Returns the sliding lifetime of the "refresh_token" in seconds. The returned value will be used at the time of generating the "refresh_token" if the sliding lifetime strategy or a hybrid lifetime strategy (sliding expiration limited by the absolute lifetime) is selected.
    /// </summary>
    /// <returns>An <see cref="long" /> value. Lifetime in seconds.</returns>
    public abstract long GetRefreshTokenSlidingLifetime();

    /// <summary>
    ///     Returns the strategy used to determine the expiration of the "refresh_token".
    /// </summary>
    /// <returns>A <see cref="string" /> that cannot be <see langword="null" />.</returns>
    public abstract string GetRefreshTokenExpirationStrategy();

    /// <summary>
    ///     Returns a flag indicating whether the client is confidential. In the current implementation, confidential clients are those whose configuration specifies a mandatory authentication method when making requests to the token endpoint.
    /// </summary>
    /// <returns>A <see cref="bool" /> value.</returns>
    public virtual bool IsConfidential()
    {
        var authenticationMethod = GetTokenEndpointAuthMethod();
        if (authenticationMethod == DefaultClientAuthenticationMethods.None)
        {
            return false;
        }

        return true;
    }
}
