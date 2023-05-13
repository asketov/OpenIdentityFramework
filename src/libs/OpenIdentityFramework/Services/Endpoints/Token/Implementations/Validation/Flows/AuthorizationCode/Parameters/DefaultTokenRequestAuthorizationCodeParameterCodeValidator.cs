using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Authentication;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.AuthorizationCode.Parameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.AuthorizationCode.Parameters;
using OpenIdentityFramework.Services.Static.SyntaxValidation;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.Flows.AuthorizationCode.Parameters;

public class DefaultTokenRequestAuthorizationCodeParameterCodeValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    : ITokenRequestAuthorizationCodeParameterCodeValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode<TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>
    where TResourceOwnerEssentialClaims : AbstractResourceOwnerEssentialClaims<TResourceOwnerIdentifiers>
    where TResourceOwnerIdentifiers : AbstractResourceOwnerIdentifiers
{
    public DefaultTokenRequestAuthorizationCodeParameterCodeValidator(
        OpenIdentityFrameworkOptions frameworkOptions,
        IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> authorizationCodes)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(authorizationCodes);
        FrameworkOptions = frameworkOptions;
        AuthorizationCodes = authorizationCodes;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    protected IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers> AuthorizationCodes { get; }


    public virtual async Task<TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>> ValidateCodeAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.1
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.3
        // code - REQUIRED. The authorization code received from the authorization server.
        if (!form.TryGetValue(TokenRequestParameters.Code, out var codeValues))
        {
            return TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>.AuthorizationCodeIsMissing;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (codeValues.Count != 1)
        {
            return TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>.MultipleAuthorizationCodeValuesNotAllowed;
        }

        var code = codeValues.ToString();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (string.IsNullOrEmpty(code))
        {
            return TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>.AuthorizationCodeIsMissing;
        }

        if (code.Length > FrameworkOptions.InputLengthRestrictions.Code)
        {
            return TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>.AuthorizationCodeIsTooLong;
        }

        if (!CodeSyntaxValidator.IsValid(code))
        {
            return TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>.InvalidAuthorizationCodeSyntax;
        }

        var authorizationCode = await AuthorizationCodes.FindAsync(requestContext, code, cancellationToken);
        if (authorizationCode == null)
        {
            return TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode, TResourceOwnerEssentialClaims, TResourceOwnerIdentifiers>.UnknownCode;
        }

        return new(code, authorizationCode);
    }
}
