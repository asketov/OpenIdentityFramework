using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.AuthorizationCode.Parameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.AuthorizationCode.Parameters;
using OpenIdentityFramework.Services.Static.SyntaxValidation;
using static System.ArgumentNullException;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.Flows.AuthorizationCode.Parameters;

public class DefaultTokenRequestAuthorizationCodeParameterCodeValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode>
    : ITokenRequestAuthorizationCodeParameterCodeValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
{
    public DefaultTokenRequestAuthorizationCodeParameterCodeValidator(
        OpenIdentityFrameworkOptions frameworkOptions,
        IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode> authorizationCodes)
    {
        ThrowIfNull(frameworkOptions);
        ThrowIfNull(authorizationCodes);
        FrameworkOptions = frameworkOptions;
        AuthorizationCodes = authorizationCodes;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    protected IAuthorizationCodeService<TRequestContext, TClient, TClientSecret, TAuthorizationCode> AuthorizationCodes { get; }

    public virtual async Task<TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode>> ValidateCodeAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        CancellationToken cancellationToken)
    {
        ThrowIfNull(form);
        ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.1
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.3
        // code - REQUIRED. The authorization code received from the authorization server.
        if (!form.TryGetValue(TokenRequestParameters.Code, out var codeValues))
        {
            return TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode>.AuthorizationCodeIsMissing;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (codeValues.Count != 1)
        {
            return TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode>.MultipleAuthorizationCodeValuesNotAllowed;
        }

        var code = codeValues.ToString();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (string.IsNullOrEmpty(code))
        {
            return TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode>.AuthorizationCodeIsMissing;
        }

        if (code.Length > FrameworkOptions.InputLengthRestrictions.Code)
        {
            return TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode>.AuthorizationCodeIsTooLong;
        }

        if (!CodeSyntaxValidator.IsValid(code))
        {
            return TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode>.InvalidAuthorizationCodeSyntax;
        }

        var authorizationCode = await AuthorizationCodes.FindAsync(requestContext, code, cancellationToken);
        if (authorizationCode == null)
        {
            return TokenRequestAuthorizationCodeParameterCodeValidationResult<TAuthorizationCode>.UnknownCode;
        }

        return new(code, authorizationCode);
    }
}
