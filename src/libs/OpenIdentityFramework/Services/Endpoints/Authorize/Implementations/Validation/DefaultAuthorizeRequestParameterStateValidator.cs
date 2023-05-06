using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Request.Authorize;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation;
using OpenIdentityFramework.Services.Static.SyntaxValidation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation;

public class DefaultAuthorizeRequestParameterStateValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestParameterStateValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public DefaultAuthorizeRequestParameterStateValidator(OpenIdentityFrameworkOptions frameworkOptions)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        FrameworkOptions = frameworkOptions;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }

    public Task<AuthorizeRequestParameterStateValidationResult> ValidateStateParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "state" - OPTIONAL (OAuth 2.1) / RECOMMENDED (OpenID Connect 1.0).
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (!parameters.Raw.TryGetValue(RequestParameters.State, out var stateValues) || stateValues.Count == 0)
        {
            return Task.FromResult(AuthorizeRequestParameterStateValidationResult.Null);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (stateValues.Count != 1)
        {
            return Task.FromResult(AuthorizeRequestParameterStateValidationResult.MultipleStateValuesNotAllowed);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var state = stateValues.ToString();
        if (string.IsNullOrEmpty(state))
        {
            return Task.FromResult(AuthorizeRequestParameterStateValidationResult.Null);
        }

        // length check
        if (state.Length > FrameworkOptions.InputLengthRestrictions.State)
        {
            return Task.FromResult(AuthorizeRequestParameterStateValidationResult.StateIsTooLong);
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.1
        // "client_id" syntax validation
        if (!StateSyntaxValidator.IsValid(state))
        {
            return Task.FromResult(AuthorizeRequestParameterStateValidationResult.InvalidStateSyntax);
        }

        var stateResult = new AuthorizeRequestParameterStateValidationResult(state);
        return Task.FromResult(stateResult);
    }
}
