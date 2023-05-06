using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants.Request.Authorize;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.Validation;
using OpenIdentityFramework.Services.Endpoints.Authorize.Validation;
using OpenIdentityFramework.Services.Static.SyntaxValidation;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations.Validation;

public class DefaultAuthorizeRequestParameterClientIdValidator<TRequestContext, TClient, TClientSecret>
    : IAuthorizeRequestParameterClientIdValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public DefaultAuthorizeRequestParameterClientIdValidator(
        OpenIdentityFrameworkOptions frameworkOptions,
        IClientService<TRequestContext, TClient, TClientSecret> clients)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(clients);
        FrameworkOptions = frameworkOptions;
        Clients = clients;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IClientService<TRequestContext, TClient, TClientSecret> Clients { get; }

    public virtual async Task<AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret>> ValidateClientIdParameterAsync(
        TRequestContext requestContext,
        AuthorizeRequestParametersToValidate parameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-4.1.1
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
        // "client_id" - REQUIRED.
        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        if (!parameters.Raw.TryGetValue(RequestParameters.ClientId, out var clientIdValues) || clientIdValues.Count == 0)
        {
            return AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret>.ClientIdIsMissing;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Request and response parameters defined by this specification MUST NOT be included more than once.
        if (clientIdValues.Count != 1)
        {
            return AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret>.MultipleClientIdValuesNotAllowed;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
        // Parameters sent without a value MUST be treated as if they were omitted from the request.
        var clientId = clientIdValues.ToString();
        if (string.IsNullOrEmpty(clientId))
        {
            return AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret>.ClientIdIsMissing;
        }

        // length check
        if (clientId.Length > FrameworkOptions.InputLengthRestrictions.ClientId)
        {
            return AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret>.ClientIdIsTooLong;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.1
        // "client_id" syntax validation
        if (!ClientIdSyntaxValidator.IsValid(clientId))
        {
            return AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret>.InvalidClientIdSyntax;
        }

        // client not found
        var client = await Clients.FindAsync(requestContext, clientId, cancellationToken);
        if (client == null)
        {
            return AuthorizeRequestParameterClientIdValidationResult<TClient, TClientSecret>.UnknownOrDisabledClient;
        }

        return new(client);
    }
}
