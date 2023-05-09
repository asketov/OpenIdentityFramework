using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Endpoints.Token.Models.Validation.Flows.AuthorizationCode;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.CommonParameters;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.AuthorizationCode;
using OpenIdentityFramework.Services.Endpoints.Token.Validation.Flows.AuthorizationCode.Parameters;

namespace OpenIdentityFramework.Services.Endpoints.Token.Implementations.Validation.Flows.AuthorizationCode;

public class DefaultTokenRequestAuthorizationCodeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode, TGrantedConsent>
    : ITokenRequestAuthorizationCodeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TAuthorizationCode : AbstractAuthorizationCode
    where TGrantedConsent : AbstractGrantedConsent
{
    protected static readonly TokenRequestAuthorizationCodeValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> UnauthorizedClient =
        new(new ProtocolError(TokenErrors.UnauthorizedClient, "The authenticated client is not authorized to use this authorization grant type"));

    protected static readonly TokenRequestAuthorizationCodeValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> InvalidGrant =
        new(new ProtocolError(TokenErrors.InvalidGrant,
            "The provided authorization grant (e.g., authorization code) is invalid, expired, revoked, does not match the redirect URI used in the authorization request, or was issued to another client"));

    protected static readonly TokenRequestAuthorizationCodeValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode> DisabledUser =
        new(new ProtocolError(TokenErrors.InvalidGrant, "User account for provided authorization code has been disabled"));

    public DefaultTokenRequestAuthorizationCodeValidator(
        ITokenRequestAuthorizationCodeParameterCodeValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode> codeValidator,
        ITokenRequestAuthorizationCodeParameterCodeVerifierValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode> codeVerifierValidator,
        ITokenRequestAuthorizationCodeParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode> redirectUriValidator,
        ITokenRequestCommonParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> scopeValidator,
        IResourceOwnerProfileService<TRequestContext, TScope, TResource, TResourceSecret> resourceOwnerProfile,
        IGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent> grantedConsents)
    {
        ArgumentNullException.ThrowIfNull(codeValidator);
        ArgumentNullException.ThrowIfNull(codeVerifierValidator);
        ArgumentNullException.ThrowIfNull(redirectUriValidator);
        ArgumentNullException.ThrowIfNull(scopeValidator);
        ArgumentNullException.ThrowIfNull(resourceOwnerProfile);
        ArgumentNullException.ThrowIfNull(grantedConsents);
        CodeValidator = codeValidator;
        CodeVerifierValidator = codeVerifierValidator;
        RedirectUriValidator = redirectUriValidator;
        ScopeValidator = scopeValidator;
        ResourceOwnerProfile = resourceOwnerProfile;
        GrantedConsents = grantedConsents;
    }

    protected ITokenRequestAuthorizationCodeParameterCodeValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode> CodeValidator { get; }
    protected ITokenRequestAuthorizationCodeParameterCodeVerifierValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode> CodeVerifierValidator { get; }
    protected ITokenRequestAuthorizationCodeParameterRedirectUriValidator<TRequestContext, TClient, TClientSecret, TAuthorizationCode> RedirectUriValidator { get; }
    protected ITokenRequestCommonParameterScopeValidator<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret> ScopeValidator { get; }
    protected IResourceOwnerProfileService<TRequestContext, TScope, TResource, TResourceSecret> ResourceOwnerProfile { get; }
    protected IGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent> GrantedConsents { get; }

    public virtual async Task<TokenRequestAuthorizationCodeValidationResult<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>> ValidateAsync(
        TRequestContext requestContext,
        IFormCollection form,
        TClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        var clientAuthorizationFlows = client.GetAllowedAuthorizationFlows();
        if (!clientAuthorizationFlows.Contains(DefaultAuthorizationFlows.AuthorizationCode) && !clientAuthorizationFlows.Contains(DefaultAuthorizationFlows.Hybrid))
        {
            return UnauthorizedClient;
        }

        var codeValidation = await CodeValidator.ValidateCodeAsync(requestContext, form, client, cancellationToken);
        if (codeValidation.HasError)
        {
            return new(codeValidation.Error);
        }

        if (!string.Equals(codeValidation.AuthorizationCode.GetClientId(), client.GetClientId(), StringComparison.Ordinal))
        {
            return InvalidGrant;
        }

        var codeVerifierValidation = await CodeVerifierValidator.ValidateCodeVerifierAsync(requestContext, form, client, codeValidation.AuthorizationCode, cancellationToken);
        if (codeVerifierValidation.HasError)
        {
            return new(codeVerifierValidation.Error);
        }

        var redirectUriValidation = await RedirectUriValidator.ValidateRedirectUriAsync(requestContext, form, client, codeValidation.AuthorizationCode, cancellationToken);
        if (redirectUriValidation.HasError)
        {
            return new(redirectUriValidation.Error);
        }

        var codeScopes = codeValidation.AuthorizationCode.GetGrantedScopes();
        var grantedConsent = await GrantedConsents.FindAsync(
            requestContext,
            codeValidation.AuthorizationCode.GetEssentialResourceOwnerClaims().Identifiers.SubjectId,
            client,
            cancellationToken);

        if (grantedConsent == null || !grantedConsent.GetGrantedScopes().IsSupersetOf(codeScopes))
        {
            return UnauthorizedClient;
        }

        var scopeValidation = await ScopeValidator.ValidateScopeAsync(requestContext, form, client, codeScopes, cancellationToken);
        if (scopeValidation.HasError)
        {
            return new(scopeValidation.Error);
        }

        var resourceOwnerProfileValidation = await ResourceOwnerProfile.GetResourceOwnerProfileAsync(
            requestContext,
            codeValidation.AuthorizationCode.GetEssentialResourceOwnerClaims(),
            scopeValidation.AllowedResources,
            cancellationToken);

        if (!resourceOwnerProfileValidation.IsActive)
        {
            return DisabledUser;
        }

        return new(new ValidAuthorizationCodeTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret, TAuthorizationCode>(
            client,
            scopeValidation.AllowedResources,
            codeValidation.Handle,
            codeValidation.AuthorizationCode,
            resourceOwnerProfileValidation.Profile));
    }
}
