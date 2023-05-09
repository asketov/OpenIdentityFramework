using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Response.Errors;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core;
using OpenIdentityFramework.Services.Core.Models.ResourceOwnerAuthenticationService;
using OpenIdentityFramework.Services.Core.Models.ResourceService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestInteractionService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;

namespace OpenIdentityFramework.Services.Endpoints.Authorize.Implementations;

public class DefaultAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent, TGrantedConsent>
    : IAuthorizeRequestInteractionService<TRequestContext, TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TRequestConsent : AbstractAuthorizeRequestConsent
    where TGrantedConsent : AbstractGrantedConsent
{
    public DefaultAuthorizeRequestInteractionService(
        IResourceOwnerProfileService<TRequestContext, TScope, TResource, TResourceSecret> resourceOwnerProfile,
        IGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent> consents)
    {
        ArgumentNullException.ThrowIfNull(resourceOwnerProfile);
        ArgumentNullException.ThrowIfNull(consents);
        ResourceOwnerProfile = resourceOwnerProfile;
        Consents = consents;
    }

    protected IResourceOwnerProfileService<TRequestContext, TScope, TResource, TResourceSecret> ResourceOwnerProfile { get; }
    protected IGrantedConsentService<TRequestContext, TClient, TClientSecret, TGrantedConsent> Consents { get; }

    public virtual async Task<AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> ProcessInteractionRequirementsAsync(
        TRequestContext requestContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        ResourceOwnerAuthentication? resourceOwnerAuthentication,
        TRequestConsent? authorizeRequestConsent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        cancellationToken.ThrowIfCancellationRequested();
        // special case when user without authentication issued an error prior to authenticating
        if (resourceOwnerAuthentication == null && authorizeRequestConsent != null && !authorizeRequestConsent.HasGranted(out var error, out _))
        {
            return ErrorDeniedConsent(error);
        }

        var isPromptNone = authorizeRequest.Prompt?.Contains(DefaultPrompt.None) == true;
        if (resourceOwnerAuthentication == null)
        {
            return LoginErrorOrInteractionRequired(isPromptNone);
        }

        var authenticationResult = await HandleAuthenticationAsync(requestContext, authorizeRequest, resourceOwnerAuthentication, isPromptNone, cancellationToken);
        if (authenticationResult != null)
        {
            return authenticationResult;
        }

        return await HandleConsentAsync(requestContext, authorizeRequest, resourceOwnerAuthentication, authorizeRequestConsent, isPromptNone, cancellationToken);
    }

    protected virtual async Task<AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>?> HandleAuthenticationAsync(
        TRequestContext requestContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        ResourceOwnerAuthentication resourceOwnerAuthentication,
        bool isPromptNone,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(resourceOwnerAuthentication);
        cancellationToken.ThrowIfCancellationRequested();
        var isActive = await ResourceOwnerProfile.IsActiveAsync(requestContext, resourceOwnerAuthentication.EssentialClaims.Identifiers, cancellationToken);
        if (!isActive)
        {
            return LoginErrorOrInteractionRequired(isPromptNone);
        }

        // OpenID Connect 1.0 - max age check
        if (authorizeRequest is { IsOpenIdRequest: true, MaxAge: not null })
        {
            if (authorizeRequest.MaxAge.Value > 0)
            {
                var absoluteMaxAge = resourceOwnerAuthentication.EssentialClaims.AuthenticatedAt.AddSeconds(authorizeRequest.MaxAge.Value);
                if (authorizeRequest.InitialRequestDate > absoluteMaxAge)
                {
                    return LoginErrorOrInteractionRequired(isPromptNone);
                }
            }
            else
            {
                // force re-authentication once when max_age=0
                // https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.1.1.1
                // Note that max_age=0 is equivalent to prompt=login.
                if (!IsReAuthenticationAlreadyPerformed(authorizeRequest, resourceOwnerAuthentication))
                {
                    return LoginErrorOrInteractionRequired(isPromptNone);
                }
            }
        }

        // handle prompt=login and prompt=select_account
        if (IsReAuthenticationRequired(authorizeRequest) && !IsReAuthenticationAlreadyPerformed(authorizeRequest, resourceOwnerAuthentication))
        {
            return LoginErrorOrInteractionRequired(isPromptNone);
        }

        return null;
    }

    protected virtual async Task<AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> HandleConsentAsync(
        TRequestContext requestContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        ResourceOwnerAuthentication resourceOwnerAuthentication,
        TRequestConsent? authorizeRequestConsent,
        bool isPromptNone,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(resourceOwnerAuthentication);
        cancellationToken.ThrowIfCancellationRequested();
        var consentRequired = await IsConsentRequiredAsync(requestContext, authorizeRequest, resourceOwnerAuthentication, cancellationToken);
        if (consentRequired && isPromptNone)
        {
            return ErrorConsentRequired();
        }

        ValidResources<TScope, TResource, TResourceSecret> grantedResources;
        IReadOnlySet<string> scopesToPersist = new HashSet<string>();
        if (consentRequired || authorizeRequest.Prompt?.Contains(DefaultPrompt.Consent) == true)
        {
            if (authorizeRequestConsent == null)
            {
                return ConsentErrorOrInteractionRequired(isPromptNone);
            }

            if (!authorizeRequestConsent.HasGranted(out var error, out var grant))
            {
                return ErrorDeniedConsent(error);
            }

            var (grantedScopes, shouldRemember) = grant.Value;
            if (!authorizeRequest.RequestedResources.IsRequiredScopesCoveredBy(grantedScopes))
            {
                return ErrorAccessDenied();
            }

            grantedResources = authorizeRequest.RequestedResources.FilterGrantedScopes(grantedScopes);
            if (shouldRemember)
            {
                scopesToPersist = grantedResources.RawScopes;
            }
        }
        else
        {
            grantedResources = authorizeRequest.RequestedResources;
            scopesToPersist = authorizeRequest.RequestedResources.RawScopes;
        }

        var claimsResult = await ResourceOwnerProfile.GetResourceOwnerProfileAsync(
            requestContext,
            resourceOwnerAuthentication.EssentialClaims,
            grantedResources,
            cancellationToken);
        if (!claimsResult.IsActive)
        {
            return LoginErrorOrInteractionRequired(isPromptNone);
        }

        await Consents.UpsertAsync(requestContext, resourceOwnerAuthentication.EssentialClaims.Identifiers.SubjectId, authorizeRequest.Client, scopesToPersist, cancellationToken);
        return new(new ValidAuthorizeRequestInteraction<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
            authorizeRequest,
            grantedResources,
            resourceOwnerAuthentication,
            claimsResult.Profile));
    }

    protected virtual AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> LoginErrorOrInteractionRequired(bool isPromptNone)
    {
        if (isPromptNone)
        {
            return ErrorLoginRequired();
        }

        return InteractionLogin();
    }

    protected virtual AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> ConsentErrorOrInteractionRequired(bool isPromptNone)
    {
        if (isPromptNone)
        {
            return ErrorConsentRequired();
        }

        return InteractionConsent();
    }

    protected virtual async Task<bool> IsConsentRequiredAsync(
        TRequestContext requestContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        ResourceOwnerAuthentication resourceOwnerAuthentication,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(resourceOwnerAuthentication);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.4
        // Once the End-User is authenticated, the Authorization Server MUST obtain an authorization decision before releasing information to the Relying Party.
        // When permitted by the request parameters used, this MAY be done through an interactive dialogue with the End-User that makes it clear what is being consented to
        // or by establishing consent via conditions for processing the request or other means (for example, via previous administrative consent).
        // ---------------------
        // administrative consent check
        if (!authorizeRequest.Client.IsConsentRequired())
        {
            return false;
        }

        if (authorizeRequest.RequestedResources.HasAnyScope())
        {
            return false;
        }

        if (!authorizeRequest.Client.CanRememberConsent())
        {
            return true;
        }

        if (authorizeRequest.RequestedResources.HasOfflineAccess)
        {
            return true;
        }

        var grantedConsent = await Consents.FindAsync(requestContext, resourceOwnerAuthentication.EssentialClaims.Identifiers.SubjectId, authorizeRequest.Client, cancellationToken);
        if (grantedConsent != null && authorizeRequest.RequestedResources.IsFullyCoveredBy(grantedConsent.GetGrantedScopes()))
        {
            return false;
        }

        return true;
    }

    protected virtual bool IsReAuthenticationAlreadyPerformed(
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        ResourceOwnerAuthentication resourceOwnerAuthentication)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(resourceOwnerAuthentication);
        return resourceOwnerAuthentication.EssentialClaims.AuthenticatedAt > authorizeRequest.InitialRequestDate;
    }

    protected virtual bool IsReAuthenticationRequired(ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        return authorizeRequest.Prompt != null && (authorizeRequest.Prompt.Contains(DefaultPrompt.Login) || authorizeRequest.Prompt.Contains(DefaultPrompt.SelectAccount));
    }

    #region Errors

    protected virtual AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> ErrorDeniedConsent(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        if (protocolError.Error == AuthorizeErrors.LoginRequired
            || protocolError.Error == AuthorizeErrors.ConsentRequired
            || protocolError.Error == AuthorizeErrors.InteractionRequired
            || protocolError.Error == AuthorizeErrors.AccountSelectionRequired)
        {
            return ErrorProtocol(protocolError);
        }

        return ErrorAccessDenied();
    }

    protected virtual AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> ErrorProtocol(ProtocolError protocolError)
    {
        return new(protocolError);
    }

    protected virtual AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> ErrorLoginRequired()
    {
        return new(new ProtocolError(AuthorizeErrors.LoginRequired, null));
    }

    protected virtual AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> ErrorAccessDenied()
    {
        return new(new ProtocolError(AuthorizeErrors.AccessDenied, null));
    }

    protected virtual AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> ErrorConsentRequired()
    {
        return new(new ProtocolError(AuthorizeErrors.ConsentRequired, null));
    }

    #endregion

    #region Interactions

    protected virtual AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> InteractionLogin()
    {
        return new(DefaultInteractionResult.Login);
    }

    protected virtual AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> InteractionConsent()
    {
        return new(DefaultInteractionResult.Consent);
    }

    #endregion
}
