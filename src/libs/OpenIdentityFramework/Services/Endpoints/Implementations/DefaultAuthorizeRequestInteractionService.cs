using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Requests.Authorize;
using OpenIdentityFramework.Constants.Responses.Authorize;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Models.Operation;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationService;
using OpenIdentityFramework.Services.Endpoints.Authorize;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestInteractionService;
using OpenIdentityFramework.Services.Endpoints.Authorize.Models.AuthorizeRequestValidator;
using OpenIdentityFramework.Services.Operation;

namespace OpenIdentityFramework.Services.Endpoints.Implementations;

public class DefaultAuthorizeRequestInteractionService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent, TGrantedConsent>
    : IAuthorizeRequestInteractionService<TClient, TClientSecret, TScope, TResource, TResourceSecret, TRequestConsent>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
    where TRequestConsent : AbstractAuthorizeRequestConsent
    where TGrantedConsent : AbstractGrantedConsent
{
    public DefaultAuthorizeRequestInteractionService(
        IUserProfileService userProfile,
        ISystemClock systemClock,
        IGrantedConsentService<TClient, TClientSecret, TGrantedConsent> consents)
    {
        ArgumentNullException.ThrowIfNull(userProfile);
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(consents);
        UserProfile = userProfile;
        SystemClock = systemClock;
        Consents = consents;
    }

    protected IUserProfileService UserProfile { get; }
    protected ISystemClock SystemClock { get; }
    protected IGrantedConsentService<TClient, TClientSecret, TGrantedConsent> Consents { get; }

    public virtual async Task<AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> ProcessInteractionRequirementsAsync(
        HttpContext httpContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        UserAuthentication? userAuthentication,
        TRequestConsent? authorizeRequestConsent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        cancellationToken.ThrowIfCancellationRequested();
        // special case when user without authentication issued an error prior to authenticating
        if (userAuthentication == null && authorizeRequestConsent != null && !authorizeRequestConsent.HasGranted(out var error, out _))
        {
            return ErrorDeniedConsent(error);
        }

        var isPromptNone = authorizeRequest.Prompt?.Contains(Prompt.None) == true;
        if (userAuthentication == null)
        {
            return LoginErrorOrInteractionRequired(isPromptNone);
        }

        var authenticationResult = await HandleAuthenticationAsync(httpContext, authorizeRequest, userAuthentication, isPromptNone, cancellationToken);
        if (authenticationResult != null)
        {
            return authenticationResult;
        }

        return await HandleConsentAsync(httpContext, authorizeRequest, userAuthentication, authorizeRequestConsent, isPromptNone, cancellationToken);
    }


    protected virtual async Task<AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>?> HandleAuthenticationAsync(
        HttpContext httpContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        UserAuthentication userAuthentication,
        bool isPromptNone,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(userAuthentication);
        cancellationToken.ThrowIfCancellationRequested();
        var userIsActive = await UserProfile.IsActiveAsync(httpContext, userAuthentication, cancellationToken);
        if (!userIsActive)
        {
            return LoginErrorOrInteractionRequired(isPromptNone);
        }

        // OpenID Connect 1.0 - max age check
        if (authorizeRequest is { IsOpenIdRequest: true, MaxAge: { } })
        {
            if (authorizeRequest.MaxAge.Value > 0)
            {
                var absoluteMaxAge = userAuthentication.AuthenticatedAt.AddSeconds(authorizeRequest.MaxAge.Value);
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
                if (!IsReAuthenticationAlreadyPerformed(authorizeRequest, userAuthentication))
                {
                    return LoginErrorOrInteractionRequired(isPromptNone);
                }
            }
        }

        // handle prompt=login and prompt=select_account
        if (IsReAuthenticationRequired(authorizeRequest) && !IsReAuthenticationAlreadyPerformed(authorizeRequest, userAuthentication))
        {
            return LoginErrorOrInteractionRequired(isPromptNone);
        }

        return null;
    }

    protected virtual async Task<AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret>> HandleConsentAsync(
        HttpContext httpContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        UserAuthentication? userAuthentication,
        TRequestConsent? authorizeRequestConsent,
        bool isPromptNone,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(userAuthentication);
        cancellationToken.ThrowIfCancellationRequested();
        var consentRequired = await IsConsentRequiredAsync(httpContext, authorizeRequest, userAuthentication, cancellationToken);
        if (consentRequired && isPromptNone)
        {
            return ErrorConsentRequired();
        }

        ValidResources<TScope, TResource, TResourceSecret> grantedResources;
        IReadOnlySet<string> scopesToPersist = new HashSet<string>();
        if (consentRequired || authorizeRequest.Prompt?.Contains(Prompt.Consent) == true)
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
                scopesToPersist = grantedResources.Raw;
            }
        }
        else
        {
            grantedResources = authorizeRequest.RequestedResources;
            scopesToPersist = authorizeRequest.RequestedResources.Raw;
        }

        await Consents.UpsertAsync(httpContext, userAuthentication.SubjectId, authorizeRequest.Client, scopesToPersist, cancellationToken);
        return new(new ValidAuthorizeRequestInteraction<TClient, TClientSecret, TScope, TResource, TResourceSecret>(
            authorizeRequest,
            userAuthentication,
            grantedResources));
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
        HttpContext httpContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        UserAuthentication userAuthentication,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(userAuthentication);
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

        var grantedConsent = await Consents.FindAsync(httpContext, userAuthentication.SubjectId, authorizeRequest.Client, cancellationToken);
        if (grantedConsent != null && authorizeRequest.RequestedResources.IsFullyCoveredBy(grantedConsent.GetGrantedScopes()))
        {
            return false;
        }

        return true;
    }

    protected virtual bool IsReAuthenticationAlreadyPerformed(
        ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest,
        UserAuthentication userAuthentication)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        ArgumentNullException.ThrowIfNull(userAuthentication);
        return userAuthentication.AuthenticatedAt > authorizeRequest.InitialRequestDate;
    }

    protected virtual bool IsReAuthenticationRequired(ValidAuthorizeRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> authorizeRequest)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        return authorizeRequest.Prompt != null && (authorizeRequest.Prompt.Contains(Prompt.Login) || authorizeRequest.Prompt.Contains(Prompt.SelectAccount));
    }

    #region Errors

    protected virtual AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> ErrorDeniedConsent(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        if (protocolError.Error == Errors.LoginRequired
            || protocolError.Error == Errors.ConsentRequired
            || protocolError.Error == Errors.InteractionRequired
            || protocolError.Error == Errors.AccountSelectionRequired)
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
        return new(new ProtocolError(Errors.LoginRequired, null));
    }

    protected virtual AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> ErrorAccessDenied()
    {
        return new(new ProtocolError(Errors.AccessDenied, null));
    }

    protected virtual AuthorizeRequestInteractionResult<TClient, TClientSecret, TScope, TResource, TResourceSecret> ErrorConsentRequired()
    {
        return new(new ProtocolError(Errors.ConsentRequired, null));
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
