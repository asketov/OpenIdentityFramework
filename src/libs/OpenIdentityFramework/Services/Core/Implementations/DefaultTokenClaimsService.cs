using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ResourceValidator;
using OpenIdentityFramework.Services.Core.Models.TokenService;
using OpenIdentityFramework.Services.Core.Models.UserAuthenticationTicketService;
using OpenIdentityFramework.Services.Operation;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultTokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    : ITokenClaimsService<TClient, TClientSecret, TScope, TResource, TResourceSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
    where TScope : AbstractScope
    where TResource : AbstractResource<TResourceSecret>
    where TResourceSecret : AbstractSecret
{
    public DefaultTokenClaimsService(IUserProfileService userProfile)
    {
        ArgumentNullException.ThrowIfNull(userProfile);
        UserProfile = userProfile;
    }

    protected IUserProfileService UserProfile { get; }

    public virtual async Task<HashSet<LightweightClaim>> GetIdentityTokenClaimsAsync(
        HttpContext httpContext,
        IdTokenRequest<TClient, TClientSecret, TScope, TResource, TResourceSecret> idTokenRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(idTokenRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var result = new HashSet<LightweightClaim>(256, LightweightClaim.EqualityComparer);
        var allowedClaimTypes = GetAllowedIdTokenClaimTypes(idTokenRequest.GrantedResources);
        foreach (var subjectClaim in GetSubjectClaims(idTokenRequest.Ticket.UserAuthentication))
        {
            result.Add(subjectClaim);
        }

        if (idTokenRequest.Client.ShouldAlwaysIncludeUserClaimsInIdToken() || idTokenRequest.ForceIncludeUserClaimsInIdToken)
        {
            var profileClaims = await UserProfile.GetProfileClaimsAsync(
                httpContext,
                idTokenRequest.Ticket,
                allowedClaimTypes,
                cancellationToken);
            foreach (var profileClaim in profileClaims)
            {
                if (allowedClaimTypes.Contains(profileClaim.Type))
                {
                    result.Add(profileClaim);
                }
            }
        }

        return result;
    }

    protected virtual IReadOnlySet<string> GetAllowedIdTokenClaimTypes(ValidResources<TScope, TResource, TResourceSecret> grantedResources)
    {
        ArgumentNullException.ThrowIfNull(grantedResources);
        var additionalClaimTypes = new HashSet<string>(256);
        foreach (var idTokenScope in grantedResources.IdTokenScopes)
        {
            foreach (var idTokenScopeClaimType in idTokenScope.GetUserClaimTypes())
            {
                if (!DefaultJwtClaimTypes.Restrictions.Contains(idTokenScopeClaimType))
                {
                    additionalClaimTypes.Add(idTokenScopeClaimType);
                }
            }
        }

        return additionalClaimTypes;
    }

    protected virtual IEnumerable<LightweightClaim> GetSubjectClaims(UserAuthentication userAuthentication)
    {
        ArgumentNullException.ThrowIfNull(userAuthentication);
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
        // sub - REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4.
        // It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
        yield return new(DefaultJwtClaimTypes.Subject, userAuthentication.SubjectId);

        // https://openid.net/specs/openid-connect-backchannel-1_0.html#rfc.section.2.1
        // The sid (session ID) Claim used in ID Tokens and as a Logout Token parameter has the following definition
        // sid - OPTIONAL. Session ID - String identifier for a Session. This represents a Session of a User Agent or device for a logged-in End-User at an RP.
        // Different sid values are used to identify distinct sessions at an OP. The sid value need only be unique in the context of a particular issuer.
        // Its contents are opaque to the RP. Its syntax is the same as an OAuth 2.0 Client Identifier.
        yield return new(DefaultJwtClaimTypes.SessionId, userAuthentication.SessionId);

        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
        // auth_time - Time when the End-User authentication occurred. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
        // When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL.
        yield return new(
            DefaultJwtClaimTypes.AuthenticationTime,
            userAuthentication.AuthenticatedAt.ToUnixTimeSeconds().ToString("D", CultureInfo.InvariantCulture),
            ClaimValueTypes.Integer64);
    }
}
