// using System;
// using System.Threading;
// using System.Threading.Tasks;
// using Microsoft.AspNetCore.Http;
// using OpenIdentityFramework.Models;
// using OpenIdentityFramework.Models.Operation;
// using OpenIdentityFramework.Services.Core;
// using OpenIdentityFramework.Services.Endpoints.Authorize;
// using OpenIdentityFramework.Services.Operation;
//
// namespace OpenIdentityFramework.Services.Interaction.Implementations;
//
// public class DefaultOpenIdentityFrameworkInteractionService<TRequestContext, TAuthorizeRequestParameters>
//     : IOpenIdentityFrameworkInteractionService<TRequestContext, TAuthorizeRequestParameters>
//     where TRequestContext : AbstractRequestContext
//     where TAuthorizeRequestParameters : AbstractAuthorizeRequestParameters
// {
//     public DefaultOpenIdentityFrameworkInteractionService(
//         IRequestContextFactory<TRequestContext> contextFactory,
//         IAuthorizeRequestParametersService<TRequestContext, TAuthorizeRequestParameters> authorizeRequestParameters)
//     {
//         ArgumentNullException.ThrowIfNull(contextFactory);
//         ArgumentNullException.ThrowIfNull(authorizeRequestParameters);
//         ContextFactory = contextFactory;
//         AuthorizeRequestParameters = authorizeRequestParameters;
//     }
//
//     protected IRequestContextFactory<TRequestContext> ContextFactory { get; }
//     protected IAuthorizeRequestParametersService<TRequestContext, TAuthorizeRequestParameters> AuthorizeRequestParameters { get; }
//
//     protected IIssuerUrlProvider<TRequestContext> IssuerUrlProvider { get; }
//
//     public virtual async Task FindAuthorizationCodeAsync(HttpContext httpContext, string authorizeRequestId, CancellationToken cancellationToken)
//     {
//         ArgumentNullException.ThrowIfNull(httpContext);
//         cancellationToken.ThrowIfCancellationRequested();
//         int result;
//         await using var requestContext = await ContextFactory.CreateAsync(httpContext, cancellationToken);
//         try
//         {
//             result = await FindAuthorizationCodeAsync(requestContext, authorizeRequestId, cancellationToken);
//             await requestContext.CommitAsync(httpContext.RequestAborted);
//         }
//         catch
//         {
//             await requestContext.RollbackAsync(httpContext.RequestAborted);
//             throw;
//         }
//
//         return;
//     }
//
//     protected virtual async Task<int> FindAuthorizationCodeAsync(TRequestContext requestContext, string authorizeRequestId, CancellationToken cancellationToken)
//     {
//         var issuer = await IssuerUrlProvider.GetIssuerAsync(requestContext, cancellationToken);
//         var authorizeRequestParameters = await AuthorizeRequestParameters.ReadAsync(requestContext, authorizeRequestId, cancellationToken);
//
//     }
// }


