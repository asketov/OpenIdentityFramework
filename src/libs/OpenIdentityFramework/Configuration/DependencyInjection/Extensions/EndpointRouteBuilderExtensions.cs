using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Endpoints;
using OpenIdentityFramework.Endpoints.Handlers;
using OpenIdentityFramework.Endpoints.Results;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Operation;

namespace OpenIdentityFramework.Configuration.DependencyInjection.Extensions;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public static class EndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapOpenIdentityFrameworkEndpoints<TRequestContext>(this IEndpointRouteBuilder builder)
        where TRequestContext : AbstractRequestContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        var frameworkOptions = builder.ServiceProvider.GetRequiredService<OpenIdentityFrameworkOptions>();
        if (frameworkOptions.Endpoints.Authorize.Enable)
        {
            builder.AddEndpoint<TRequestContext, IAuthorizeEndpointHandler<TRequestContext>>(
                frameworkOptions.Endpoints.Authorize.Path,
                new(new[]
                {
                    // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
                    // The authorization server MUST support the use of the HTTP GET method Section 9.3.1 of [RFC9110] for the authorization endpoint
                    // and MAY support the POST method (Section 9.3.3 of RFC9110) as well.
                    HttpMethods.Get,
                    HttpMethods.Post
                }));
            builder.AddEndpoint<TRequestContext, IAuthorizeEndpointCallbackHandler<TRequestContext>>(
                frameworkOptions.Endpoints.Authorize.CallbackPath,
                new(new[]
                {
                    // Internal callback may use any handler
                    HttpMethods.Get
                }));
        }

        if (frameworkOptions.Endpoints.Token.Enable)
        {
            builder.AddEndpoint<TRequestContext, ITokenEndpointHandler<TRequestContext>>(
                frameworkOptions.Endpoints.Token.Path,
                new(new[]
                {
                    // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.2
                    // The client MUST use the HTTP POST method when making access token requests.
                    HttpMethods.Post
                }));
        }

        return builder;
    }

    public static void AddEndpoint<TRequestContext, THandler>(
        this IEndpointRouteBuilder builder,
        string path,
        HttpMethodMetadata metadata)
        where TRequestContext : AbstractRequestContext
        where THandler : class, IEndpointHandler<TRequestContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(metadata);
        var endpointBuilder = builder.Map(
            RoutePatternFactory.Parse(path),
            static async httpContext =>
            {
                httpContext.RequestAborted.ThrowIfCancellationRequested();
                var contextFactory = httpContext.RequestServices.GetRequiredService<IRequestContextFactory<TRequestContext>>();
                IEndpointHandlerResult<TRequestContext> result;
                await using var requestContext = await contextFactory.CreateAsync(httpContext, httpContext.RequestAborted);
                try
                {
                    var handler = httpContext.RequestServices.GetRequiredService<THandler>();
                    result = await handler.HandleAsync(requestContext, httpContext.RequestAborted);
                    await requestContext.CommitAsync(httpContext.RequestAborted);
                }
                catch
                {
                    await requestContext.RollbackAsync(httpContext.RequestAborted);
                    throw;
                }

                await result.ExecuteAsync(requestContext, httpContext.RequestAborted);
            });
        endpointBuilder.WithMetadata(metadata);
        endpointBuilder.WithDisplayName($"{path} HTTP: {string.Join(", ", metadata.HttpMethods)}");
    }
}
