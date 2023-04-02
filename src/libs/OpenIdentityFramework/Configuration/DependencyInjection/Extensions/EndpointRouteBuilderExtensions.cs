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

namespace OpenIdentityFramework.Configuration.DependencyInjection.Extensions;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public static class EndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapOpenIdentityFrameworkEndpoints(this IEndpointRouteBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var frameworkOptions = builder.ServiceProvider.GetRequiredService<OpenIdentityFrameworkOptions>();
        if (frameworkOptions.Endpoints.Authorize.Enable)
        {
            builder.AddEndpoint<IAuthorizeEndpointHandler>(
                frameworkOptions.Endpoints.Authorize.Path,
                new(new[]
                {
                    // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#section-3.1
                    // The authorization server MUST support the use of the HTTP GET method Section 9.3.1 of [RFC9110] for the authorization endpoint
                    // and MAY support the POST method (Section 9.3.3 of RFC9110) as well.
                    HttpMethods.Get,
                    HttpMethods.Post
                }));
            builder.AddEndpoint<IAuthorizeEndpointCallbackHandler>(
                frameworkOptions.Endpoints.Authorize.CallbackPath,
                new(new[]
                {
                    // Internal callback may use any handler
                    HttpMethods.Get
                }));
        }

        return builder;
    }

    public static void AddEndpoint<THandler>(
        this IEndpointRouteBuilder builder,
        string path,
        HttpMethodMetadata metadata)
        where THandler : class, IEndpointHandler
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(metadata);
        var endpointBuilder = builder.Map(
            RoutePatternFactory.Parse(path),
            static async httpContext =>
            {
                httpContext.RequestAborted.ThrowIfCancellationRequested();
                var handler = httpContext.RequestServices.GetRequiredService<THandler>();
                var result = await handler.HandleAsync(httpContext, httpContext.RequestAborted);
                await result.ExecuteAsync(httpContext, httpContext.RequestAborted);
            });
        endpointBuilder.WithMetadata(metadata);
        endpointBuilder.WithDisplayName($"{path} HTTP: {string.Join(", ", metadata.HttpMethods)}");
    }
}
