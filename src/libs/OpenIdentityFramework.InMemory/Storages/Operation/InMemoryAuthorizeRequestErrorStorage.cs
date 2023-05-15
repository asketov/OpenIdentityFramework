using System;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.InMemory.Models.Operation;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Storages.Operation;

namespace OpenIdentityFramework.InMemory.Storages.Operation;

public class InMemoryAuthorizeRequestErrorStorage : IAuthorizeRequestErrorStorage<InMemoryRequestContext, InMemoryAuthorizeRequestError>
{
    public InMemoryAuthorizeRequestErrorStorage(
        OpenIdentityFrameworkOptions frameworkOptions,
        ISystemClock systemClock,
        IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(provider);
        FrameworkOptions = frameworkOptions;
        SystemClock = systemClock;
        DataProtector = provider.CreateProtector($"{typeof(InMemoryAuthorizeRequestErrorStorage).Namespace}.{nameof(InMemoryAuthorizeRequestErrorStorage)}");
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected ISystemClock SystemClock { get; }
    protected IDataProtector DataProtector { get; }

    public Task<string> CreateAsync(
        InMemoryRequestContext requestContext,
        ProtocolError protocolError,
        string? clientId,
        string? redirectUri,
        string? responseMode,
        string? state,
        string issuer,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var error = new InMemoryAuthorizeRequestError(
            protocolError,
            clientId,
            redirectUri,
            responseMode,
            state,
            issuer,
            createdAt,
            expiresAt);
        var serializedValue = JsonSerializer.Serialize(error);
        var errorBytes = Encoding.UTF8.GetBytes(serializedValue);
        var protectedBytes = DataProtector.Protect(errorBytes);
        var authorizeRequestErrorHandle = WebEncoders.Base64UrlEncode(protectedBytes);
        return Task.FromResult(authorizeRequestErrorHandle);
    }

    public Task<InMemoryAuthorizeRequestError?> FindAsync(
        InMemoryRequestContext requestContext,
        string authorizeRequestErrorHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var protectedBytes = WebEncoders.Base64UrlDecode(authorizeRequestErrorHandle);
            var errorBytes = DataProtector.Unprotect(protectedBytes);
            var serializedValue = Encoding.UTF8.GetString(errorBytes);
            var deserializedValue = JsonSerializer.Deserialize<InMemoryAuthorizeRequestError>(serializedValue);
            var currentDate = SystemClock.UtcNow;
            if (deserializedValue is not null && currentDate < deserializedValue.GetExpirationDate())
            {
                return Task.FromResult<InMemoryAuthorizeRequestError?>(deserializedValue);
            }
        }
#pragma warning disable CA1031
        // ReSharper disable once EmptyGeneralCatchClause
        catch
#pragma warning restore CA1031
        {
        }

        return Task.FromResult<InMemoryAuthorizeRequestError?>(null);
    }

    public Task DeleteAsync(
        InMemoryRequestContext requestContext,
        string authorizeRequestErrorHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }
}
