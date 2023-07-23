using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultClientSecretValidator<TRequestContext, TClient, TClientSecret>
    : IClientSecretValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
{
    public DefaultClientSecretValidator(IClientSecretHasher secretHasher, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(secretHasher);
        ArgumentNullException.ThrowIfNull(timeProvider);
        SecretHasher = secretHasher;
        TimeProvider = timeProvider;
    }

    protected IClientSecretHasher SecretHasher { get; }
    protected TimeProvider TimeProvider { get; }

    public virtual Task<bool> IsValidPreSharedSecret(
        TRequestContext requestContext,
        TClient client,
        string preSharedSecret,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        var clientSecrets = client.GetSecrets();
        if (!(clientSecrets.Count > 0))
        {
            return Task.FromResult(false);
        }

        foreach (var secret in clientSecrets)
        {
            if (SecretHasher.IsValid(preSharedSecret, secret.GetHashedValue()))
            {
                var expirationDateSeconds = secret.GetExpirationDate();
                if (expirationDateSeconds > 0)
                {
                    var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expirationDateSeconds);
                    var isActive = expiresAt >= TimeProvider.GetUtcNow();
                    return Task.FromResult(isActive);
                }

                return Task.FromResult(true);
            }
        }

        return Task.FromResult(false);
    }
}
