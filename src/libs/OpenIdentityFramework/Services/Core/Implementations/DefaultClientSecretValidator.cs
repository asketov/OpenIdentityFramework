using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultClientSecretValidator<TClient, TClientSecret>
    : IClientSecretValidator<TClient, TClientSecret>
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public DefaultClientSecretValidator(IClientSecretHasher secretHasher, ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(secretHasher);
        ArgumentNullException.ThrowIfNull(systemClock);
        SecretHasher = secretHasher;
        SystemClock = systemClock;
    }

    protected IClientSecretHasher SecretHasher { get; }
    protected ISystemClock SystemClock { get; }

    public virtual Task<bool> IsValidPreSharedSecret(
        HttpContext httpContext,
        TClient client,
        string preSharedSecret,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        var clientSecrets = client.GetSecrets();
        if (!(clientSecrets.Count > 0))
        {
            return Task.FromResult(false);
        }

        foreach (var secret in clientSecrets.Where(static x => x.GetSecretType() == DefaultSecretTypes.PreSharedSecret))
        {
            if (SecretHasher.IsValid(preSharedSecret, secret.GetValue()))
            {
                var expirationDate = secret.GetExpirationDate();
                if (expirationDate.HasValue)
                {
                    var isActive = expirationDate.Value >= SystemClock.UtcNow;
                    return Task.FromResult(isActive);
                }

                return Task.FromResult(true);
            }
        }

        return Task.FromResult(false);
    }
}
