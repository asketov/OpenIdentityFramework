using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.Services.Core;

public interface IClientSecretValidator<TRequestContext, TClient, TClientSecret>
    where TRequestContext : class, IRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractClientSecret, IEquatable<TClientSecret>
{
    Task<bool> IsValidPreSharedSecret(TRequestContext requestContext, TClient client, string preSharedSecret, CancellationToken cancellationToken);
}
