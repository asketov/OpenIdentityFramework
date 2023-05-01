using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Storages.Configuration;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultKeyMaterialService<TRequestContext> : IKeyMaterialService<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    public DefaultKeyMaterialService(IKeyMaterialStorage<TRequestContext> storage)
    {
        ArgumentNullException.ThrowIfNull(storage);
        Storage = storage;
    }

    protected IKeyMaterialStorage<TRequestContext> Storage { get; }

    public virtual async Task<SigningCredentials> GetSigningCredentialsAsync(
        TRequestContext requestContext,
        string issuer,
        IReadOnlySet<string>? allowedSigningAlgorithms,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var credentials = await Storage.FindAsync(requestContext, issuer, allowedSigningAlgorithms, cancellationToken);
        return GetSigningCredentials(credentials, allowedSigningAlgorithms);
    }

    protected virtual SigningCredentials GetSigningCredentials(
        IReadOnlyCollection<SigningCredentials>? credentials,
        IReadOnlySet<string>? algorithms)
    {
        if (credentials == null || credentials.Count < 1)
        {
            if (algorithms is { Count: > 0 })
            {
                throw new InvalidOperationException($"No signing credential for algorithms ({string.Join(" ", algorithms)}) registered");
            }

            throw new InvalidOperationException("No signing credential registered");
        }

        if (algorithms == null || algorithms.Count == 0)
        {
            return credentials.First();
        }

        var credentialForSpecificAlgorithm = credentials.FirstOrDefault(x => algorithms.Contains(x.Algorithm));
        if (credentialForSpecificAlgorithm == null)
        {
            throw new InvalidOperationException($"No signing credential for algorithms ({string.Join(" ", algorithms)}) registered");
        }

        return credentialForSpecificAlgorithm;
    }
}
