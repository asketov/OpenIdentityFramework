using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core.Models.KeyMaterialService;
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

    public virtual async Task<SigningCredentialsSearchResult> FindSigningCredentialsAsync(
        TRequestContext requestContext,
        IReadOnlySet<string>? allowedSigningAlgorithms,
        CancellationToken cancellationToken)
    {
        var credentials = await Storage.FindAsync(requestContext, allowedSigningAlgorithms, cancellationToken);
        return GetSigningCredentials(credentials, allowedSigningAlgorithms);
    }


    protected virtual SigningCredentialsSearchResult GetSigningCredentials(
        IReadOnlyCollection<SigningCredentials>? credentials,
        IReadOnlySet<string>? algorithms)
    {
        if (credentials == null || credentials.Count < 1)
        {
            if (algorithms is { Count: > 0 })
            {
                return new($"No signing credential for algorithms ({string.Join(" ", algorithms)}) registered");
            }

            throw new InvalidOperationException("No signing credential registered");
        }

        if (algorithms == null || algorithms.Count == 0)
        {
            return new(credentials.First());
        }

        var credentialForSpecificAlgorithm = credentials.FirstOrDefault(x => algorithms.Contains(x.Algorithm));
        if (credentialForSpecificAlgorithm == null)
        {
            return new($"No signing credential for algorithms ({string.Join(" ", algorithms)}) registered");
        }

        return new(credentialForSpecificAlgorithm);
    }
}
