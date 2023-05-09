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
        cancellationToken.ThrowIfCancellationRequested();
        var credentials = await Storage.FindAsync(requestContext, allowedSigningAlgorithms, cancellationToken);
        return GetSigningCredentials(credentials, allowedSigningAlgorithms);
    }

    public virtual async Task<IReadOnlyCollection<SigningCredentials>> GetAllAsync(TRequestContext requestContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await Storage.GetAllAsync(requestContext, cancellationToken);
    }

    public virtual async Task<IReadOnlySet<string>> GetAllSigningCredentialsAlgorithmsAsync(
        TRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var credentials = await Storage.GetAllAsync(requestContext, cancellationToken);
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var credential in credentials)
        {
            result.Add(credential.Algorithm);
        }

        return result;
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
