using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.InMemory.Models;
using OpenIdentityFramework.Storages.Configuration;

namespace OpenIdentityFramework.InMemory.Storages.Configuration;

public class InMemoryKeyMaterialStorage : IKeyMaterialStorage<InMemoryRequestContext>
{
    private readonly List<SigningCredentials> _signingCredentials;

    public InMemoryKeyMaterialStorage(IEnumerable<SigningCredentials> signingCredentials)
    {
        ArgumentNullException.ThrowIfNull(signingCredentials);
        _signingCredentials = signingCredentials.ToList();
    }

    public Task<IReadOnlyCollection<SigningCredentials>> GetAllAsync(
        InMemoryRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyCollection<SigningCredentials>>(_signingCredentials);
    }

    public Task<IReadOnlyCollection<SigningCredentials>> FindAsync(
        InMemoryRequestContext requestContext,
        IReadOnlySet<string>? allowedSigningAlgorithms,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (allowedSigningAlgorithms is not null && allowedSigningAlgorithms.Count > 0)
        {
            IReadOnlyCollection<SigningCredentials> result = _signingCredentials.Where(x => allowedSigningAlgorithms.Contains(x.Algorithm)).ToList();
            return Task.FromResult(result);
        }

        return Task.FromResult<IReadOnlyCollection<SigningCredentials>>(_signingCredentials);
    }
}
