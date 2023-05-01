using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Storages.Configuration;

public interface IKeyMaterialStorage<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    Task<IReadOnlyCollection<SigningCredentials>> FindAsync(
        TRequestContext requestContext,
        string issuer,
        IReadOnlySet<string>? allowedSigningAlgorithms,
        CancellationToken cancellationToken);
}
