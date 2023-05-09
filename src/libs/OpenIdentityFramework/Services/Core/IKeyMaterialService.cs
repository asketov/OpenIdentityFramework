using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core.Models.KeyMaterialService;

namespace OpenIdentityFramework.Services.Core;

public interface IKeyMaterialService<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    Task<SigningCredentialsSearchResult> FindSigningCredentialsAsync(
        TRequestContext requestContext,
        IReadOnlySet<string>? allowedSigningAlgorithms,
        CancellationToken cancellationToken);

    Task<IReadOnlyCollection<SigningCredentials>> GetAllAsync(
        TRequestContext requestContext,
        CancellationToken cancellationToken);

    Task<IReadOnlySet<string>> GetAllSigningCredentialsAlgorithmsAsync(
        TRequestContext requestContext,
        CancellationToken cancellationToken);
}
