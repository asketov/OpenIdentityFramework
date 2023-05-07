using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
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
}
