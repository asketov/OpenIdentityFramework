using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.Services.Core;

public interface IKeyMaterialService<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    Task<SigningCredentials> GetSigningCredentialsAsync(
        TRequestContext requestContext,
        string issuer,
        IReadOnlySet<string>? allowedSigningAlgorithms,
        CancellationToken cancellationToken);
}
