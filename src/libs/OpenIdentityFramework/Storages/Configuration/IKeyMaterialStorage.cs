using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace OpenIdentityFramework.Storages.Configuration;

public interface IKeyMaterialStorage
{
    Task<IReadOnlyCollection<SigningCredentials>> GetSigningCredentialsAsync(
        HttpContext httpContext,
        string issuer,
        IReadOnlySet<string>? allowedSigningAlgorithms,
        CancellationToken cancellationToken);
}
