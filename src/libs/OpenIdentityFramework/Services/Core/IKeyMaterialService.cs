using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace OpenIdentityFramework.Services.Core;

public interface IKeyMaterialService
{
    Task<SigningCredentials> GetSigningCredentialsAsync(
        HttpContext httpContext,
        string issuer,
        IReadOnlySet<string>? allowedSigningAlgorithms,
        CancellationToken cancellationToken);
}
