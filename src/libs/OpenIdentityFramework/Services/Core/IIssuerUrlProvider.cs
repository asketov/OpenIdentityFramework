using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace OpenIdentityFramework.Services.Core;

public interface IIssuerUrlProvider
{
    Task<string> GetIssuerAsync(HttpContext httpContext, CancellationToken cancellationToken);
}
