using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIdentityFramework.Services.Core.Models.ErrorService;

namespace OpenIdentityFramework.Services.Core;

public interface IErrorService
{
    Task<string> SaveAsync(
        HttpContext httpContext,
        Error error,
        CancellationToken cancellationToken);
}
