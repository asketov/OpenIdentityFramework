using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core.Models.ErrorService;

namespace OpenIdentityFramework.Services.Core;

public interface IErrorService<TRequestContext>
    where TRequestContext : class, IRequestContext
{
    Task<string> SaveAsync(
        TRequestContext requestContext,
        UnredirectableError unredirectableError,
        CancellationToken cancellationToken);
}
