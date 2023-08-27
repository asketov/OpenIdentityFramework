using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Host.Mvc.Services.Local.Models;

namespace OpenIdentityFramework.Host.Mvc.Services.Local;

public interface ILocalUserService
{
    Task<LocalUser?> FindByLoginAndPasswordAsync(string login, string password, CancellationToken cancellationToken);
    Task<LocalUser?> FindByIdAsync(Guid id, CancellationToken cancellationToken);
    Task<bool> IsActiveAsync(Guid id, CancellationToken cancellationToken);
}
