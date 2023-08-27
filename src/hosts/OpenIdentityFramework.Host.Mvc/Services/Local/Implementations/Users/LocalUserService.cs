using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Host.Mvc.Services.Local.Models;

namespace OpenIdentityFramework.Host.Mvc.Services.Local.Implementations.Users;

public class LocalUserService : ILocalUserService
{
    private readonly LocalUser[] _localUsers;
    private readonly ILocalUserPasswordHasher _passwordHasher;

    public LocalUserService(ILocalUserPasswordHasher passwordHasher, IEnumerable<LocalUser> localUsers)
    {
        ArgumentNullException.ThrowIfNull(passwordHasher);
        ArgumentNullException.ThrowIfNull(localUsers);
        _passwordHasher = passwordHasher;
        _localUsers = localUsers.ToArray();
    }

    public Task<LocalUser?> FindByLoginAndPasswordAsync(string login, string password, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        foreach (var localUser in _localUsers)
        {
            if (localUser.Login == login && _passwordHasher.IsValid(password, localUser.PasswordHash))
            {
                return Task.FromResult<LocalUser?>(localUser);
            }
        }

        return Task.FromResult<LocalUser?>(null);
    }

    public Task<LocalUser?> FindByIdAsync(Guid id, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        foreach (var localUser in _localUsers)
        {
            if (localUser.Id == id)
            {
                return Task.FromResult<LocalUser?>(localUser);
            }
        }

        return Task.FromResult<LocalUser?>(null);
    }

    public Task<bool> IsActiveAsync(Guid id, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        foreach (var localUser in _localUsers)
        {
            if (localUser.Id == id)
            {
                return Task.FromResult(true);
            }
        }

        return Task.FromResult(false);
    }
}
