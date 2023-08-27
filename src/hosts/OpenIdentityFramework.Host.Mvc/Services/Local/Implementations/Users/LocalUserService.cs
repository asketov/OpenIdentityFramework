using System;
using System.Collections.Generic;
using System.Linq;
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

    public LocalUser? FindByLoginAndPassword(string login, string password)
    {
        foreach (var localUser in _localUsers)
        {
            if (localUser.Login == login && _passwordHasher.IsValid(password, localUser.PasswordHash))
            {
                return localUser;
            }
        }

        return null;
    }

    public LocalUser? FindById(Guid id)
    {
        foreach (var localUser in _localUsers)
        {
            if (localUser.Id == id)
            {
                return localUser;
            }
        }

        return null;
    }
}
