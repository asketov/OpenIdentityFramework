using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.Host.Mvc.Services.Local.Models;

public class LocalUser
{
    public LocalUser(Guid id, string login, byte[] passwordHash, IReadOnlySet<string>? roles)
    {
        Id = id;
        Login = login;
        PasswordHash = passwordHash;
        Roles = roles;
    }

    public Guid Id { get; }

    public string Login { get; }

    public byte[] PasswordHash { get; }

    public IReadOnlySet<string>? Roles { get; }
}
