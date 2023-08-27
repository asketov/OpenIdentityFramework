using System;
using OpenIdentityFramework.Host.Mvc.Services.Local.Models;

namespace OpenIdentityFramework.Host.Mvc.Services.Local;

public interface ILocalUserService
{
    LocalUser? FindByLoginAndPassword(string login, string password);
    LocalUser? FindById(Guid id);
}
