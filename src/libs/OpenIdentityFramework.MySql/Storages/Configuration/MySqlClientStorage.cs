using System;
using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.MySql.Models;
using OpenIdentityFramework.MySql.Models.Configuration;
using OpenIdentityFramework.Storages.Configuration;

namespace OpenIdentityFramework.MySql.Storages.Configuration;

public class MySqlClientStorage : IClientStorage<MySqlRequestContext, MySqlClient, MySqlClientSecret>
{
    public Task<MySqlClient?> FindEnabledAsync(
        MySqlRequestContext requestContext,
        string clientId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        using var cmd = requestContext.Connection.CreateCommand();
        cmd.CommandText = "";
        throw new NotImplementedException();
    }
}
