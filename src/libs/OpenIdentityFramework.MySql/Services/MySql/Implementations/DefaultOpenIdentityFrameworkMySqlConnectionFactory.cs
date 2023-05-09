using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using MySqlConnector;

namespace OpenIdentityFramework.MySql.Services.MySql.Implementations;

public class DefaultOpenIdentityFrameworkMySqlConnectionFactory
    : IOpenIdentityFrameworkMySqlConnectionFactory
{
    public DefaultOpenIdentityFrameworkMySqlConnectionFactory(IOptions<DefaultOpenIdentityFrameworkMySqlConnectionFactoryOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ConnectionString = options.Value.ConnectionString;
    }

    protected string ConnectionString { get; }

    public virtual async Task<MySqlConnection> CreateAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = new MySqlConnection(ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}
