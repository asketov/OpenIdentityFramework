using System;
using System.Data;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using OpenIdentityFramework.MySql.Models;
using OpenIdentityFramework.MySql.Services.MySql;
using OpenIdentityFramework.Services.Operation;

namespace OpenIdentityFramework.MySql.Services.Operation;

public class MySqlRequestContextFactory : IRequestContextFactory<MySqlRequestContext>
{
    public MySqlRequestContextFactory(
        IOptions<MySqlRequestContextFactoryOptions> options,
        IOpenIdentityFrameworkMySqlConnectionFactory connectionFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(connectionFactory);
        IsolationLevel = options.Value.IsolationLevel;
        ConnectionFactory = connectionFactory;
    }

    protected IsolationLevel IsolationLevel { get; }
    protected IOpenIdentityFrameworkMySqlConnectionFactory ConnectionFactory { get; }

    public virtual async Task<MySqlRequestContext> CreateAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var connection = await ConnectionFactory.CreateAsync(httpContext, cancellationToken);
        var transaction = await connection.BeginTransactionAsync(IsolationLevel, cancellationToken);
        return new(httpContext, connection, transaction);
    }
}
