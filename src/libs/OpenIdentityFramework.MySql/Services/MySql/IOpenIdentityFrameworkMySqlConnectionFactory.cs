using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using MySqlConnector;

namespace OpenIdentityFramework.MySql.Services.MySql;

public interface IOpenIdentityFrameworkMySqlConnectionFactory
{
    Task<MySqlConnection> CreateAsync(HttpContext httpContext, CancellationToken cancellationToken);
}
