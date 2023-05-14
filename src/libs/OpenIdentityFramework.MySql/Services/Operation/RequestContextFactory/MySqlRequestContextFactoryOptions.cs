using System.Data;

namespace OpenIdentityFramework.MySql.Services.Operation.RequestContextFactory;

public class MySqlRequestContextFactoryOptions
{
    public IsolationLevel IsolationLevel { get; set; } = IsolationLevel.ReadCommitted;
}
