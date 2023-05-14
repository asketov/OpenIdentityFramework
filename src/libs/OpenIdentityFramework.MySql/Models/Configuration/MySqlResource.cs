using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.MySql.Models.Configuration;

public class MySqlResource : AbstractResource<MySqlResourceSecret>
{
    public MySqlResource(string protocolName, IReadOnlySet<string> accessTokenScopes, IReadOnlyCollection<MySqlResourceSecret> secrets)
    {
        if (string.IsNullOrEmpty(protocolName))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(protocolName));
        }

        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(accessTokenScopes);

        ProtocolName = protocolName;
        AccessTokenScopes = accessTokenScopes;
        Secrets = secrets;
    }

    public string ProtocolName { get; }
    public IReadOnlySet<string> AccessTokenScopes { get; }
    public IReadOnlyCollection<MySqlResourceSecret> Secrets { get; }

    public override string GetProtocolName()
    {
        return ProtocolName;
    }

    public override IReadOnlySet<string> GetAccessTokenScopes()
    {
        return AccessTokenScopes;
    }

    public override IReadOnlyCollection<MySqlResourceSecret> GetSecrets()
    {
        return Secrets;
    }
}
