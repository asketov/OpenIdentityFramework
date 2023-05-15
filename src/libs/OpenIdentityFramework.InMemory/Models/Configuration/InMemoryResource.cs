using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.InMemory.Models.Configuration;

public class InMemoryResource : AbstractResource<InMemoryResourceSecret>
{
    public InMemoryResource(string protocolName, IReadOnlySet<string> accessTokenScopes, IReadOnlyCollection<InMemoryResourceSecret> secrets)
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
    public IReadOnlyCollection<InMemoryResourceSecret> Secrets { get; }

    public override string GetProtocolName()
    {
        return ProtocolName;
    }

    public override IReadOnlySet<string> GetAccessTokenScopes()
    {
        return AccessTokenScopes;
    }

    public override IReadOnlyCollection<InMemoryResourceSecret> GetSecrets()
    {
        return Secrets;
    }
}
