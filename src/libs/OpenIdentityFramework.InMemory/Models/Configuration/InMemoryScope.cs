using System;
using System.Collections.Generic;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.InMemory.Models.Configuration;

public class InMemoryScope : AbstractScope
{
    public InMemoryScope(
        string protocolName,
        string scopeTokenType,
        bool required,
        bool showInDiscovery,
        IReadOnlySet<string> userClaimTypes)
    {
        if (string.IsNullOrEmpty(protocolName))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(protocolName));
        }

        if (string.IsNullOrEmpty(scopeTokenType))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(scopeTokenType));
        }

        ArgumentNullException.ThrowIfNull(userClaimTypes);

        ProtocolName = protocolName;
        ScopeTokenType = scopeTokenType;
        Required = required;
        ShowInDiscovery = showInDiscovery;
        UserClaimTypes = userClaimTypes;
    }

    public string ProtocolName { get; }
    public string ScopeTokenType { get; }
    public bool Required { get; }
    public bool ShowInDiscovery { get; }
    public IReadOnlySet<string> UserClaimTypes { get; }


    public override string GetProtocolName()
    {
        return ProtocolName;
    }

    public override string GetScopeTokenType()
    {
        return ScopeTokenType;
    }

    public override bool IsRequired()
    {
        return Required;
    }

    public override bool ShowInDiscoveryEndpoint()
    {
        return ShowInDiscovery;
    }

    public override IReadOnlySet<string> GetUserClaimTypes()
    {
        return UserClaimTypes;
    }
}
