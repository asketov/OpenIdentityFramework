using System.Collections.Generic;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.InMemory.Models.Configuration;

public class InMemoryScope : AbstractScope
{
    private readonly bool _isRequired;

    private readonly string _scopeId;
    private readonly string _scopeTokenType;
    private readonly bool _showInDiscoveryEndpoint;
    private readonly IReadOnlySet<string> _userClaimTypes;

    public InMemoryScope(string scopeId, string scopeTokenType, bool isRequired, bool showInDiscoveryEndpoint, IReadOnlySet<string> userClaimTypes)
    {
        _scopeId = scopeId;
        _scopeTokenType = scopeTokenType;
        _isRequired = isRequired;
        _showInDiscoveryEndpoint = showInDiscoveryEndpoint;
        _userClaimTypes = userClaimTypes;
    }

    public override string GetScopeId()
    {
        return _scopeId;
    }

    public override string GetScopeTokenType()
    {
        return _scopeTokenType;
    }

    public override bool IsRequired()
    {
        return _isRequired;
    }

    public override bool ShowInDiscoveryEndpoint()
    {
        return _showInDiscoveryEndpoint;
    }

    public override IReadOnlySet<string> GetUserClaimTypes()
    {
        return _userClaimTypes;
    }
}
