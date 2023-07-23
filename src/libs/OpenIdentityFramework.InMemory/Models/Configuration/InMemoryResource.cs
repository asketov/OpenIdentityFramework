using System;
using System.Collections.Generic;
using System.Linq;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Implementations;

namespace OpenIdentityFramework.InMemory.Models.Configuration;

public class InMemoryResource : AbstractResource<InMemoryResourceSecret>
{
    private readonly string _resourceId;
    private readonly long _resourceIdIssuedAt;
    private readonly IReadOnlyCollection<InMemoryResourceSecret> _secrets;
    private readonly IReadOnlySet<string> _supportedAccessTokenScopes;

    public InMemoryResource(string resourceId, long resourceIdIssuedAt, IReadOnlySet<string> supportedAccessTokenScopes, IReadOnlyCollection<InMemoryResourceSecret> secrets)
    {
        _resourceId = resourceId;
        _resourceIdIssuedAt = resourceIdIssuedAt;
        _supportedAccessTokenScopes = supportedAccessTokenScopes;
        _secrets = secrets;
    }

    public static InMemoryResource Create(string resourceId, string secret, DateTimeOffset resourceIdIssuedAt, IEnumerable<string> supportedAccessTokenScopes)
    {
        var issuedAtUnixTime = resourceIdIssuedAt.ToUnixTimeSeconds();
        var secrets = new HashSet<InMemoryResourceSecret>
        {
            new(DefaultClientSecretHasher.Instance.ComputeHash(secret), issuedAtUnixTime, 0)
        };
        return new(
            resourceId,
            issuedAtUnixTime,
            supportedAccessTokenScopes.ToHashSet(StringComparer.Ordinal),
            secrets);
    }

    public override string GetResourceId()
    {
        return _resourceId;
    }

    public override long GetResourceIdIssuedAt()
    {
        return _resourceIdIssuedAt;
    }

    public override IReadOnlySet<string> GetSupportedAccessTokenScopes()
    {
        return _supportedAccessTokenScopes;
    }

    public override IReadOnlyCollection<InMemoryResourceSecret> GetSecrets()
    {
        return _secrets;
    }
}
