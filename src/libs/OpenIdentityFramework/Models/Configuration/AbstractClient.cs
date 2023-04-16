using System;
using System.Collections.Generic;
using OpenIdentityFramework.Constants;

namespace OpenIdentityFramework.Models.Configuration;

public abstract class AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    public abstract string GetClientId();
    public abstract IReadOnlySet<string> GetPreRegisteredRedirectUris();
    public abstract string GetClientType();
    public abstract IReadOnlySet<string> GetAllowedScopes();
    public abstract IReadOnlyCollection<TClientSecret> GetSecrets();
    public abstract IReadOnlySet<string> GetAllowedGrantTypes();
    public abstract IReadOnlySet<string> GetAllowedCodeChallengeMethods();

    public bool IsConfidential()
    {
        return string.Equals(DefaultClientTypes.Confidential, GetClientType(), StringComparison.Ordinal);
    }
}
