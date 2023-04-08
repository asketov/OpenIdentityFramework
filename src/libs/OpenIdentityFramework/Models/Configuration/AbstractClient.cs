using System.Collections.Generic;

namespace OpenIdentityFramework.Models.Configuration;

public abstract class AbstractClient
{
    public abstract string GetClientId();
    public abstract bool IsEnabled();

    public abstract IReadOnlySet<string> GetAllowedResponseTypes();
}
