using System;
using System.Collections.Generic;

namespace OpenIdentityFramework.Models.Operation;

public abstract class AbstractGrantedConsent
{
    public abstract string GetSubjectId();
    public abstract string GetClientId();
    public abstract IReadOnlySet<string> GetGrantedScopes();
    public abstract DateTimeOffset? GetExpirationDate();
}
