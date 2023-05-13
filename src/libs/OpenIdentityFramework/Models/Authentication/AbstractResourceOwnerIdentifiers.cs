namespace OpenIdentityFramework.Models.Authentication;

public abstract class AbstractResourceOwnerIdentifiers
{
    public abstract string GetSubjectId();
    public abstract string GetSessionId();
}
