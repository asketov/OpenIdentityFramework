namespace OpenIdentityFramework.Models.Configuration;

public abstract class AbstractSecret
{
    public abstract byte[] GetValue();
    public abstract string GetSecretType();
}
