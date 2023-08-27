namespace OpenIdentityFramework.Host.Mvc.Services.Local;

public interface ILocalUserPasswordHasher
{
    byte[] ComputeHash(string rawPassword);
    bool IsValid(string rawPassword, byte[] passwordHash);
}
