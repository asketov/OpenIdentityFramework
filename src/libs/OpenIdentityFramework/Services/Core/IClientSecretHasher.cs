namespace OpenIdentityFramework.Services.Core;

public interface IClientSecretHasher
{
    byte[] ComputeHash(string rawClientSecret);
    bool IsValid(string rawClientSecret, byte[] clientSecretHash);
}
