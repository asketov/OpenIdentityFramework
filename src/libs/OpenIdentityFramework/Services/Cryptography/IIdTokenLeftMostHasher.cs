namespace OpenIdentityFramework.Services.Cryptography;

public interface IIdTokenLeftMostHasher
{
    string ComputeHash(string value, string tokenSigningAlgorithm);
}
