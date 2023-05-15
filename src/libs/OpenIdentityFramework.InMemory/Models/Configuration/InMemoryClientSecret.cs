using System;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.InMemory.Models.Configuration;

public class InMemoryClientSecret : AbstractSecret
{
    public InMemoryClientSecret(string secretType, byte[] value, DateTimeOffset? expirationDate)
    {
        ArgumentNullException.ThrowIfNull(secretType);
        ArgumentNullException.ThrowIfNull(value);

        SecretType = secretType;
        Value = value;
        ExpirationDate = expirationDate;
    }

    public string SecretType { get; }

    public byte[] Value { get; }

    public DateTimeOffset? ExpirationDate { get; }

    public override byte[] GetValue()
    {
        return Value;
    }

    public override string GetSecretType()
    {
        return SecretType;
    }

    public override DateTimeOffset? GetExpirationDate()
    {
        return ExpirationDate;
    }
}
