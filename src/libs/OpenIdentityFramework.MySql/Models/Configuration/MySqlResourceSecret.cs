using System;
using OpenIdentityFramework.Models.Configuration;

namespace OpenIdentityFramework.MySql.Models.Configuration;

public class MySqlResourceSecret : AbstractSecret
{
    public MySqlResourceSecret(string secretType, byte[] value, DateTimeOffset? expirationDate)
    {
        if (string.IsNullOrEmpty(secretType))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(secretType));
        }

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
