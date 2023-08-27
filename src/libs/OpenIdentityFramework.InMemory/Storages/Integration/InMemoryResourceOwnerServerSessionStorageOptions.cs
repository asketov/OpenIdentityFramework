using System;

namespace OpenIdentityFramework.InMemory.Storages.Integration;

public class InMemoryResourceOwnerServerSessionStorageOptions
{
    public TimeSpan DefaultServerSessionDuration { get; set; } = TimeSpan.FromHours(1);
}
