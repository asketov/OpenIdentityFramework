﻿using System.Diagnostics.CodeAnalysis;

namespace OpenIdentityFramework.Configuration.Options;

[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
public class OpenIdentityFrameworkOptions
{
    public EndpointOptions Endpoints { get; set; } = new();
}
