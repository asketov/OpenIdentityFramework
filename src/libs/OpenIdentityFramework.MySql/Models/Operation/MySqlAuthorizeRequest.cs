using System;
using System.Collections.Generic;
using Microsoft.Extensions.Primitives;
using OpenIdentityFramework.Models.Operation;

namespace OpenIdentityFramework.MySql.Models.Operation;

public class MySqlAuthorizeRequest : AbstractAuthorizeRequest
{
    public MySqlAuthorizeRequest(
        DateTimeOffset initialRequestDate,
        IReadOnlyDictionary<string, StringValues> authorizeRequestParameters,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequestParameters);

        InitialRequestDate = initialRequestDate;
        AuthorizeRequestParameters = authorizeRequestParameters;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public DateTimeOffset InitialRequestDate { get; }
    public IReadOnlyDictionary<string, StringValues> AuthorizeRequestParameters { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }

    public override DateTimeOffset GetInitialRequestDate()
    {
        return InitialRequestDate;
    }

    public override IReadOnlyDictionary<string, StringValues> GetAuthorizeRequestParameters()
    {
        return AuthorizeRequestParameters;
    }

    public override DateTimeOffset GetCreationDate()
    {
        return CreatedAt;
    }

    public override DateTimeOffset GetExpirationDate()
    {
        return ExpiresAt;
    }
}
