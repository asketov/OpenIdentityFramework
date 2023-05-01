﻿using System.Threading;
using System.Threading.Tasks;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Services.Core.Models.ErrorService;

namespace OpenIdentityFramework.Services.Core;

public interface IErrorService<TRequestContext>
    where TRequestContext : AbstractRequestContext
{
    Task<string> SaveAsync(
        TRequestContext requestContext,
        Error error,
        CancellationToken cancellationToken);
}
