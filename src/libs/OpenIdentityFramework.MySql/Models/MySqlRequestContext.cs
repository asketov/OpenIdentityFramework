using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using MySqlConnector;
using OpenIdentityFramework.Models;

namespace OpenIdentityFramework.MySql.Models;

public class MySqlRequestContext : IRequestContext
{
    private MySqlConnection? _connection;
    private bool _objectDisposed;
    private MySqlTransaction? _transaction;

    public MySqlRequestContext(HttpContext httpContext, MySqlConnection connection, MySqlTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(transaction);
        HttpContext = httpContext;
        if (ReferenceEquals(connection, transaction.Connection))
        {
            throw new ArgumentException($"\"{nameof(transaction)}.{nameof(transaction.Connection)}\" used connection that differs from \"{nameof(connection)}\"", nameof(transaction));
        }

        _connection = connection;
        _transaction = transaction;
    }

    public MySqlConnection Connection => GetConnection();

    public MySqlTransaction Transaction => GetTransaction();

    public HttpContext HttpContext { get; }

    public async Task CommitAsync(CancellationToken cancellationToken)
    {
        var transaction = _transaction;
        if (transaction is not null)
        {
            await transaction.CommitAsync(cancellationToken);
            await DisposeAsync();
        }
    }

    public async Task RollbackAsync(CancellationToken cancellationToken)
    {
        var transaction = _transaction;
        if (transaction is not null)
        {
            await transaction.RollbackAsync(cancellationToken);
            await DisposeAsync();
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public async ValueTask DisposeAsync()
    {
        if (!_objectDisposed)
        {
            var transaction = _transaction;
            if (transaction is not null)
            {
                await transaction.DisposeAsync();
            }

            var connection = _connection;
            if (connection is not null)
            {
                await connection.DisposeAsync();
            }

            _connection = null;
            _transaction = null;
            _objectDisposed = true;
        }

        GC.SuppressFinalize(this);
    }

    private MySqlConnection GetConnection()
    {
        var resultConnection = _connection;
        if (resultConnection is not null && !_objectDisposed)
        {
            return resultConnection;
        }

        if (_objectDisposed)
        {
            throw new ObjectDisposedException(nameof(MySqlConnection));
        }

        throw new InvalidOperationException($"Can't get {nameof(MySqlConnection)}");
    }

    private MySqlTransaction GetTransaction()
    {
        var resultTransaction = _transaction;
        if (resultTransaction is not null && !_objectDisposed)
        {
            return resultTransaction;
        }

        if (_objectDisposed)
        {
            throw new ObjectDisposedException(nameof(MySqlTransaction));
        }

        throw new InvalidOperationException($"Can't get {nameof(MySqlTransaction)}");
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_objectDisposed)
        {
            if (disposing)
            {
                _transaction?.Dispose();
                _connection?.Dispose();
            }

            _connection = null;
            _transaction = null;
            _objectDisposed = true;
        }
    }
}
