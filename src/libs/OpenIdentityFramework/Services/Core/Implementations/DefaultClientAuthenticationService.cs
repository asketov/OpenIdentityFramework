using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using OpenIdentityFramework.Configuration.Options;
using OpenIdentityFramework.Constants;
using OpenIdentityFramework.Constants.Request;
using OpenIdentityFramework.Models;
using OpenIdentityFramework.Models.Configuration;
using OpenIdentityFramework.Services.Core.Models.ClientAuthenticationService;
using OpenIdentityFramework.Services.Static.SyntaxValidation;

namespace OpenIdentityFramework.Services.Core.Implementations;

public class DefaultClientAuthenticationService<TRequestContext, TClient, TClientSecret>
    : IClientAuthenticationService<TRequestContext, TClient, TClientSecret>
    where TRequestContext : AbstractRequestContext
    where TClient : AbstractClient<TClientSecret>
    where TClientSecret : AbstractSecret
{
    protected static readonly ClientAuthenticationResult<TClient, TClientSecret> NotAuthenticated = new();
    protected static readonly ClientAuthenticationResult<TClient, TClientSecret> MultipleAuthorizeHeader = new($"Multiple \"{HeaderNames.Authorization}\" headers are present");
    protected static readonly ClientAuthenticationResult<TClient, TClientSecret> InvalidAuthorizeHeader = new($"Invalid \"{HeaderNames.Authorization}\" header value");
    protected static readonly ClientAuthenticationResult<TClient, TClientSecret> MissingClientId = new($"\"{ClientAuthenticationParameters.ClientId}\" is missing");
    protected static readonly ClientAuthenticationResult<TClient, TClientSecret> ClientIdIsTooLong = new($"\"{ClientAuthenticationParameters.ClientId}\" is too long");
    protected static readonly ClientAuthenticationResult<TClient, TClientSecret> ClientSecretIsTooLong = new($"\"{ClientAuthenticationParameters.ClientSecret}\" is too long");
    protected static readonly ClientAuthenticationResult<TClient, TClientSecret> InvalidClientIdSyntax = new($"Invalid \"{ClientAuthenticationParameters.ClientId}\" syntax");
    protected static readonly ClientAuthenticationResult<TClient, TClientSecret> UnknownOrDisabledClient = new("Unknown or disabled client");
    protected static readonly ClientAuthenticationResult<TClient, TClientSecret> InvalidAuthenticationMethod = new("Invalid authentication method");
    protected static readonly ClientAuthenticationResult<TClient, TClientSecret> MultipleClientId = new($"Multiple \"{ClientAuthenticationParameters.ClientId}\" values are present, but only one is allowed");
    protected static readonly ClientAuthenticationResult<TClient, TClientSecret> MissingClientSecret = new($"\"{ClientAuthenticationParameters.ClientSecret}\" is missing");
    protected static readonly ClientAuthenticationResult<TClient, TClientSecret> MultipleClientSecret = new($"Multiple \"{ClientAuthenticationParameters.ClientSecret}\" values are present, but only one is allowed");

    public DefaultClientAuthenticationService(
        OpenIdentityFrameworkOptions frameworkOptions,
        IClientService<TRequestContext, TClient, TClientSecret> clients,
        IClientSecretValidator<TRequestContext, TClient, TClientSecret> secretValidator)
    {
        ArgumentNullException.ThrowIfNull(frameworkOptions);
        ArgumentNullException.ThrowIfNull(clients);
        ArgumentNullException.ThrowIfNull(secretValidator);
        FrameworkOptions = frameworkOptions;
        Clients = clients;
        SecretValidator = secretValidator;
    }

    protected OpenIdentityFrameworkOptions FrameworkOptions { get; }
    protected IClientService<TRequestContext, TClient, TClientSecret> Clients { get; }
    protected IClientSecretValidator<TRequestContext, TClient, TClientSecret> SecretValidator { get; }

    public virtual async Task<ClientAuthenticationResult<TClient, TClientSecret>> AuthenticateAsync(
        TRequestContext requestContext,
        IFormCollection form,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(form);
        cancellationToken.ThrowIfCancellationRequested();
        var basicResult = await AuthenticateUsingHttpBasicSchemeAsync(requestContext, cancellationToken);
        if (basicResult.IsAuthenticated)
        {
            return new(basicResult.Client, basicResult.ClientAuthenticationMethod);
        }

        if (basicResult.HasError)
        {
            return basicResult;
        }

        var noneOrPostResult = await ClientSecretPostOrNoneAsync(requestContext, form, cancellationToken);
        if (noneOrPostResult.IsAuthenticated)
        {
            return new(noneOrPostResult.Client, noneOrPostResult.ClientAuthenticationMethod);
        }

        if (noneOrPostResult.HasError)
        {
            return noneOrPostResult;
        }

        return new();
    }

    protected virtual async Task<ClientAuthenticationResult<TClient, TClientSecret>> AuthenticateUsingHttpBasicSchemeAsync(
        TRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        cancellationToken.ThrowIfCancellationRequested();
        if (!requestContext.HttpContext.Request.Headers.TryGetValue(HeaderNames.Authorization, out var authorizationHeaderValues))
        {
            return NotAuthenticated;
        }

        if (authorizationHeaderValues.Count != 1)
        {
            return MultipleAuthorizeHeader;
        }

        var authorizationHeader = authorizationHeaderValues.ToString();

        // https://datatracker.ietf.org/doc/html/rfc7617#section-2
        // Note that both scheme and parameter names are matched case-insensitively.
        if (!authorizationHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return NotAuthenticated;
        }

        // https://datatracker.ietf.org/doc/html/rfc7617#section-2
        if (!HttpBasicCredentialsSyntaxValidator.IsValid(authorizationHeader.AsSpan(6)))
        {
            return InvalidAuthorizeHeader;
        }

        if (!TryParseBasicClientIdAndSecret(authorizationHeader.AsSpan(6), out var clientId, out var clientSecret))
        {
            return InvalidAuthorizeHeader;
        }

        if (string.IsNullOrEmpty(clientId))
        {
            return MissingClientId;
        }

        if (clientId.Length > FrameworkOptions.InputLengthRestrictions.ClientId)
        {
            return ClientIdIsTooLong;
        }

        if (clientSecret.Length > FrameworkOptions.InputLengthRestrictions.ClientSecret)
        {
            return ClientSecretIsTooLong;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.1
        // "client_id" syntax validation
        if (!ClientIdSyntaxValidator.IsValid(clientId))
        {
            return InvalidClientIdSyntax;
        }

        var client = await Clients.FindAsync(requestContext, clientId, cancellationToken);
        if (client == null)
        {
            return UnknownOrDisabledClient;
        }

        if (client.GetAuthenticationMethod() != DefaultClientAuthenticationMethods.ClientSecretBasic)
        {
            return InvalidAuthenticationMethod;
        }

        if (await SecretValidator.IsValidPreSharedSecret(requestContext, client, clientSecret, cancellationToken))
        {
            return new(client, DefaultClientAuthenticationMethods.ClientSecretBasic);
        }

        return UnknownOrDisabledClient;
    }

    protected virtual bool TryParseBasicClientIdAndSecret(
        ReadOnlySpan<char> encodedCredentials,
        [NotNullWhen(true)] out string? clientId,
        [NotNullWhen(true)] out string? clientSecret)
    {
        const int maxStackallocBytesCount = 1024;
        const int maxStackallocCharsCount = 512;

        if (encodedCredentials.Length == 0)
        {
            clientId = null;
            clientSecret = null;
            return false;
        }

        var decodedCredentialsBufferSize = (encodedCredentials.Length >> 2) * 3;
        byte[]? decodedCredentialsBufferFromPool = null;
        var decodedCredentialsBuffer = decodedCredentialsBufferSize <= maxStackallocBytesCount
            ? stackalloc byte[maxStackallocBytesCount]
            : decodedCredentialsBufferFromPool = ArrayPool<byte>.Shared.Rent(decodedCredentialsBufferSize);
        try
        {
            if (Convert.TryFromBase64Chars(encodedCredentials, decodedCredentialsBuffer, out var base64BytesCount))
            {
                var textBufferSize = Encoding.UTF8.GetMaxCharCount(base64BytesCount);
                char[]? textBufferFromPool = null;
                var textBuffer = textBufferSize <= maxStackallocCharsCount
                    ? stackalloc char[maxStackallocCharsCount]
                    : textBufferFromPool = ArrayPool<char>.Shared.Rent(textBufferSize);
                try
                {
                    var charsCount = Encoding.UTF8.GetChars(decodedCredentialsBuffer[..base64BytesCount], textBuffer);
                    var loginPassword = textBuffer[..charsCount];
                    // https://datatracker.ietf.org/doc/html/rfc7617#section-2 text after the first colon is part of the password
                    int divideIndex;
                    if ((divideIndex = loginPassword.IndexOf(':')) > -1 && divideIndex + 1 < loginPassword.Length)
                    {
                        var clientIdSpan = loginPassword[..divideIndex];
                        var clientSecretSpan = loginPassword[(divideIndex + 1)..loginPassword.Length];
                        if (IsNonCtl(clientIdSpan) && IsNonCtl(clientSecretSpan))
                        {
                            clientId = new(clientIdSpan);
                            clientSecret = new(clientSecretSpan);
                            return true;
                        }
                    }
                }
                finally
                {
                    if (textBufferFromPool is not null)
                    {
                        ArrayPool<char>.Shared.Return(textBufferFromPool, true);
                    }
                    else
                    {
                        textBuffer.Clear();
                    }
                }
            }
        }
        finally
        {
            if (decodedCredentialsBufferFromPool is not null)
            {
                ArrayPool<byte>.Shared.Return(decodedCredentialsBufferFromPool, true);
            }
            else
            {
                decodedCredentialsBuffer.Clear();
            }
        }

        clientId = null;
        clientSecret = null;
        return false;

        // https://datatracker.ietf.org/doc/html/rfc7617#section-2
        // The user-id and password MUST NOT contain any control characters (see "CTL" in Appendix B.1 of [RFC5234]).
        // https://datatracker.ietf.org/doc/html/rfc5234#appendix-B.1
        // CTL = %x00-1F / %x7F
        static bool IsNonCtl(ReadOnlySpan<char> value)
        {
            foreach (var ch in value)
            {
                if (ch <= 0x1f || ch == 0x7f)
                {
                    return false;
                }
            }

            return true;
        }
    }

    protected virtual async Task<ClientAuthenticationResult<TClient, TClientSecret>> ClientSecretPostOrNoneAsync(
        TRequestContext requestContext,
        IFormCollection form,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        cancellationToken.ThrowIfCancellationRequested();
        if (!form.TryGetValue(ClientAuthenticationParameters.ClientId, out var clientIdValues))
        {
            return NotAuthenticated;
        }

        if (clientIdValues.Count != 1)
        {
            return MultipleClientId;
        }

        var clientId = clientIdValues.ToString();
        if (string.IsNullOrEmpty(clientId))
        {
            return MissingClientId;
        }

        if (clientId.Length > FrameworkOptions.InputLengthRestrictions.ClientId)
        {
            return ClientIdIsTooLong;
        }

        // https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-08.html#appendix-A.1
        // "client_id" syntax validation
        if (!ClientIdSyntaxValidator.IsValid(clientId))
        {
            return InvalidClientIdSyntax;
        }

        var client = await Clients.FindAsync(requestContext, clientId, cancellationToken);
        if (client == null)
        {
            return UnknownOrDisabledClient;
        }

        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.1
        // If the Client is a Confidential Client, then it MUST authenticate to the Token Endpoint using the authentication method registered for its client_id.
        // => Non public clients should perform authentication
        var clientType = client.GetClientType();
        var clientAuthenticationMethod = client.GetAuthenticationMethod();
        if (clientType == DefaultClientTypes.Public)
        {
            if (clientAuthenticationMethod == DefaultClientAuthenticationMethods.None)
            {
                return new(client, DefaultClientAuthenticationMethods.None);
            }
        }

        if (clientAuthenticationMethod != DefaultClientAuthenticationMethods.ClientSecretPost)
        {
            return InvalidAuthenticationMethod;
        }

        if (!form.TryGetValue(ClientAuthenticationParameters.ClientSecret, out var clientSecretValues))
        {
            return MissingClientSecret;
        }

        if (clientSecretValues.Count != 1)
        {
            return MultipleClientSecret;
        }

        var clientSecret = clientSecretValues.ToString();

        if (clientSecret.Length > FrameworkOptions.InputLengthRestrictions.ClientSecret)
        {
            return ClientSecretIsTooLong;
        }

        if (await SecretValidator.IsValidPreSharedSecret(requestContext, client, clientSecret, cancellationToken))
        {
            return new(client, DefaultClientAuthenticationMethods.ClientSecretPost);
        }

        return UnknownOrDisabledClient;
    }
}
