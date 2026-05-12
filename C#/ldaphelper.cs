using System;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

public class LdapHelper
{
    #region Secure LDAPS Connection

    public static LdapConnection CreateSecureLdapConnection(
        string server,
        string bindDn,
        string password,
        string? trustedCertificatesDirectory = null,
        int maxRetries = 3,
        int baseDelayMs = 1000)
    {
        return CreateSecureLdapConnectionInternalAsync(server, bindDn, password, 
            trustedCertificatesDirectory, maxRetries, baseDelayMs)
            .GetAwaiter().GetResult();
    }

    public static async Task<LdapConnection> CreateSecureLdapConnectionAsync(
        string server,
        string bindDn,
        string password,
        string? trustedCertificatesDirectory = null,
        int maxRetries = 3,
        int baseDelayMs = 1000,
        CancellationToken cancellationToken = default)
    {
        return await CreateSecureLdapConnectionInternalAsync(server, bindDn, password, 
            trustedCertificatesDirectory, maxRetries, baseDelayMs, cancellationToken);
    }

    private static async Task<LdapConnection> CreateSecureLdapConnectionInternalAsync(
        string server, string bindDn, string password, string? trustedCertificatesDirectory,
        int maxRetries, int baseDelayMs, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(server))
            throw new ArgumentException("LDAP server is required", nameof(server));

        LdapException? lastException = null;

        for (int attempt = 0; attempt <= maxRetries; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LdapConnection? connection = null;

            try
            {
                var identifier = new LdapDirectoryIdentifier(server, 636, true, false);

                connection = new LdapConnection(identifier)
                {
                    AuthType = AuthType.Basic,
                    Credential = new NetworkCredential(bindDn, password)
                };

                var options = connection.SessionOptions;
                options.ProtocolVersion = 3;
                options.SecureSocketLayer = true;

                if (!string.IsNullOrWhiteSpace(trustedCertificatesDirectory) &&
                    (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()))
                {
                    options.TrustedCertificatesDirectory = trustedCertificatesDirectory;
                    options.StartNewTlsSessionContext();
                }

                await Task.Run(() => connection.Bind(), cancellationToken);
                return connection;
            }
            catch (LdapException ldapEx)
            {
                lastException = ldapEx;
                await LogAndDelayAsync(attempt, maxRetries, baseDelayMs, 
                    $"LDAP Error: {ldapEx.Message} (Code: {ldapEx.ErrorCode})", cancellationToken);
            }
            catch (TlsOperationException tlsEx)
            {
                await LogAndDelayAsync(attempt, maxRetries, baseDelayMs, 
                    $"TLS Error: {tlsEx.Message}", cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                connection?.Dispose();
                throw;
            }

            connection?.Dispose();
        }

        throw new LdapException($"Failed to connect after {maxRetries + 1} attempts.", 
            lastException?.ErrorCode ?? 0, lastException);
    }

    private static async Task LogAndDelayAsync(int attempt, int maxRetries, int baseDelayMs, 
        string errorMessage, CancellationToken cancellationToken)
    {
        Console.Error.WriteLine($"LDAP attempt {attempt + 1}/{maxRetries + 1} failed: {errorMessage}");
        if (attempt < maxRetries)
        {
            int delay = baseDelayMs * (int)Math.Pow(2, attempt);
            Console.WriteLine($"Retrying in {delay}ms...");
            await Task.Delay(delay, cancellationToken);
        }
    }

    #endregion

    #region Core Search

    public static async Task<SearchResult?> SearchUserAsync(
        LdapConnection connection,
        string searchBase,
        string filter,
        string[]? attributesToLoad = null,
        CancellationToken cancellationToken = default)
    {
        if (connection == null) throw new ArgumentNullException(nameof(connection));
        if (string.IsNullOrWhiteSpace(searchBase)) throw new ArgumentException("Search base required", nameof(searchBase));
        if (string.IsNullOrWhiteSpace(filter)) throw new ArgumentException("Filter required", nameof(filter));

        try
        {
            return await Task.Run(() =>
            {
                using var request = new SearchRequest(searchBase, filter, SearchScope.Subtree);
                if (attributesToLoad?.Length > 0)
                    request.Attributes.AddRange(attributesToLoad);

                using var response = (SearchResponse)connection.SendRequest(request);
                return response.Entries.Count > 0 ? response.Entries[0] : null;
            }, cancellationToken);
        }
        catch (LdapException ldapEx)
        {
            Console.Error.WriteLine($"LDAP Search Error [{ldapEx.ErrorCode}]: {ldapEx.Message}");
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine($"Unexpected error in SearchUserAsync: {ex}");
            throw;
        }
    }

    #endregion

    #region Specific User Lookup Helpers

    public static async Task<SearchResult?> GetUserByEmailAsync(
        LdapConnection connection,
        string searchBase,
        string email,
        string[]? attributesToLoad = null,
        CancellationToken cancellationToken = default)
    {
        return await SearchUserAsync(connection, searchBase, $"(mail={email})", attributesToLoad, cancellationToken);
    }

    public static async Task<SearchResult?> GetUserBySamAccountNameAsync(
        LdapConnection connection,
        string searchBase,
        string samAccountName,
        string[]? attributesToLoad = null,
        CancellationToken cancellationToken = default)
    {
        return await SearchUserAsync(connection, searchBase, $"(sAMAccountName={samAccountName})", attributesToLoad, cancellationToken);
    }

    public static async Task<SearchResult?> GetUserByUpnAsync(
        LdapConnection connection,
        string searchBase,
        string upn,
        string[]? attributesToLoad = null,
        CancellationToken cancellationToken = default)
    {
        return await SearchUserAsync(connection, searchBase, $"(userPrincipalName={upn})", attributesToLoad, cancellationToken);
    }

    #endregion

    #region Attribute Helpers

    public static string? GetAttributeValue(SearchResult? result, string attributeName)
    {
        if (result?.Attributes[attributeName] == null || result.Attributes[attributeName].Count == 0)
            return null;
        return result.Attributes[attributeName][0]?.ToString();
    }

    public static List<string> GetAllAttributeValues(SearchResult? result, string attributeName)
    {
        var values = new List<string>();
        if (result?.Attributes[attributeName] == null) return values;

        foreach (var value in result.Attributes[attributeName])
        {
            if (value != null)
                values.Add(value.ToString()!);
        }
        return values;
    }

    #endregion

    #region Authentication Wrapper

    public static async Task<bool> AuthenticateUserAsync(
        string server,
        string userDnOrUpn,
        string password,
        string? trustedCertificatesDirectory = null,
        CancellationToken cancellationToken = default)
    {
        LdapConnection? connection = null;
        try
        {
            connection = await CreateSecureLdapConnectionAsync(
                server: server,
                bindDn: userDnOrUpn,
                password: password,
                trustedCertificatesDirectory: trustedCertificatesDirectory,
                maxRetries: 2,
                cancellationToken: cancellationToken);

            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            connection?.Dispose();
        }
    }

    #endregion

    #region Paged Search

    public static async Task<List<SearchResult>> SearchPagedAsync(
        LdapConnection connection,
        string searchBase,
        string filter,
        string[]? attributesToLoad = null,
        int pageSize = 1000,
        SearchScope scope = SearchScope.Subtree,
        CancellationToken cancellationToken = default)
    {
        var list = new List<SearchResult>();
        await foreach (var item in SearchPagedAsAsyncEnumerable(connection, searchBase, filter, 
            attributesToLoad, pageSize, scope, cancellationToken))
        {
            list.Add(item);
        }
        return list;
    }

    public static async IAsyncEnumerable<SearchResult> SearchPagedAsAsyncEnumerable(
        LdapConnection connection,
        string searchBase,
        string filter,
        string[]? attributesToLoad = null,
        int pageSize = 1000,
        SearchScope scope = SearchScope.Subtree,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (connection == null) throw new ArgumentNullException(nameof(connection));
        if (string.IsNullOrWhiteSpace(searchBase)) throw new ArgumentException("Search base required", nameof(searchBase));
        if (string.IsNullOrWhiteSpace(filter)) throw new ArgumentException("Filter required", nameof(filter));

        byte[]? cookie = null;

        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using var request = new SearchRequest(searchBase, filter, scope);
                if (attributesToLoad?.Length > 0)
                    request.Attributes.AddRange(attributesToLoad);

                var pageControl = new PageResultRequestControl(pageSize) { Cookie = cookie ?? Array.Empty<byte>() };
                request.Controls.Add(pageControl);

                var response = await Task.Run(() => 
                    (SearchResponse)connection.SendRequest(request), cancellationToken);

                foreach (SearchResult entry in response.Entries)
                    yield return entry;

                cookie = null;
                foreach (DirectoryControl ctrl in response.Controls)
                {
                    if (ctrl is PageResultResponseControl prc)
                    {
                        cookie = prc.Cookie;
                        break;
                    }
                }

                if (cookie == null || cookie.Length == 0)
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in paged search: {ex.Message}");
            throw;
        }
    }
}
