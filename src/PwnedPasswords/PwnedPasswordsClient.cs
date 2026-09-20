using System.Security.Cryptography;
using System.Text;

namespace Matrixsoft.PwnedPasswords;

/// <summary>
/// The client consumes <a href="https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange"/>PwnedPasswords</a> API v3.
/// </summary>
public class PwnedPasswordsClient : IPwnedPasswordsClient, IDisposable
{
    internal const int HashLength = 40;
    internal const int PrefixLength = 5;
    private static readonly Uri BaseUri = new("https://api.pwnedpasswords.com");
    private readonly HttpClient _client;
    private readonly bool _ownsClient;
    private bool _disposed;

    public PwnedPasswordsClient()
        : this(new HttpClient(), ownsClient: true)
    {
    }

    public PwnedPasswordsClient(HttpClient client)
        : this(client, ownsClient: false)
    {
    }

    private PwnedPasswordsClient(HttpClient client, bool ownsClient)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _ownsClient = ownsClient;
        if (!_client.DefaultRequestHeaders.UserAgent.Any(h => string.Equals(h.Product?.Name, "Matrixsoft.PwnedPasswords", StringComparison.Ordinal)))
        {
            _client.DefaultRequestHeaders.UserAgent.ParseAdd("Matrixsoft.PwnedPasswords");
        }
    }

    /// <summary>
    /// Checks <paramref name="password"/> whether it has previously appeared in a data breach.
    /// </summary>
    /// <param name="password">The password for the user to hash and check whether it's pwned or not.</param>
    /// <returns></returns>
    public Task<bool> IsPasswordPwnedAsync(string? password) => IsPasswordPwnedAsync(password, CancellationToken.None);

    /// <summary>
    /// Checks <paramref name="password"/> whether it has previously appeared in a data breach.
    /// </summary>
    /// <param name="password">The password for the user to hash and check whether it's pwned or not.</param>
    /// <param name="cancellationToken">Token to cancel the API request.</param>
    /// <returns></returns>
    public async Task<bool> IsPasswordPwnedAsync(string? password, CancellationToken cancellationToken)
    {
#if NET6_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
#else
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("The password is null or has a whitespace.", nameof(password));
        }
#endif

        // Null was rejected above; the bang covers the netstandard2.0 leg whose
        // IsNullOrWhiteSpace contract lacks NotNullWhen for flow analysis.
        var hashedPasswordString = ComputeSha1Hex(password!);

        if (hashedPasswordString.Length != HashLength || hashedPasswordString.Length < PrefixLength)
        {
            throw new ArgumentException("The password length is not valid.", nameof(hashedPasswordString));
        }

        var (hashPrefix, hashSuffix) = SplitHash(hashedPasswordString);
#if NET5_0_OR_GREATER
        var passwordHashes = await _client.GetStringAsync(new Uri(BaseUri, $"/range/{hashPrefix}"), cancellationToken).ConfigureAwait(false);
#else
        var passwordHashes = await _client.GetStringAsync(new Uri(BaseUri, $"/range/{hashPrefix}")).ConfigureAwait(false);
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        return passwordHashes.Contains(hashSuffix, StringComparison.Ordinal);
#else
        return passwordHashes.Contains(hashSuffix);
#endif
    }

    internal static string ComputeSha1Hex(string password)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
#if NET5_0_OR_GREATER
        return Convert.ToHexString(SHA1.HashData(passwordBytes));
#else
        using var sha1 = SHA1.Create();
        return ByteArrayToString(sha1.ComputeHash(passwordBytes));
#endif
    }

    internal static (string Prefix, string Suffix) SplitHash(string hash) => (hash.Substring(0, PrefixLength), hash.Substring(PrefixLength));

#if NET5_0_OR_GREATER
    // Static SHA1.HashData is used; legacy hex helper not required.
#else
    private static string ByteArrayToString(byte[] data)
    {
        return BitConverter.ToString(data).Replace("-", "");
    }
#endif

    /// <summary>
    /// Releases all resources
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_ownsClient)
        {
            _client.Dispose();
        }

        GC.SuppressFinalize(this);
    }
}
