using System.Security.Cryptography;
using System.Text;

namespace Matrixsoft.PwnedPasswords;

/// <summary>
/// The client consumes <a href="https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange"/>PwnedPasswords</a> API v3.
/// </summary>
public class PwnedPasswordsClient : IDisposable
{
    private const int HashLength = 40;
    private const int PrefixLength = 5;
    private static readonly Uri BaseUri = new("https://api.pwnedpasswords.com");
    private readonly HttpClient _client;
#if NET5_0_OR_GREATER
    // Static SHA1.HashData is used; no instance state required.
#else
    private readonly SHA1 _sha1;
#endif

    public PwnedPasswordsClient()
    {
        _client = new HttpClient();
        _client.DefaultRequestHeaders.UserAgent.ParseAdd("Matrixsoft.PwnedPasswords");
#if NET5_0_OR_GREATER
        // No instance state required; static SHA1.HashData is used.
#else
        _sha1 = SHA1.Create();
#endif
    }

    /// <summary>
    /// Checks <paramref name="password"/> whether it has previously appeared in a data breach.
    /// </summary>
    /// <param name="password">The password for the user to hash and check whether it's pwned or not.</param>
    /// <returns></returns>
    public async Task<bool> IsPasswordPwnedAsync(string? password)
    {
#if NET6_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
#else
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("The password is null or has a whitespace.", nameof(password));
        }
#endif

        var passwordBytes = Encoding.UTF8.GetBytes(password);
#if NET5_0_OR_GREATER
        var hashedPasswordString = Convert.ToHexString(SHA1.HashData(passwordBytes));
#else
        var hashedPassword = _sha1.ComputeHash(passwordBytes);
        var hashedPasswordString = ByteArrayToString(hashedPassword);
#endif

        if (hashedPasswordString.Length != HashLength || hashedPasswordString.Length < PrefixLength)
        {
            throw new ArgumentException("The password length is not valid.", nameof(hashedPasswordString));
        }

        var hashPrefix = hashedPasswordString.Substring(0, PrefixLength);
        var passwordHashes = await _client.GetStringAsync(new Uri(BaseUri, $"/range/{hashPrefix}")).ConfigureAwait(false);
        var hashSuffix = hashedPasswordString.Substring(PrefixLength);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        return passwordHashes.Contains(hashSuffix, StringComparison.Ordinal);
#else
        return passwordHashes.Contains(hashSuffix);
#endif
    }

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
        _client.Dispose();
#if NET5_0_OR_GREATER
        // No instance state to release; static SHA1.HashData is used.
#else
        _sha1.Dispose();
#endif
    }
}
