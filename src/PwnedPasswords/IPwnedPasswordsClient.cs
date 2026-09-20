using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("PwnedPasswords.Tests")]

namespace Matrixsoft.PwnedPasswords;

/// <summary>
/// Checks passwords against the PwnedPasswords API.
/// </summary>
public interface IPwnedPasswordsClient
{
    /// <summary>
    /// Checks <paramref name="password"/> whether it has previously appeared in a data breach.
    /// </summary>
    /// <param name="password">The password to hash and check whether it's pwned or not.</param>
    /// <param name="cancellationToken">Token to cancel the API request.</param>
    Task<bool> IsPasswordPwnedAsync(string? password, CancellationToken cancellationToken = default);
}
