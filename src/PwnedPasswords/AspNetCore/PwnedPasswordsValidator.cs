using Microsoft.AspNetCore.Identity;

namespace Matrixsoft.PwnedPasswords.AspNetCore;

/// <summary>
/// Validates a password against Troy Hunt's <a href="https://haveibeenpwned.com/Passwords"/>Pwned Passwords</a>
/// </summary>
public class PwnedPasswordsValidator<TUser> : IPasswordValidator<TUser> where TUser : class
{
    private readonly IPwnedPasswordsClient _client;

    public PwnedPasswordsValidator(PwnedPasswordsClient client)
        : this((IPwnedPasswordsClient)client)
    {
    }

    public PwnedPasswordsValidator(IPwnedPasswordsClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    /// <summary>
    /// Validates <paramref name="password"/> as an asynchronous operation.
    /// </summary>
    /// <param name="manager"></param>
    /// <param name="user"></param>
    /// <param name="password">The password supplied for validation</param>
    /// <returns></returns>
    public Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string? password) => ValidateAsync(manager, user, password, CancellationToken.None);

    /// <summary>
    /// Validates <paramref name="password"/> as an asynchronous operation.
    /// </summary>
    /// <param name="manager"></param>
    /// <param name="user"></param>
    /// <param name="password">The password supplied for validation</param>
    /// <param name="cancellationToken">Token to cancel the API request.</param>
    /// <returns></returns>
    public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string? password, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("The password is null or has a whitespace.", nameof(password));
        }

        var flag = await _client.IsPasswordPwnedAsync(password, cancellationToken).ConfigureAwait(false);

        return flag
            ? IdentityResult.Failed(new IdentityError
            {
                Code = "PasswordPwned",
                Description = "This password has previously appeared in a data breach and should never be used. If you've ever used it anywhere before, change it!"
            })
            : IdentityResult.Success;
    }
}