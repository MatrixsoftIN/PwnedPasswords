using Microsoft.AspNetCore.Identity;
using System;
using System.Threading.Tasks;

namespace Matrixsoft.PwnedPasswords.AspNetCore
{
    /// <summary>
    /// Validates a password against Troy Hunt's <a href="https://haveibeenpwned.com/Passwords"/>Pwned Passwords</a> 
    /// </summary>
    public class PwnedPasswordsValidator<TUser> : IPasswordValidator<TUser> where TUser : class
    {
        private readonly PwnedPasswordsClient _client;

        public PwnedPasswordsValidator(PwnedPasswordsClient client)
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
        public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Null or whitespace password", nameof(password));
            }

            var flag = await _client.IsPasswordPwnedAsync(password);
            if (flag)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Description = "This password has previously appeared in a data breach and should never be used. If you've ever used it anywhere before, change it immediately!"
                });
            }
            else
            {
                return IdentityResult.Success;
            }
        }
    }
}
