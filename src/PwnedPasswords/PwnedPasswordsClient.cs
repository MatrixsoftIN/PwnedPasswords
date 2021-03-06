﻿using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Matrixsoft.PwnedPasswords
{
    /// <summary>
    /// The client consumes <a href="https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange"/>PwnedPasswords</a> API v3.
    /// </summary>
    public class PwnedPasswordsClient : IDisposable
    {
        private const string _baseUri = "https://api.pwnedpasswords.com";
        private readonly HttpClient _client;
        private readonly SHA1 _sha1;

        public PwnedPasswordsClient()
        {
            _client = new HttpClient();
            _sha1 = SHA1.Create();
        }

        /// <summary>
        /// Checks <paramref name="password"/> whether it has previously appeared in a data breach.
        /// </summary>
        /// <param name="password">The password for the user to hash and check whether it's pwned or not.</param>
        /// <returns></returns>
        public async Task<bool> IsPasswordPwnedAsync(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("The password is null or has a whitespace.", nameof(password));
            }

            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var hashedPassword = _sha1.ComputeHash(passwordBytes);
            var hashedPasswordString = ByteArrayToString(hashedPassword);

            if (hashedPasswordString.Length != 40 || hashedPasswordString.Length < 5)
            {
                throw new ArgumentException("The password length is not valid.", nameof(hashedPasswordString));
            }

            var hashPrefix = hashedPasswordString.Substring(0, 5);
            var passwordHashes = await _client.GetStringAsync($"{_baseUri}/range/{hashPrefix}");
            var hashSuffix = hashedPasswordString.Substring(5);

            return passwordHashes.Contains(hashSuffix);
        }

        #region Helpers
        private static string ByteArrayToString(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", "");
        }
        #endregion
        
        /// <summary>
        /// Releases all resources
        /// </summary>
        public void Dispose()
        {
            _client.Dispose();
            _sha1.Dispose();
        }
    }
}