using Microsoft.AspNetCore.Identity;

namespace Matrixsoft.PwnedPasswords.AspNetCore
{
    /// <summary>
    /// Identity extensions for <see cref="IdentityBuilder"/>.
    /// </summary>
    public static class BuilderExtensions
    {
        /// <summary>
        /// Adds <see cref="PwnedPasswordValidator"/> for ASP.NET Core 2.x apps.
        /// </summary>
        /// <typeparam name="TUser"></typeparam>
        /// <param name="builder">The <see cref="IdentityBuilder"/>instance this method extends.</param>
        /// <returns>The <see cref="IdentityBuilder"/>instance this method extends.</returns>
        public static IdentityBuilder AddPwnedPasswordsValidator<TUser>(this IdentityBuilder builder) where TUser : class
        {
            return builder.AddPasswordValidator<PwnedPasswordsValidator<TUser>>();
        }
    }
}
