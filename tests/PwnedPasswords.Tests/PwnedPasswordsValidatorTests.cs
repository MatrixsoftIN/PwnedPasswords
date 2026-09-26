using Matrixsoft.PwnedPasswords.AspNetCore;
using NSubstitute;
using Xunit;

namespace Matrixsoft.PwnedPasswords.Tests;

public sealed class TestUser;

public class PwnedPasswordsValidatorTests
{
    [Fact]
    public void Ctor_NullClient_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new PwnedPasswordsValidator<TestUser>((PwnedPasswordsClient)null!));
        Assert.Throws<ArgumentNullException>(() => new PwnedPasswordsValidator<TestUser>((IPwnedPasswordsClient)null!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ValidateAsync_NullOrWhitespace_ThrowsArgumentException(string? password)
    {
        var client = Substitute.For<IPwnedPasswordsClient>();
        var sut = new PwnedPasswordsValidator<TestUser>(client);

        // ThrowsAny: see client tests for the null-type nuance.
        var ex = await Assert.ThrowsAnyAsync<ArgumentException>(() => sut.ValidateAsync(null!, null!, password));

        Assert.Equal("password", ex.ParamName);
    }

    [Fact]
    public async Task ValidateAsync_PwnedPassword_ReturnsFailedWithContractValues()
    {
        var client = Substitute.For<IPwnedPasswordsClient>();
        client.IsPasswordPwnedAsync(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(true);
        var sut = new PwnedPasswordsValidator<TestUser>(client);

        var result = await sut.ValidateAsync(null!, null!, "password");

        Assert.False(result.Succeeded);
        var error = Assert.Single(result.Errors);
        Assert.Equal("PasswordPwned", error.Code);
        Assert.Equal("This password has previously appeared in a data breach and should never be used. If you've ever used it anywhere before, change it!", error.Description);
    }

    [Fact]
    public async Task ValidateAsync_CleanPassword_ReturnsSuccess()
    {
        var client = Substitute.For<IPwnedPasswordsClient>();
        client.IsPasswordPwnedAsync(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(false);
        var sut = new PwnedPasswordsValidator<TestUser>(client);

        var result = await sut.ValidateAsync(null!, null!, "a-clean-unique-password-123!");

        Assert.True(result.Succeeded);
    }
}
