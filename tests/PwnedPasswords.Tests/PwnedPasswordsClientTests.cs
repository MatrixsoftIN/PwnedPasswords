using System.Net;

using Xunit;

namespace Matrixsoft.PwnedPasswords.Tests;

public class PwnedPasswordsClientTests
{
    private const string KnownPassword = "password";
    private const string KnownHash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
    private const string KnownPrefix = "5BAA6";
    private const string KnownSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    [Fact]
    public void ComputeSha1Hex_KnownPassword_ReturnsUppercaseVector()
    {
        Assert.Equal(KnownHash, PwnedPasswordsClient.ComputeSha1Hex(KnownPassword));
    }

    [Fact]
    public void SplitHash_KnownHash_ReturnsPrefixAndSuffix()
    {
        var (prefix, suffix) = PwnedPasswordsClient.SplitHash(KnownHash);

        Assert.Equal(KnownPrefix, prefix);
        Assert.Equal(KnownSuffix, suffix);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task IsPasswordPwnedAsync_NullOrWhitespace_ThrowsArgumentException(string? password)
    {
        using var sut = new PwnedPasswordsClient(new HttpClient(new FakeHandler(string.Empty)));

        // ThrowsAny: netstandard2.0 throws ArgumentException; net8+ throws
        // ArgumentNullException (a subclass) for null via ThrowIfNullOrWhiteSpace.
        var ex = await Assert.ThrowsAnyAsync<ArgumentException>(() => sut.IsPasswordPwnedAsync(password));

        Assert.Equal("password", ex.ParamName);
    }

    [Fact]
    public async Task IsPasswordPwnedAsync_SuffixPresent_ReturnsTrueAndQueriesPrefix()
    {
        var handler = new FakeHandler($"003D68A0D1C9279D7D4C803D8A9F96A477D86:2\r\n{KnownSuffix}:5\r\n");
        using var sut = new PwnedPasswordsClient(new HttpClient(handler));

        var result = await sut.IsPasswordPwnedAsync(KnownPassword);

        Assert.True(result);
        Assert.NotNull(handler.LastRequest);
        Assert.EndsWith($"/range/{KnownPrefix}", handler.LastRequest!.RequestUri!.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task IsPasswordPwnedAsync_SuffixAbsent_ReturnsFalse()
    {
        var handler = new FakeHandler("003D68A0D1C9279D7D4C803D8A9F96A477D86:2\r\n00A5E1D4D04934CBB56C1AED45B8D8EA7D7C:1\r\n");
        using var sut = new PwnedPasswordsClient(new HttpClient(handler));

        var result = await sut.IsPasswordPwnedAsync(KnownPassword);

        Assert.False(result);
    }

    [Fact]
    public async Task Dispose_IsIdempotent_AndKeepsSharedHttpClientAlive()
    {
        var handler = new FakeHandler("empty");
        var httpClient = new HttpClient(handler);
        var sut = new PwnedPasswordsClient(httpClient);

        sut.Dispose();
        sut.Dispose();

        using var response = await httpClient.GetAsync("http://localhost/range/5BAA6");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(handler.LastRequest);
    }
}