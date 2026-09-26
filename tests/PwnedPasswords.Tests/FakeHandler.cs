using System.Net;

namespace Matrixsoft.PwnedPasswords.Tests;

/// <summary>
/// Returns a canned response instead of hitting the network.
/// NSubstitute cannot mock protected HttpMessageHandler.SendAsync, so this hand-rolled fake is the seam.
/// </summary>
internal sealed class FakeHandler(string responseBody, HttpStatusCode statusCode = HttpStatusCode.OK) : HttpMessageHandler
{
    public HttpRequestMessage? LastRequest { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;
        return Task.FromResult(new HttpResponseMessage(statusCode) { Content = new StringContent(responseBody) });
    }
}
