using Dragonhill.SlimSSH.Tests;
using FluentAssertions;
using System;
using System.Threading.Tasks;
using Xunit;

namespace Dragonhill.SlimSSH.IO;

public class TcpSshClientConnectionTests
{
    [Fact]
    public async Task Connect()
    {
        var settings = TestSettings.Global;

        var connection = new TcpSshClientConnection(settings.SshHost, settings.SshPort);

        await connection.Connect(TimeSpan.FromMinutes(1));

        connection.ServerVersion.Should().NotBeNull();

        connection.ServerVersion!.SoftwareVersion.Should().Contain("OpenSSH");
        connection.ServerVersion!.Comment.Should().Contain("Debian");
    }

    [Fact]
    public async Task ConnectTimeout()
    {
        var settings = TestSettings.Global;

        var connection = new TcpSshClientConnection(settings.SshHost, settings.SshPort);

        await FluentActions.Awaiting(() => connection.Connect(TimeSpan.Zero))
            .Should()
            .ThrowAsync<TimeoutException>();
    }
}
