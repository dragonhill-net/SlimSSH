using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.TestHelpers;
using FluentAssertions;
using System;
using System.Threading.Tasks;
using Xunit;

namespace Dragonhill.SlimSSH.IO;

public class SshConnectionBaseTests
{
    [Fact]
    public async Task TestWithMockedStream()
    {
        var instance = new TestSshConnection().SendServerVersion(true);

        // The IsClosed property should be false before Connect has been called, not much use but ensure consistency
        instance.IsClosed.Should().BeFalse();

        var connectTask = instance.Connect();

        instance.SendServerVersion(false);

        await connectTask;

        instance.IsClosed.Should().BeFalse();

        instance.ServerVersion.Should().NotBeNull();
        instance.ServerVersion!.SoftwareVersion.Should().Be($"{Constants.VersionName}_{TestSshConnection.Version.Replace('-', '_')}");
        instance.ServerVersion!.Comment.Should().Be(TestSshConnection.Comment);

        instance.CloseServer();

        await instance.WaitClose(TimeSpan.FromHours(1));

        instance.IsClosed.Should().BeTrue();
    }

    [Fact]
    public async Task WaitCloseBeforeConnect()
    {
        var instance = new TestSshConnection();

        await FluentActions.Awaiting(() => instance.WaitClose())
            .Should()
            .ThrowAsync<SshException>()
            .WithMessage(Strings.SshConnectionBase_NotStarted);
    }

    [Fact]
    public async Task CloseConnectionBeforeVersionIsSent()
    {
        var instance = new TestSshConnection().SendServerVersion(true);

        var connectTask = instance.Connect();

        instance.CloseServer();

        await FluentActions.Awaiting(() => connectTask)
            .Should()
            .ThrowAsync<SshException>()
            .WithMessage(Strings.SshConnectionBase_ClosedUnexpectedly);
    }

    [Fact]
    public async Task ConnectCalledTwice()
    {
        var instance = new TestSshConnection().SendServerVersion(true);

        var _ = instance.Connect(); //Intentionally not waiting for connect

        await FluentActions.Awaiting(() => instance.Connect())
            .Should()
            .ThrowAsync<SshException>()
            .WithMessage(Strings.SshConnectionBase_ConnectCalledTwice);

        instance.Abort();
    }

    [Fact]
    public async Task ConnectTimeout()
    {
        var instance = new TestSshConnection().SendServerVersion(true);

        await FluentActions.Awaiting(() => instance.Connect(TimeSpan.Zero))
            .Should()
            .ThrowAsync<TimeoutException>();
    }

    [Fact]
    public async Task ServerSendsInvalidSshVersion()
    {
        var instance = new TestSshConnection().SendInvalidSshVersion();

        await FluentActions.Awaiting(() => instance.Connect())
            .Should()
            .ThrowAsync<SshException>()
            .WithMessage(Strings.ProtocolVersionExchange_InvalidVersion);
    }
}
