using System;
using System.IO;
using System.Text.Json;

namespace Dragonhill.SlimSSH.Tests;

public sealed class TestSettings
{
    public static readonly TestSettings Global;

    private readonly Lazy<string> _sshHost;
    private readonly Lazy<ushort> _sshPort;
    private readonly Lazy<string> _hostEd25519PublicKey;
    private readonly Lazy<string> _hostRsaPublicKey;
    private readonly Lazy<string> _clientEd25519PrivateKey;
    private readonly Lazy<string> _clientRsaPrivateKey;

    public string SshHost => _sshHost.Value;
    public ushort SshPort => _sshPort.Value;
    public string? HostEd25519PublicKey => _hostEd25519PublicKey.Value;
    public string? HostRsaPublicKey => _hostRsaPublicKey.Value;
    public string? ClientEd25519PrivateKey => _clientEd25519PrivateKey.Value;
    public string? ClientRsaPrivateKey => _clientRsaPrivateKey.Value;

    static TestSettings()
    {
        Global = new TestSettings();
    }

    private static string Key(string envName, Lazy<string> basePath, string relPath)
    {
        var env = Environment.GetEnvironmentVariable(envName);

        if (env != null)
        {
            return env;
        }

        var path = Path.Join(basePath.Value, relPath);

        try
        {
            return File.ReadAllText(path);
        }
        catch
        {
            throw new InvalidOperationException($"Could not read key from '{path}'");
        }
    }

    private TestSettings()
    {
        Lazy<string> devopsDir = new(() => Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "../../../../../devops")));

        Lazy<IntegrationTestSettingsDto> integrationTestSettings = new(() =>
        {
            var path = Path.Combine(devopsDir.Value, "integration-test-settings.json");
            var jsonBytes = File.ReadAllBytes(path);
            return JsonSerializer.Deserialize<IntegrationTestSettingsDto>(jsonBytes) ?? throw new InvalidOperationException($"Could not deserialize integration test settings from '{path}'");
        });

        _sshHost = new Lazy<string>(() => Environment.GetEnvironmentVariable("SLIM_SSH_TESTS_SSH_HOST") ?? integrationTestSettings.Value.Host);

        _sshPort = new Lazy<ushort>(() => ushort.TryParse(Environment.GetEnvironmentVariable("SLIM_SSH_TESTS_SSH_PORT"), out var sshPort) ? sshPort : integrationTestSettings.Value.Port);

        Lazy<string> localDataDir = new(() => Path.Combine(devopsDir.Value, ".local"));

        _hostEd25519PublicKey = new Lazy<string>(() => Key("SLIM_SSH_TESTS_SERVER_ED25519_PUB", localDataDir, "server-keys/ssh_host_ed25519_key.pub"));
        _hostRsaPublicKey = new Lazy<string>(() => Key("SLIM_SSH_TESTS_SERVER_RSA_PUB", localDataDir, "server-keys/ssh_host_rsa_key.pub"));

        _clientEd25519PrivateKey = new Lazy<string>(() => Key("SLIM_SSH_TESTS_CLIENT_ED25519", localDataDir, "client/id_ed25519"));
        _clientRsaPrivateKey = new Lazy<string>(() => Key("SLIM_SSH_TESTS_CLIENT_RSA", localDataDir, "client/id_rsa"));
    }
}
