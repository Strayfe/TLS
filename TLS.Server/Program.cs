using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using McMaster.Extensions.CommandLineUtils;
using Serilog;
using Serilog.Events;

namespace TLS.Server
{
    [Command(Description = "A server applet that listens for incoming socket connections to test TLS.")]
    [HelpOption("-?")]
    internal class Program
    {
        [Option("-cf|--certFile", Description = "The machine certificate to be used to create a secure channel. " +
                                                "Defaults to example cert included in the build.")]
        private string CertificateFile { get; } = Path.Combine(Environment.CurrentDirectory, "example.pfx");

        [Option("-cp|--certPass", Description = "The password to open an encrypted machine certificate.")]
        private string CertificatePassword { get; } = "test1234";

        [Option("-ct|--certThumbprint",
            Description = "The thumbprint of the certificate to fetch from the cert store, windows only for now.")]
        private string CertificateThumbprint { get; } = null;

        [Option("-sn|--storeName",
            Description =
                "The name of the certificate store to lookup a certificate thumbprint in, windows only for now, defaults to [My].")]
        private StoreName StoreName { get; } = StoreName.My;

        [Option("-sl|--storeLocation",
            Description =
                "The location of the certificate store to lookup a certificate thumbprint in, windows only for now, defaults to [CurrentUser].")]
        private StoreLocation StoreLocation { get; } = StoreLocation.CurrentUser;

        [Option("-p|--port", Description = "The port to communicate via. Defaults to 443.")]
        private int Port { get; } = 4433;

        [Option("-l|--logEventLevel",
            Description = "The verbosity of the output from the app processing. Defaults to [Information]")]
        private LogEventLevel LogEventLevel { get; } = LogEventLevel.Information;

        private static X509Certificate _certificate;

        private static async Task<int> Main(string[] args) =>
            await CommandLineApplication.ExecuteAsync<Program>(args);

        private async Task<int> OnExecuteAsync(CommandLineApplication app,
            CancellationToken cancellationToken = default)
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Is(LogEventLevel)
                .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
                .Enrich.FromLogContext()
                .WriteTo.Console()
                .CreateLogger();

            try
            {
                Log.Information("Starting up...\n");

                await CreateTlsServerAsync(app, cancellationToken);
            }
            catch (Exception e)
            {
                Log.Fatal(e, "Host terminated unexpectedly");
                return 0;
            }
            finally
            {
                Log.CloseAndFlush();
            }

            return 1;
        }

        private async Task CreateTlsServerAsync(CommandLineApplication app,
            CancellationToken cancellationToken = default)
        {
            if (!string.IsNullOrWhiteSpace(CertificateThumbprint))
            {
                var store = new X509Store(StoreName, StoreLocation);
                store.Open(OpenFlags.ReadOnly);
                var certCollection =
                    store.Certificates.Find(X509FindType.FindByThumbprint, CertificateThumbprint, false);
                if (certCollection.Count > 0)
                {
                    Log.Verbose("Found [{@certs}] in store [{@store}] location [{@location}]", 
                        certCollection.Count, StoreName, StoreLocation);
                    _certificate = certCollection[0];
                }
                else
                {
                    Log.Verbose("Unable to find the certificate in the specified store.");
                }
            }

            if (_certificate == null && !string.IsNullOrWhiteSpace(CertificateFile))
            {
                _certificate = new X509Certificate(CertificateFile, CertificatePassword);
            }
            
            if (_certificate == null)
            {
                Log.Error("Unable to load certificate, please provide a valid certificate");
                app.ShowHelp();
                return;
            }

            Log.Verbose("Certificate loaded: {@certificate}\n", _certificate);

            var listener = new TcpListener(IPAddress.Any, Port);
            listener.Start();

            while (true)
            {
                Log.Information("Waiting for a client to connect...");
                var client = await listener.AcceptTcpClientAsync();
                await ProcessClientConnectionAsync(client, cancellationToken);
            }
        }

        private static async Task ProcessClientConnectionAsync(TcpClient client,
            CancellationToken cancellationToken = default)
        {
            var sslStream = new SslStream(client.GetStream(), false);

            try
            {
                await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _certificate,
                    ClientCertificateRequired = false,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, cancellationToken);

                DisplaySecurityLevel(sslStream);
                DisplaySecurityServices(sslStream);
                DisplayCertificateInformation(sslStream);
                DisplayStreamProperties(sslStream);
            }
            catch (Exception e)
            {
                Log.Information("Exception: [{0}]", e.Message);
                if (e.InnerException != null)
                {
                    Log.Information("Inner exception: [{0}]", e.InnerException.Message);
                }

                Log.Information("Authentication failed - closing the connection.\n");
            }
            finally
            {
                sslStream.Close();
                client.Close();
            }
        }

        private static void DisplaySecurityLevel(SslStream stream)
        {
            Log.Verbose("Security Details");
            Log.Verbose("Cipher: [{0}] strength [{1}]", stream.CipherAlgorithm, stream.CipherStrength);
            Log.Verbose("Hash: [{0}] strength [{1}]", stream.HashAlgorithm, stream.HashStrength);
            Log.Verbose("Key exchange: [{0}] strength [{1}]", stream.KeyExchangeAlgorithm,
                stream.KeyExchangeStrength);
            Log.Verbose("Protocol: [{0}]\n", stream.SslProtocol);
        }

        private static void DisplaySecurityServices(AuthenticatedStream stream)
        {
            Log.Verbose("Authentication Details");
            Log.Verbose("Authenticated: [{0}]", stream.IsAuthenticated);
            Log.Verbose("As Server: [{0}]", stream.IsServer);
            Log.Verbose("Signed: [{0}]", stream.IsSigned);
            Log.Verbose("Encrypted: [{0}]\n", stream.IsEncrypted);
        }

        private static void DisplayStreamProperties(Stream stream)
        {
            Log.Verbose("Stream Details");
            Log.Verbose("Can Read: [{0}]", stream.CanRead);
            Log.Verbose("Can Write: [{0}]", stream.CanWrite);
            Log.Verbose("Can Timeout: [{0}]\n", stream.CanTimeout);
        }

        private static void DisplayCertificateInformation(SslStream stream)
        {
            Log.Verbose("Certificate Details");
            Log.Verbose("Certificate revocation list checked: [{0}]", stream.CheckCertRevocationStatus);

            var localCertificate = stream.LocalCertificate;
            if (stream.LocalCertificate != null)
            {
                Log.Verbose("Local cert was issued to [{0}] and is valid from [{1}] until [{2}].",
                    localCertificate.Subject,
                    localCertificate.GetEffectiveDateString(),
                    localCertificate.GetExpirationDateString());
            }
            else
            {
                Log.Verbose("Local certificate is null.");
            }

            // Display the properties of the client's certificate.
            var remoteCertificate = stream.RemoteCertificate;
            if (stream.RemoteCertificate != null)
            {
                Log.Verbose("Remote cert was issued to [{0}] and is valid from [{1}] until [{2}].\n",
                    remoteCertificate?.Subject,
                    remoteCertificate?.GetEffectiveDateString(),
                    remoteCertificate?.GetExpirationDateString());
            }
            else
            {
                Log.Verbose("Remote certificate is null.\n");
            }
        }
    }
}