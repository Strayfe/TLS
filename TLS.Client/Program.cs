using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using McMaster.Extensions.CommandLineUtils;
using Newtonsoft.Json;
using Serilog;
using Serilog.Events;

namespace TLS.Client
{
    [Command(Description = "A simple app to test SSL/TLS protocols for a specified endpoint.")]
    [HelpOption("-?")]
    internal class Program
    {
        [Option("-t|--target", Description = "The target endpoint to query. Defaults to 127.0.0.1")]
        private string Target { get; } = IPAddress.Loopback.MapToIPv4().ToString();

        [Option("-p|--port", Description = "The port to connect on. Defaults to 443.")]
        private int Port { get; } = 443;

        [Option("-l|--logEventLevel", Description = "The verbosity of the output from the app processing. Defaults to [Information]")] 
        private LogEventLevel LogEventLevel { get; } = LogEventLevel.Information;
        
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

                await CreateTlsClientAsync(app, cancellationToken);
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

        private async Task CreateTlsClientAsync(CommandLineApplication app,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(Target))
            {
                Log.Error("Invalid target, please provide a valid DNS host or IP");
                app.ShowHelp();
            }
            
            var status = new ProtocolStatus
            {
                Target = Target,
                Port = Port
            };

            Log.Verbose("ProtocolStatus: {@status}\n", status);
            
            foreach (SslProtocols protocol in Enum.GetValues(typeof(SslProtocols)))
            {
                Log.Information("Testing protocol [{@protocol}]", protocol);
                
                var client = new TcpClient();

                try
                {
                    Log.Verbose($"Creating connection to [{Target}:{Port}]");

                    await client.ConnectAsync(Target, Port);
                    
                    status.ConnectionSuccessful = true;
                    
                    Log.Verbose("Connection [{@result}]", 
                        status.ConnectionSuccessful ? "Successful" : "Unsuccessful");
                }
                catch
                {
                    status.ConnectionSuccessful = false;

                    Log.Verbose("Connection [{@result}]", 
                        status.ConnectionSuccessful ? "Successful" : "Unsuccessful");
                }

                var sslStream = new SslStream(client.GetStream(), false);
                
                try
                {
                    Log.Verbose("Authenticating via protocol [{@protocol}]", protocol);

                    await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = Target,
                        EnabledSslProtocols = protocol,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                        RemoteCertificateValidationCallback = RemoteCertificateValidationCallback
                    }, cancellationToken);
                    
                    Log.Verbose("Authentication [{@result}]", 
                        sslStream.IsAuthenticated ? "Successful" : "Unsuccessful");
                    
                    Log.Verbose("Gathering certificate details");
                    
                    status.Certificate = new Certificate
                    {
                        Subject = sslStream.RemoteCertificate?.Subject,
                        Issuer = sslStream.RemoteCertificate?.Issuer,
                        NotBefore = sslStream.RemoteCertificate?.GetEffectiveDateString(),
                        NotAfter = sslStream.RemoteCertificate?.GetExpirationDateString(),
                    };

                    Log.Verbose("Adding successful attempt for protocol [{@protocol}]", protocol);

                    status.Protocols.Add(protocol, true);
                }
                catch (Exception e)
                {
                    Log.Verbose("Exception: {0}", e.Message);
                    if (e.InnerException != null)
                    {
                        Log.Verbose("Inner exception: {0}", e.InnerException.Message);
                    }
                    Log.Verbose("Authentication failed - closing the connection.");
                    Log.Verbose("Adding unsuccessful attempt for protocol [{@protocol}]", protocol);
                    
                    status.Protocols.Add(protocol, false);
                }
                finally
                {
                    Log.Verbose("Closing the SSL/TLS connection stream\n");

                    sslStream.Close();
                }
            }

            Console.WriteLine("\n" + JsonConvert.SerializeObject(status, Formatting.Indented));
        }

        private static bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate,
            X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // we do not care if the cert is invalid right now
            return true;
        }
    }

    internal class ProtocolStatus
    {
        public string Target { get; set; }
        public int Port { get; set; }
        public bool ConnectionSuccessful { get; set; }
        public Dictionary<SslProtocols, bool> Protocols { get; } = new Dictionary<SslProtocols, bool>();
        public Certificate Certificate { get; set; }
    }

    internal class Certificate
    {
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public string NotBefore { get; set; }
        public string NotAfter { get; set; }
    }
}