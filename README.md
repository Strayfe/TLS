# TLS Tester
This is a simple repo that I have thrown together that will allow me to verify what transport layer security protocols are enabled on a server.

_Probably could do with refactoring._

In this repo currently is:

- a TLS client console app that will connect to an IP or DNS host on a specified port and attempt to create a secure connection over each available protocol and print the results.
- a TLS server console app that will listen for incoming connections with an SSL certificate and respond only on protocols that are mutually supported

Both can be run from the same machine, across a network or over the internet (providing the port you are listening on is publicly available) depending on your Client/Server protocol requirements.

## Usage
**TLS.Client**
```
TLS.Client -?
A simple app to test SSL/TLS protocols for a specified endpoint.

Usage: TLS.Client [options]

Options:
  -?                  Show help information
  -t|--target         The target endpoint to query. Defaults to 127.0.0.1
  -p|--port           The port to connect on. Defaults to 443.
  -l|--logEventLevel  The verbosity of the output from the app processing. Defaults to [Information]
```

**TLS.Server**
```
TLS.Server -?
A server applet that listens for incoming socket connections to test TLS.

Usage: TLS.Server [options]

Options:
  -?                  Show help information
  -cf|--certFile      The machine certificate to be used to create a secure channel. Defaults to example cert included in the build.
  -cp|--certPass      The password to open an encrypted machine certificate.
  -p|--port           The port to communicate via. Defaults to 443.
  -l|--logEventLevel  The verbosity of the output from the app processing. Defaults to [Information]
```

## Images
![Before](./before.png?raw=true "Before")
![After](./after.png?raw=true "After")
