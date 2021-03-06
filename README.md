# CHTestSigningService
Context Handler Test Signing Service

Document reference: D.03.08.00003

## <a name=“introduction”></a>Introduction
The following document describes how to configure the Context Handler (CH) Test Signing Service. After completing this guide, the CH Test Signing Service will be configured.

It is assumed that the reader is a .Net-developer knowledgeable in the technologies used to develop this .Net-based sample, including:

* C#
* Microsoft.Net framework v4.5
* Microsoft Windows Server Operating System
* Microsoft Internet Information Systems (IIS)
* HTTP and HTTPS
* X509v3 Certificates

## <a name=“setup”></a>Setup
To use this sample do the following:

1. Either clone the repository <https://github.com/Safewhere/CHTestSigningService.git> to `C:\CHTestSigningService`, or unpack the provided zip-file `CHTestSigningService.zip` to `C:\CHTestSigningService`.
2. Open `C:\CHTestSigningService\Kombit.Samples.CHTestSigningService.sln` in Visual Studio, and build the solution.
3. Make sure an SSL certificate that covers the DNS name `chtestsigningservice.projekt-stoettesystemerne.dk` is present in `LocalMachine\My` certificate store.
4. Open the Hosts-file, and map the DNS name `chtestsigningservice.projekt-stoettesystemerne.dk` to `127.0.0.1`.
5. Create a new IIS web application:
	1. The `Site name` should be `chtestsigningservice.projekt-stoettesystemerne.dk`
	2. The `Physical path`should be `C:\CHTestSigningService\Kombit.Samples.CHTestSigningService`
	3. The `Binding type` should be `HTTPS`
	4. The `Host name` should be `chtestsigningservice.projekt-stoettesystemerne.dk`
	5. Select an appropriate SSL certificate, that matches the host name chosen in the previous step
6. Grant the application pool identity for the web application read and execute permissions to `C:\CHTestSigningService\`
7. Import the certificate `C:\CHTestSigningService\Certificates\certificate.p12` to `LocalMachine\My`.
8. Assign the application pool identity for the web application read permissions to the private key for the certificate imported in the previous step.
9. Open a browser and point it to <https://chtestsigningservice.projekt-stoettesystemerne.dk>

## <a name=“configuration”></a>Configuration ParametersA few properties in the configuration file, web.config, for CHTestSigningService may need to be updated. The configuration file is located in `C:\CHTestSigningService\Kombit.Samples.CHTestSigningService\web.config`.

The following parameters can be changed:* `SigningCertificateThumbprint` The thumbprint of a certificate with private key that is used to sign the updated token. The certificate must exist in `LocalMachine\My`.
* `serilog:minimum-level` Specifies the level of logging.  Log files are stored in the `Logs\` folder.
* `owin:AutomaticAppStartup` Tell the application that it should use OWIN middleware when hosting under IIS. This setting should be true.

##API DocumentationThis service supports an interactive API documentation based on Swagger 2.0 (Open API) specification. After setting up the application, open the file `Content\api-docs.json` file and change the "basePath": `/{application endpoint}/api` setting to `/api/`
