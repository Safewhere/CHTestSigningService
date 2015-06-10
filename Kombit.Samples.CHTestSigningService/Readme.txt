Introduction
    This is a test signing service that can be called by a user facing system, with a previously issued SAML assertion as input,
    and the test signing service must then reply with an updated version of the SAML assertion.
        - Timestamp
        - Id
        - Signature. Signing will be done correspondingly to the input token. In other words:
            + If the input token's assertion is signed, that of the updated token will be signed.
            + If the input token's response element is signed, that of the updated token will be signed.
        - Encryption. Updated token's assertion will *always* be encrypted.
            + Encryption certificate is overridable.

    The test signing service takes an Assertion element as input, rather than an EncryptedAssertion element. This way, caller is able to modify the assertion before it is sent to the test signing service, so that different roles can be put in the assertion before it is re-signed. This behaviour diverts from the specific requirement that states it must take an actual token as input and return an updated token. This difference in behaviour has been requested by KOMBIT.

Configuration
    - SigningCertificateThumbprint: thumbprint of a certificate with private key that is used to sign the updated token. The certificate must exist in LocalMachine\My.
    - EncryptionCertificateThumbprint: thumbprint of a certificate with private key that is used to decrypt and then encrypt the updated token, given that the input token uses encryption.
                                       The certificate must exist in LocalMachine\My. A call to update a token can override the encryption certificate by passing a thumbprint via the request.
    - serilog:minimum-level: specify the level of logging.  Log files are stored in the Logs\ folder.
    - owin:AutomaticAppStartup: tell the application that it should use OWIN middleware when hosting under IIS. This setting should be true.

Running
    The application can be run under IIS or Visual Studio 2013's IIS Express.

Unittest
    To run unittest, the stock certificate (CertificateIdp.p12) found in the Certificates folder must be imported to LocalMachine\My. Remember to grant access to it
    for the user that runs Visual Studio. Note that when you want to write test to run against a real site hosted under IIS, remember to grant access for the identity app pool account.
    Unittest has two main sets of test cases:
        - One set tests the TokenSigningService class.
        - One set tests against a real WebApi environment using OWIN.

How to call the service
    - Sample code which demonstrates how to call the service can be found in the ContextHandlerTestSigningControllerTest class.
    - Encryption certificate can be overridden by adding a thumprint to the service url:
            http://localhost:19000/api/ContextHandlerTestSigning/CA95B2F383BEF8144500CD74B88BC42CD3DE936C
            (or https://adgangsstyringeksempler.test-stoettesystemerne.dk/CHTestSigningService/CA95B2F383BEF8144500CD74B88BC42CD3DE936C depending on where the application is deployed)
API Documentation
	This service supports an interactive API documentation based on Swagger 2.0 specification.

