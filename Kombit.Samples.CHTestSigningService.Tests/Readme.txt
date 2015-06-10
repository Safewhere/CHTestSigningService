Introduction
    This project contains unit tests of the Kombit.Samples.CHTestSigningService project

Unittest
    To run unittest, the stock certificate (CertificateIdp.p12) found in the Certificates folder must be imported to LocalMachine\My. Remember to grant access to it
    for the user that runs Visual Studio. Note that when you want to write test to run against a real site hosted under IIS, remember to grant access for the identity app pool account.
    Unittest has two main sets of test cases:
        - One set tests the TokenSigningService class: TokenSigningServiceTest
        - One set tests against a real WebApi environment using OWIN: ContextHandlerTestSigningControllerTest
