using Kombit.Samples.CHTestSigningService.Code;
using Xunit;

namespace Kombit.Samples.CHTestSigningService.Tests
{
    /// <summary>
    ///     Unit tests for the TokenSigningService class (SUT - system under test)
    /// </summary>
    [Collection("TestAssemblyInitialize collection")]
    public class TokenSigningServiceTest
    {
        /// <summary>
        ///     Initializes an object of TokenSigningServiceTest. The main point of this is to make sure
        ///     TestAssemblyInitializeFixture is run.
        /// </summary>
        /// <param name="fixture"></param>
        public TokenSigningServiceTest(TestAssemblyInitializeFixture fixture)
        {
        }

        /// <summary>
        ///     Verifies that SUT can update a token that has both assertion and response elements signed
        /// </summary>
        [Fact]
        public void TokenSigningServiceCanUpdateToken_SignedAssertion_SignedMessage()
        {
            // Set up
            TokenSigningService sut = new TokenSigningService();

            // Exercise system
            string updatedToken = sut.UpdateToken(Constants.Response_SignedAssertion_SignedMessage,
                CertificateRegistry.SigningCertificate, CertificateRegistry.EncryptionCertificate);

            // Verify
            AssertionHelper.AssertUpdatedToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate, Constants.Response_SignedAssertion_SignedMessage, true);
        }

        /// <summary>
        ///     Verifies that SUT can update a token that has both assertion and response elements signed
        ///     And that the updated token can be update again
        /// </summary>
        [Fact]
        public void TokenSigningServiceCanUpdateTheUpdatedToken_SignedAssertion_SignedMessage()
        {
            // Set up
            TokenSigningService sut = new TokenSigningService();

            // Exercise system
            string updatedToken = sut.UpdateToken(Constants.Response_SignedAssertion_SignedMessage,
                CertificateRegistry.SigningCertificate, CertificateRegistry.EncryptionCertificate);
            // one more time
            updatedToken = sut.UpdateToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate);

            // Verify
            AssertionHelper.AssertUpdatedToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate, Constants.Response_SignedAssertion_SignedMessage, true);
        }

        /// <summary>
        ///     Verifies that SUT can update a token that has both assertion and response elements signed. Assertion is also
        ///     encrypted.
        /// </summary>
        [Fact]
        public void TokenSigningServiceCanUpdateToken_SignedAndEncryptedAssertion_SignedMessage()
        {
            // Set up
            TokenSigningService sut = new TokenSigningService();

            // Exercise system
            string updatedToken = sut.UpdateToken(Constants.Response_SignedAndEncryptedAssertion_SignedMessage,
                CertificateRegistry.SigningCertificate, CertificateRegistry.EncryptionCertificate);

            // Verify
            AssertionHelper.AssertUpdatedToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate, Constants.Response_SignedAndEncryptedAssertion_SignedMessage,
                true);
        }

        /// <summary>
        ///     Verifies that SUT can update a token that has both assertion and response elements signed. Assertion is also
        ///     encrypted.
        ///     And that the updated token can be update again
        /// </summary>
        [Fact]
        public void TokenSigningServiceCanUpdateTheUpdatedToken_SignedAndEncryptedAssertion_SignedMessage()
        {
            // Set up
            TokenSigningService sut = new TokenSigningService();

            // Exercise system
            string updatedToken = sut.UpdateToken(Constants.Response_SignedAndEncryptedAssertion_SignedMessage,
                CertificateRegistry.SigningCertificate, CertificateRegistry.EncryptionCertificate);
            // one more time
            updatedToken = sut.UpdateToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate);

            // Verify
            AssertionHelper.AssertUpdatedToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate, Constants.Response_SignedAndEncryptedAssertion_SignedMessage,
                true);
        }

        /// <summary>
        ///     Verifies that SUT can update a token that has assertion element signed.
        /// </summary>
        [Fact]
        public void TokenSigningServiceCanUpdateToken_SignedAssertion()
        {
            // Set up
            TokenSigningService sut = new TokenSigningService();

            // Exercise system
            string updatedToken = sut.UpdateToken(Constants.Response_SignedAssertion,
                CertificateRegistry.SigningCertificate, CertificateRegistry.EncryptionCertificate);

            // Verify
            AssertionHelper.AssertUpdatedToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate, Constants.Response_SignedAssertion, false);
        }

        /// <summary>
        ///     Verifies that SUT can update a token that has assertion element signed.
        ///     And that the updated token can be update again
        /// </summary>
        [Fact]
        public void TokenSigningServiceCanUpdateTheUpdatedToken_SignedAssertion()
        {
            // Set up
            TokenSigningService sut = new TokenSigningService();

            // Exercise system
            string updatedToken = sut.UpdateToken(Constants.Response_SignedAssertion,
                CertificateRegistry.SigningCertificate, CertificateRegistry.EncryptionCertificate);
            // one more time
            updatedToken = sut.UpdateToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate);

            // Verify
            AssertionHelper.AssertUpdatedToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate, Constants.Response_SignedAssertion, false);
        }

        /// <summary>
        ///     Verifies that SUT can update a token that has assertion element signed. Assertion is also encrypted
        /// </summary>
        [Fact]
        public void TokenSigningServiceCanUpdateToken_SignedAndEncryptedAssertion()
        {
            // Set up
            TokenSigningService sut = new TokenSigningService();

            // Exercise system
            string updatedToken = sut.UpdateToken(Constants.Response_SignedAndEncryptedAssertion,
                CertificateRegistry.SigningCertificate, CertificateRegistry.EncryptionCertificate);

            // Verify
            AssertionHelper.AssertUpdatedToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate, Constants.Response_SignedAndEncryptedAssertion, false);
        }

        /// <summary>
        ///     Verifies that SUT can update a token that has assertion element signed. Assertion is also encrypted
        ///     And that the updated token can be update again
        /// </summary>
        [Fact]
        public void TokenSigningServiceCanUpdateTheUpdatedToken_SignedAndEncryptedAssertion()
        {
            // Set up
            TokenSigningService sut = new TokenSigningService();

            // Exercise system
            string updatedToken = sut.UpdateToken(Constants.Response_SignedAndEncryptedAssertion,
                CertificateRegistry.SigningCertificate, CertificateRegistry.EncryptionCertificate);
            // one more time
            updatedToken = sut.UpdateToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate);

            // Verify
            AssertionHelper.AssertUpdatedToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate, Constants.Response_SignedAndEncryptedAssertion, false);
        }

        /// <summary>
        ///     Verifies that SUT can update a token that has both assertion and response elements signed using SHA256
        /// </summary>
        [Fact]
        public void TokenSigningServiceCanUpdateToken_SignedAssertion_SignedMessage_Sha256()
        {
            // Set up
            TokenSigningService sut = new TokenSigningService();

            // Exercise system
            string updatedToken = sut.UpdateToken(Constants.Response_SignedAssertion_SignedMessage_Sha256,
                CertificateRegistry.SigningCertificate, CertificateRegistry.EncryptionCertificate);

            // Verify
            AssertionHelper.AssertUpdatedToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate, Constants.Response_SignedAssertion_SignedMessage_Sha256, true);
        }

        /// <summary>
        ///     Verifies that SUT can update a token that has assertion element signed using SHA256. Assertion is also encrypted
        /// </summary>
        [Fact]
        public void TokenSigningServiceCanUpdateToken_SignedAndEncryptedAssertion_Sha256()
        {
            // Set up
            TokenSigningService sut = new TokenSigningService();

            // Exercise system
            string updatedToken = sut.UpdateToken(Constants.Response_SignedAndEncryptedAssertion_Sha256,
                CertificateRegistry.SigningCertificate, CertificateRegistry.EncryptionCertificate);

            // Verify
            AssertionHelper.AssertUpdatedToken(updatedToken, CertificateRegistry.SigningCertificate,
                CertificateRegistry.EncryptionCertificate, Constants.Response_SignedAndEncryptedAssertion_Sha256, false);
        }
    }
}