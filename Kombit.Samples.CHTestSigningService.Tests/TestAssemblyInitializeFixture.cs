#region

using System;
using System.Security.Cryptography;
using dk.nita.saml20.Utils;

#endregion

namespace Kombit.Samples.CHTestSigningService.Tests
{
    /// <summary>
    ///     A initialize test fixture that runs once for all tests in this assembly.
    /// </summary>
    public sealed class TestAssemblyInitializeFixture : IDisposable
    {
        /// <summary>
        ///     Creates an instance of TestAssemblyInitializeFixture that registers SHA256 handler to .Net
        /// </summary>
        public TestAssemblyInitializeFixture()
        {
            CryptoConfig.AddAlgorithm(
                typeof (RSAPKCS1SHA256SignatureDescription),
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        }

        /// <summary>
        ///     This is just a test fixture, no need to disable anything.
        /// </summary>
        public void Dispose()
        {
        }
    }
}