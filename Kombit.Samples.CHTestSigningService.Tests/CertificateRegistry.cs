#region

using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using Kombit.Samples.Common;

#endregion

namespace Kombit.Samples.CHTestSigningService.Tests
{
    /// <summary>
    ///     This class provides access to the two configured certificates: the signing certificate and the encryption
    ///     certificate
    /// </summary>
    public static class CertificateRegistry
    {
        /// <summary>
        ///     The signing certificate
        /// </summary>
        public static X509Certificate2 SigningCertificate =
            CertificateLoader.LoadCertificateFromMyStore(
                ConfigurationManager.AppSettings["SigningCertificateThumbprint"]);

        /// <summary>
        ///     The encryption certificate
        /// </summary>
        public static X509Certificate2 EncryptionCertificate =
            CertificateLoader.LoadCertificateFromMyStore(
                ConfigurationManager.AppSettings["EncryptionCertificateThumbprint"]);
    }
}