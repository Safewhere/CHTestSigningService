#region

using System.Security.Cryptography.X509Certificates;

#endregion

namespace Kombit.Samples.CHTestSigningService.Code
{
    /// <summary>
    ///     Defines an API which is responsible for updating a token
    /// </summary>
    public interface ITokenSigningService
    {
        /// <summary>
        ///     Updates a token and sign it. The updated token must be valid.
        /// </summary>
        /// <param name="message">A base64 SAML2 response message to update</param>
        /// <param name="signingCertificate">The signing certificate  which will be used to sign the updated token.</param>
        /// <param name="decryptionCertificate">
        ///     A certificate which will be used to decrypt a token when the input message is
        ///     encrypted
        /// </param>
        /// <returns></returns>
        string UpdateToken(string message, X509Certificate2 signingCertificate, X509Certificate2 decryptionCertificate);
    }
}