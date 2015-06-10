#region

using System;
using System.Configuration;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Http;
using System.Web.Http.Description;
using Kombit.Samples.CHTestSigningService.Code;
using Kombit.Samples.Common;

#endregion

namespace Kombit.Samples.CHTestSigningService.Controllers
{
    //[RoutePrefix("api")]
    public class ContextHandlerTestSigningController : ApiController
    {
        private readonly ITokenSigningService tokenSigningService;

        /// <summary>
        ///     Creates an instance of this controller. This is just a simple service -> use poor-man DI
        /// </summary>
        public ContextHandlerTestSigningController()
            : this(new TokenSigningService())
        {
        }

        /// <summary>
        ///     Creates an instance of this controller using the input tokenSigningService. Useful for unittest
        /// </summary>
        /// <param name="tokenSigningService">A object of type tokenSigningService which does the actual update</param>
        public ContextHandlerTestSigningController(ITokenSigningService tokenSigningService)
        {
            if (tokenSigningService == null)
                throw new ArgumentNullException("tokenSigningService");

            this.tokenSigningService = tokenSigningService;
        }

        /// <summary>
        ///     Test signing service
        /// </summary>
        /// <remarks>
        ///     This is a test signing service that can be called by a user facing system, with a previously issued SAML assertion
        ///     as input,
        ///     and the test signing service must then reply with an updated version of the SAML assertion.
        /// </remarks>
        /// <param name="message">Base64 encoded SAML response message</param>
        /// <param name="thumbprint">Default encryption certificate can be overridden by passing a thumprint via service call</param>
        /// <response code="200">Token updated successfully</response>
        /// <response code="400">The input message is null or empty</response>
        /// <response code="500">An exception was thrown</response>
        //[Route("ContextHandlerTestSigning")]
        [ResponseType(typeof (string))]
        public HttpResponseMessage Post([FromBody] string message, [FromUri] string thumbprint = "")
        {
            try
            {
                Logging.Instance.Debug("Received message {Message} with thumbprint {Thumbprint}.", message, thumbprint);
                if (string.IsNullOrEmpty(message))
                {
                    Logging.Instance.Information("Returning code is {HttpStatusCode}", HttpStatusCode.BadRequest);
                    Request.CreateErrorResponse(HttpStatusCode.BadRequest, "Message is null or empty");
                }

                string signingCertificateThumbprint = ConfigurationManager.AppSettings["SigningCertificateThumbprint"];
                Logging.Instance.Debug(
                    "Signing certificate tbumbprint in web.config is {SigningCertificateThumbprint}",
                    signingCertificateThumbprint);
                X509Certificate2 signingCertificate =
                    CertificateLoader.LoadCertificateFromMyStore(signingCertificateThumbprint);


                string encryptionCertificateThumbprint =
                    ConfigurationManager.AppSettings["EncryptionCertificateThumbprint"];
                Logging.Instance.Debug(
                    "Encryption certificate tbumbprint in web.config is {EncryptionCertificateThumbprint}",
                    encryptionCertificateThumbprint);
                if (!string.IsNullOrEmpty(thumbprint))
                {
                    encryptionCertificateThumbprint = thumbprint;
                    Logging.Instance.Debug(
                        "An alternate encryption certificate thumbprint {EncryptionCertificateThumbprint} is sent along with the request which will override the configured on in web.config.",
                        encryptionCertificateThumbprint);
                }
                X509Certificate2 encryptionCertificate =
                    CertificateLoader.LoadCertificateFromMyStore(encryptionCertificateThumbprint);

                string updatedMessage = tokenSigningService.UpdateToken(message, signingCertificate,
                    encryptionCertificate);

                Logging.Instance.Information("Returning code is {HttpStatusCode}", HttpStatusCode.OK);
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content =
                        new StringContent(updatedMessage,
                            Encoding.UTF8, "text/plain")
                };
                return response;
            }
            catch (Exception ex)
            {
                Logging.Instance.Error(ex,
                    "An error has occurred while updating a token. Returning code is {HttpStatusCode}",
                    HttpStatusCode.InternalServerError);
                return Request.CreateErrorResponse(HttpStatusCode.InternalServerError, ex.Message, ex);
            }
        }
    }
}