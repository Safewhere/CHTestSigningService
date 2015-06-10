#region

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Web;
using Kombit.Samples.Common;
using Xunit;

#endregion

namespace Kombit.Samples.CHTestSigningService.Tests
{
    /// <summary>
    ///     Unittests for the ContextHandlerTestSigningController
    /// </summary>
    [Collection("TestAssemblyInitialize collection")]
    public class ContextHandlerTestSigningControllerTest
    {
        /// <summary>
        ///     Calls the update API to update a response. The response is passed to it using form encoded content
        /// </summary>
        [TestCase("2H-31")]
        [Fact]
        public void CanPostMessageToUpdateWithFormEncodedContent()
        {
            // Set up
            // Start OWIN host 
            using (HostProvider.Start<Startup>(url: Constants.BaseAddress))
            {
                // Create HttpCient and make a request to api/values 
                HttpClient client = new HttpClient {BaseAddress = new Uri(Constants.BaseAddress)};
                var formUrlEncodedContent = new FormUrlEncodedContent(
                    new[]
                    {
                        new KeyValuePair<string, string>("", Constants.Response_SignedAndEncryptedAssertion)
                    }
                    );

                formUrlEncodedContent.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

                // Exercise system
                var response = client.PostAsync(Constants.ApiUrl, formUrlEncodedContent).Result;

                Console.WriteLine(response);
                string result = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine(result);
                response.EnsureSuccessStatusCode();

                // Verify
                AssertionHelper.AssertUpdatedToken(result, CertificateRegistry.SigningCertificate,
                    CertificateRegistry.EncryptionCertificate, Constants.Response_SignedAndEncryptedAssertion, false);
            }
        }

        /// <summary>
        ///     Calls the update API to update a response. The response is passed to it as string content
        /// </summary>
        [TestCase("2H-31")]
        [Fact]
        public void CanPostMessageToUpdateWithStringContent()
        {
            // Set up

            // Start OWIN host 
            using (HostProvider.Start<Startup>(url: Constants.BaseAddress))
            {
                // Create HttpCient and make a request to api/values 
                HttpClient client = new HttpClient {BaseAddress = new Uri(Constants.BaseAddress)};
                HttpContent content =
                    new StringContent("=" + HttpUtility.UrlEncode(Constants.Response_SignedAndEncryptedAssertion));
                content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

                // Exercise system
                var response = client.PostAsync(Constants.ApiUrl, content).Result;

                Console.WriteLine(response);
                response.EnsureSuccessStatusCode();
                string result = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine(result);

                // Verify
                AssertionHelper.AssertUpdatedToken(result, CertificateRegistry.SigningCertificate,
                    CertificateRegistry.EncryptionCertificate, Constants.Response_SignedAndEncryptedAssertion, false);
            }
        }

        /// <summary>
        ///     Calls the update API with invalid thumbprint for the encryption certificate. Expected behavior is that an error
        ///     will be returned.
        /// </summary>
        [TestCase("2H-31")]
        [Fact]
        public void PostMessageToUpdateWithInvalidThumbprintWillReturnError()
        {
            // Set up
            // Start OWIN host 
            using (HostProvider.Start<Startup>(url: Constants.BaseAddress))
            {
                // Create HttpCient and make a request to api/values 
                HttpClient client = new HttpClient {BaseAddress = new Uri(Constants.BaseAddress)};
                HttpContent content =
                    new StringContent("=" + HttpUtility.UrlEncode(Constants.Response_SignedAndEncryptedAssertion));
                content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

                // Exercise system
                var response = client.PostAsync(Constants.ApiUrl + "/1234", content).Result;

                Console.WriteLine(response);
                string result = response.Content.ReadAsStringAsync().Result;
                Assert.False(response.IsSuccessStatusCode);
                Console.WriteLine(result);
            }
        }
    }
}