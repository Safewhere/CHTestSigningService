#region

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using dk.nita.saml20;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Utils;
using Xunit;

#endregion

namespace Kombit.Samples.CHTestSigningService.Tests
{
    /// <summary>
    ///     A helper class which asserts a token after it is updated to make sure it is valid
    /// </summary>
    public class AssertionHelper
    {
        /// <summary>
        ///     Asserts an updated token
        /// </summary>
        /// <param name="updatedToken">the updated token to assert</param>
        /// <param name="signingCertificate">signing certificate</param>
        /// <param name="encryptionCertificate">encryption certificate</param>
        /// <param name="originalTokenMessage">original token message (the token to update)</param>
        /// <param name="validateResponseSignature">Controls whether the response has an signature and if it should be verified.</param>
        public static void AssertUpdatedToken(string updatedToken, X509Certificate2 signingCertificate,
            X509Certificate2 encryptionCertificate, string originalTokenMessage, bool validateResponseSignature)
        {
            string decodedMessage = Encoding.UTF8.GetString(Convert.FromBase64String(originalTokenMessage));
            Response originalToken = Serialization.DeserializeFromXmlString<Response>(decodedMessage);
            Console.Out.Write("Updated token: " + updatedToken);

            // get assertion
            Saml20Assertion originalAssertion;
            GetMessageDocumentAndAssertion(decodedMessage, encryptionCertificate, false, out originalAssertion);

            // get updated assertion
            string decodedUpdatedToken = Encoding.UTF8.GetString(Convert.FromBase64String(updatedToken));
            Response updatedResponse = Serialization.DeserializeFromXmlString<Response>(decodedUpdatedToken);
            Saml20Assertion updatedAssertion;
            bool validSignature = ValidateSignature(decodedUpdatedToken, signingCertificate, encryptionCertificate,
                validateResponseSignature, out updatedAssertion);

            Assert.NotEqual(originalToken.ID, updatedResponse.ID);
            Assert.NotEqual(originalToken.IssueInstant, updatedResponse.IssueInstant);
            Assert.True(DateTime.UtcNow.Subtract(updatedResponse.IssueInstant.Value).TotalMinutes < 1);
            Assert.True(validSignature,
                "OIOSAML code can't verify signature that has both message and signature signed but assertion is not encrypted.");

            AssertAssertionAttributes(originalAssertion.Assertion, updatedAssertion.Assertion);
        }

        /// <summary>
        ///     Asserts updated attributes of the updated assertion
        /// </summary>
        /// <param name="originalAssertion">The original assertion</param>
        /// <param name="updatedAssertion">the updated assertion</param>
        private static void AssertAssertionAttributes(Assertion originalAssertion, Assertion updatedAssertion)
        {
            Assert.NotEqual(originalAssertion.ID, updatedAssertion.ID);
            Assert.NotEqual(originalAssertion.IssueInstant, updatedAssertion.IssueInstant);
            Assert.True(DateTime.UtcNow.Subtract(updatedAssertion.IssueInstant.Value).TotalMinutes < 1);

            Assert.NotEqual(originalAssertion.Conditions.NotBefore, updatedAssertion.Conditions.NotBefore);
            Assert.NotEqual(originalAssertion.Conditions.NotOnOrAfter, updatedAssertion.Conditions.NotOnOrAfter);
            Assert.True(DateTime.UtcNow.Subtract(updatedAssertion.Conditions.NotOnOrAfter.Value).TotalMinutes < 1);

            SubjectConfirmation originalSubjectConfirmation =
                originalAssertion.Subject.Items.OfType<SubjectConfirmation>().First();
            SubjectConfirmation updatedSubjectConfirmation =
                updatedAssertion.Subject.Items.OfType<SubjectConfirmation>().First();
            Assert.NotEqual(originalSubjectConfirmation.SubjectConfirmationData.NotOnOrAfter,
                updatedSubjectConfirmation.SubjectConfirmationData.NotOnOrAfter);
            Assert.True(
                DateTime.UtcNow.Subtract(updatedSubjectConfirmation.SubjectConfirmationData.NotOnOrAfter.Value)
                    .TotalMinutes < 1);

            AuthnStatement originalAuthnStatement = originalAssertion.Items.OfType<AuthnStatement>().First();
            AuthnStatement updatedAuthnStatement = updatedAssertion.Items.OfType<AuthnStatement>().First();
            Assert.NotEqual(originalAuthnStatement.AuthnInstant, updatedAuthnStatement.AuthnInstant);
            Assert.True(DateTime.UtcNow.Subtract(updatedAuthnStatement.AuthnInstant.Value).TotalMinutes < 1);
        }

        /// <summary>
        ///     Verifies if a signature is valid
        /// </summary>
        /// <param name="decodedUpdatedToken">The decoded updated token</param>
        /// <param name="signingCertificate">The signing certificate</param>
        /// <param name="encryptionCertificate">The encryption certificate</param>
        /// <param name="validateResponseSignature">If response signature exists and should be validated</param>
        /// <param name="saml20Assertion">Output the assertion object</param>
        /// <returns>True if the signature is valid. Otherwise, false.</returns>
        private static bool ValidateSignature(string decodedUpdatedToken, X509Certificate2 signingCertificate,
            X509Certificate2 encryptionCertificate, bool validateResponseSignature,
            out Saml20Assertion saml20Assertion)
        {
            XmlDocument messageDocument = GetMessageDocumentAndAssertion(decodedUpdatedToken, encryptionCertificate,
                true, out saml20Assertion);
            bool validAssertionSignature = saml20Assertion.CheckSignature(new List<AsymmetricAlgorithm>
            {
                signingCertificate.PublicKey.Key
            });
            bool validMessageSignature = true;
            if (validateResponseSignature)
            {
                validMessageSignature = XmlSignatureUtils.CheckSignature(messageDocument);
            }
            return validAssertionSignature && validMessageSignature;
        }

        /// <summary>
        ///     From the input decoded updated token message, returns two xlm elements: the response element and the assertion
        ///     element
        /// </summary>
        /// <param name="decodedUpdatedToken">The decoded updated token</param>
        /// <param name="encryptionCertificate">The encryption certificate</param>
        /// <param name="checkAssertionEncrypted">Verifies if the assertion is encrypted</param>
        /// <param name="saml20Assertion">Output the assertion object</param>
        /// <returns>Returns the response xml document. Also output assertion element.</returns>
        private static XmlDocument GetMessageDocumentAndAssertion(string decodedUpdatedToken,
            X509Certificate2 encryptionCertificate, bool checkAssertionEncrypted, out Saml20Assertion saml20Assertion)
        {
            XmlDocument doc = new XmlDocument {XmlResolver = null, PreserveWhitespace = true};

            doc.LoadXml(decodedUpdatedToken);
            bool isEncrypted;
            XmlElement assertionElement = GetAssertion(doc.DocumentElement, out isEncrypted);
            if (checkAssertionEncrypted)
            {
                Assert.True(isEncrypted, "Updated token's assertion must always be encrypted");
            }
            if (isEncrypted)
            {
                assertionElement =
                    GetDecryptedAssertion(assertionElement, encryptionCertificate).Assertion.DocumentElement;
            }


            saml20Assertion = new Saml20Assertion(assertionElement, null, AssertionProfile.DKSaml, false,
                false);
            return doc;
        }

        /// <summary>
        ///     Loads and decrypts an encrypted Saml20 assertion elemnt
        /// </summary>
        /// <param name="elem">The encrypted assertion element</param>
        /// <param name="encrytionCertificate">The certificate which is used to decrypt</param>
        /// <returns>Decrypted assertion object</returns>
        private static Saml20EncryptedAssertion GetDecryptedAssertion(XmlElement elem,
            X509Certificate2 encrytionCertificate)
        {
            Saml20EncryptedAssertion decryptedAssertion =
                new Saml20EncryptedAssertion((RSA) encrytionCertificate.PrivateKey);
            decryptedAssertion.LoadXml(elem);
            decryptedAssertion.Decrypt();
            return decryptedAssertion;
        }

        /// <summary>
        ///     Gets assertion xml element from a response message element
        /// </summary>
        /// <param name="el">The response message element</param>
        /// <param name="isEncrypted">Indicates if assertion is encrypted</param>
        /// <returns>The assertion xml element</returns>
        private static XmlElement GetAssertion(XmlElement el, out bool isEncrypted)
        {
            XmlNodeList encryptedList =
                el.GetElementsByTagName(EncryptedAssertion.ELEMENT_NAME, Saml20Constants.ASSERTION);

            if (encryptedList.Count == 1)
            {
                isEncrypted = true;
                return (XmlElement) encryptedList[0];
            }

            XmlNodeList assertionList =
                el.GetElementsByTagName(Assertion.ELEMENT_NAME, Saml20Constants.ASSERTION);

            if (assertionList.Count == 1)
            {
                isEncrypted = false;
                return DetachAssertionElementFromTheResponse((XmlElement) assertionList[0]);
            }

            isEncrypted = false;
            return null;
        }

        /// <summary>
        ///     Loads assertion element to separate xml document so that its signature can be verified
        /// </summary>
        /// <param name="xmlElement">The response xml document</param>
        /// <returns>The separated assertion element</returns>
        private static XmlElement DetachAssertionElementFromTheResponse(XmlElement xmlElement)
        {
            XmlDocument document = new XmlDocument
            {
                PreserveWhitespace = true
            };
            document.AppendChild(document.ImportNode((XmlNode) xmlElement, true));
            return document.DocumentElement;
        }
    }
}