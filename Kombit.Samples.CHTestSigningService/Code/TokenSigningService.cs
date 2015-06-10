#region

using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using dk.nita.saml20;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Utils;
using Kombit.Samples.Common;
using EncryptedData = dk.nita.saml20.Schema.XEnc.EncryptedData;

#endregion

namespace Kombit.Samples.CHTestSigningService.Code
{
    /// <summary>
    ///     Implementation of the <see cref="ITokenSigningService" /> interface which can update and sign a token
    /// </summary>
    public class TokenSigningService : ITokenSigningService
    {
        /// <summary>
        ///     Updates a token and sign it. The updated token must be valid. Updated token is always encrypted.
        ///     Whether the updated token be signed or not depends on the input token. If the input token is signed, then the
        ///     updated token is too.
        /// </summary>
        /// <param name="message">A base64 SAML2 response message to update</param>
        /// <param name="signingCertificate">The signing certificate  which will be used to sign the updated token.</param>
        /// <param name="decryptionCertificate">
        ///     A certificate which will be used to decrypt a token when the input message is
        ///     encrypted
        /// </param>
        /// <returns>base64-encoded updated token</returns>
        public string UpdateToken(string message, X509Certificate2 signingCertificate,
            X509Certificate2 decryptionCertificate)
        {
            if (string.IsNullOrEmpty(message))
                throw new ArgumentNullException("message");
            if (signingCertificate == null)
                throw new ArgumentNullException("signingCertificate");
            if (!signingCertificate.HasPrivateKey)
                throw new ArgumentException("The certificate that is used for updating a token must have private key.",
                    "signingCertificate");
            if (decryptionCertificate == null)
                throw new ArgumentNullException("decryptionCertificate");
            if (!decryptionCertificate.HasPrivateKey)
                throw new ArgumentException(
                    "The certificate that is used for decrypting a token must have private key.",
                    "decryptionCertificate");

            // load message
            string decoded = GetDecodedSamlResponse(message, Encoding.UTF8);
            Logging.Instance.Debug("Starting to update a response message: {DecodedResponse}", decoded);
            XmlDocument responseXmlDocument = LoadResponseAsXml(decoded);

            Response response = Serialization.DeserializeFromXmlString<Response>(decoded);

            // check if the input response message is signed, and record what the signing method and digest method are
            bool isMessageSigned = response.Signature != null;
            string responseSignatureMethod = isMessageSigned
                ? response.Signature.SignedInfo.SignatureMethod.Algorithm
                : string.Empty;
            string responseDigestMethod = isMessageSigned
                ? response.Signature.SignedInfo.Reference[0].DigestMethod.Algorithm
                : string.Empty;

            // try to decrypt the token, given that it is encrypted
            bool isEncrypted;
            var assertion = GetOrDecryptAssertion(decryptionCertificate, response, responseXmlDocument, out isEncrypted);

            // check if the input assertion is signed, and record what the signing method and digest method are
            bool isAssertionSigned = assertion.Signature != null;
            string assertionSignatureMethod = isAssertionSigned
                ? assertion.Signature.SignedInfo.SignatureMethod.Algorithm
                : string.Empty;
            string assertionDigestMethod = isAssertionSigned
                ? assertion.Signature.SignedInfo.Reference[0].DigestMethod.Algorithm
                : string.Empty;

            Logging.Instance.Debug(
                "Response status: signed message: {IsMessageSigned}, signed assertion: {IsAssertionSigned}, encrypted assertion: {IsAssertionEncrypted}",
                isMessageSigned, isAssertionSigned, isEncrypted);

            // do the update
            UpdateAttributes(response, assertion);

            // Serialize the response
            XmlDocument assertionDoc = new XmlDocument {XmlResolver = null, PreserveWhitespace = false};
            assertionDoc.LoadXml(Serialization.SerializeToXmlString(response));

            // Sign the assertion inside the response message.
            if (isAssertionSigned)
            {
                Logging.Instance.Debug("Sign assertion {ID}", assertion.ID);
                SignAssertion(assertionDoc, assertion.ID, signingCertificate, assertionSignatureMethod,
                    assertionDigestMethod);
            }

            Logging.Instance.Debug("Always encrypt assertion...");
            EncryptAssertion(decryptionCertificate, assertionDoc);

            if (isMessageSigned)
            {
                Logging.Instance.Debug("Sign the whole message {ID}", response.ID);
                SignWholeResponseMessage(assertionDoc, response.ID, signingCertificate, responseSignatureMethod,
                    responseDigestMethod);
            }

            string updatedResponse = assertionDoc.OuterXml;
            return EncodeXmlResponse(updatedResponse, Encoding.UTF8);
        }

        /// <summary>
        ///     Get the assertion object out of an input Response. If it is encrypted, also decrypt it
        /// </summary>
        /// <param name="decryptionCertificate">The certificate which can be used to decrypt the token</param>
        /// <param name="response">The input response object</param>
        /// <param name="responseXmlDocument">The response message in the form of an xml document</param>
        /// <param name="isEncrypted">An out parameter which indicates if the assertion is encrypted</param>
        /// <returns></returns>
        private static Assertion GetOrDecryptAssertion(X509Certificate2 decryptionCertificate, Response response,
            XmlDocument responseXmlDocument, out bool isEncrypted)
        {
            EncryptedElement encryptedAssertionElement = response.Items[0] as EncryptedElement;
            Assertion assertion = response.Items[0] as Assertion;
            isEncrypted = false;
            if (encryptedAssertionElement != null)
            {
                Logging.Instance.Debug("Assertion is encrypted. Decrypt it.");
                XmlElement assertionElement = GetAssertion(responseXmlDocument.DocumentElement, out isEncrypted);
                XmlDocument encryptedAssertionDocument =
                    GetDecryptedAssertion(assertionElement, decryptionCertificate).Assertion;
                assertion =
                    Serialization.DeserializeFromXmlString<Assertion>(
                        encryptedAssertionDocument.DocumentElement.OuterXml);
                response.Items[0] = assertion;
            }
            return assertion;
        }

        /// <summary>
        ///     Encrypts an assertion element
        /// </summary>
        /// <param name="decryptionCertificate"></param>
        /// <param name="assertionDoc"></param>
        private static void EncryptAssertion(X509Certificate2 decryptionCertificate, XmlDocument assertionDoc)
        {
            Logging.Instance.Debug("Encrypt assertion...");
            // encrypt assertion
            XmlNodeList list = assertionDoc.DocumentElement.GetElementsByTagName(Assertion.ELEMENT_NAME,
                Saml20Constants.ASSERTION);
            XmlDocument wrappedAssertion = new XmlDocument();
            var imported = wrappedAssertion.ImportNode(list[0], true);
            wrappedAssertion.AppendChild(imported);

            XmlDocument encryptedAssertionDocument = EncryptAssertion(wrappedAssertion, decryptionCertificate);

            // replace plain assertion node with the encrypted node.
            XmlNode newNode = assertionDoc.ImportNode(encryptedAssertionDocument.DocumentElement, true);
            XmlNode currentAssertionElement =
                assertionDoc.GetElementsByTagName(Assertion.ELEMENT_NAME, Saml20Constants.ASSERTION)[0];
            assertionDoc.DocumentElement.InsertAfter(newNode, currentAssertionElement);
            assertionDoc.DocumentElement.RemoveChild(currentAssertionElement);
        }

        /// <summary>
        ///     Updates attributes of a response, including IDs and Datetime fields
        /// </summary>
        /// <param name="response"></param>
        /// <param name="assertion"></param>
        private static void UpdateAttributes(Response response, Assertion assertion)
        {
            response.IssueInstant = DateTime.UtcNow;
            response.ID = "_id" + Guid.NewGuid();
            response.Signature = null;
            assertion.ID = "_id" + Guid.NewGuid();
            assertion.IssueInstant = DateTime.UtcNow;
            assertion.Signature = null;
            var subjectConfirmation = assertion.Subject.Items.OfType<SubjectConfirmation>().First();
            subjectConfirmation.SubjectConfirmationData.NotOnOrAfter = DateTime.UtcNow.AddHours(1);
            assertion.Conditions.NotBefore = DateTime.UtcNow;
            assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddHours(1);
            AuthnStatement authnStatement = assertion.Items.OfType<AuthnStatement>().First();
            authnStatement.AuthnInstant = DateTime.UtcNow;
            Logging.Instance.Debug(
                "Update IssueInstant, ID, assertion.Id, assertion.IssueInstant, subject.NotOnOrAfter, conditions.NotBefore, conditions.NotOnOrAfter, authnStatement.AuthnInstant.");
        }

        /// <summary>
        ///     Loads a response message to an XmlDocument
        /// </summary>
        /// <param name="decoded"></param>
        /// <returns></returns>
        private static XmlDocument LoadResponseAsXml(string decoded)
        {
            XmlDocument doc = new XmlDocument {XmlResolver = null, PreserveWhitespace = true};
            doc.LoadXml(decoded);
            return doc;
        }

        /// <summary>
        ///     Decodes a base64 input message.
        /// </summary>
        /// <param name="message">The encoded message</param>
        /// <param name="encoding">Encoding used</param>
        /// <returns>Decoded message</returns>
        private static string GetDecodedSamlResponse(string message, Encoding encoding)
        {
            try
            {
                string samlResponse = encoding.GetString(Convert.FromBase64String(message));
                return samlResponse;
            }
            catch (FormatException ex)
            {
                Logging.Instance.Error(ex, "An error has occurred while decoding the received message.");
                throw;
            }
        }

        /// <summary>
        ///     Performs base64-encode a message xml string
        /// </summary>
        /// <param name="message">The message to encode</param>
        /// <param name="encoding">Encoding used</param>
        /// <returns>Encoded message</returns>
        private static string EncodeXmlResponse(string message, Encoding encoding)
        {
            string samlResponse = Convert.ToBase64String(encoding.GetBytes(message));

            return samlResponse;
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
        ///     Encrypts an Xml assertion
        /// </summary>
        /// <param name="assertion">Assertion to encrypt</param>
        /// <param name="encryptionCertificate">The certificate which is used to encrypt</param>
        /// <returns>Encrypted assertion xml element</returns>
        private static XmlDocument EncryptAssertion(XmlDocument assertion, X509Certificate2 encryptionCertificate)
        {
            System.Security.Cryptography.Xml.EncryptedData encryptedData =
                new System.Security.Cryptography.Xml.EncryptedData();
            encryptedData.Type = EncryptedXml.XmlEncElementUrl;

            encryptedData.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
            var sessionKey = new RijndaelManaged {KeySize = 256};
            sessionKey.GenerateKey();

            // Encrypt the assertion and add it to the encryptedData instance.
            EncryptedXml encryptedXml = new EncryptedXml();
            byte[] encryptedElement = encryptedXml.EncryptData(assertion.DocumentElement, sessionKey, false);
            encryptedData.CipherData.CipherValue = encryptedElement;

            // Add an encrypted version of the key used.
            encryptedData.KeyInfo = new KeyInfo();

            EncryptedKey encryptedKey = new EncryptedKey
            {
                EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url),
                CipherData = new CipherData(EncryptedXml.EncryptKey(sessionKey.Key,
                    (RSA) encryptionCertificate.PublicKey.Key, false)),
                KeyInfo = new KeyInfo()
            };
            var keyInfoClause = new SecurityTokenReferenceKeyInfoX509Data(encryptionCertificate); //KeyInfoX509Data();
            encryptedKey.KeyInfo.AddClause(keyInfoClause);

            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

            // Create an empty EncryptedAssertion to hook into.
            EncryptedAssertion encryptedAssertion = new EncryptedAssertion();
            encryptedAssertion.encryptedData = new EncryptedData();

            XmlDocument result = new XmlDocument();
            result.XmlResolver = null;
            result.LoadXml(Serialization.SerializeToXmlString(encryptedAssertion));

            XmlElement encryptedDataElement = GetElement(EncryptedData.ELEMENT_NAME, Saml20Constants.XENC,
                result.DocumentElement);
            EncryptedXml.ReplaceElement(encryptedDataElement, encryptedData, false);

            return result;
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
                return (XmlElement) assertionList[0];
            }

            isEncrypted = false;
            return null;
        }

        /// <summary>
        ///     Signs the whole response message
        /// </summary>
        /// <param name="doc">Response xml document</param>
        /// <param name="id">Id of the element to sign. Usually it is the Id of the response message</param>
        /// <param name="cert">The signing certificate</param>
        /// <param name="responseSignatureMethod">Signing method to use</param>
        /// <param name="responseDigestMethod">Digest method to use</param>
        private static void SignWholeResponseMessage(XmlDocument doc, string id, X509Certificate2 cert,
            string responseSignatureMethod, string responseDigestMethod)
        {
            SignedXml signedXml = new SignedXml(doc);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = responseSignatureMethod;
            signedXml.SigningKey = cert.PrivateKey;

            // Retrieve the value of the "ID" attribute on the root assertion element.
            Reference reference = new Reference("#" + id);

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            signedXml.AddReference(reference);

            // Include the public key of the certificate in the assertion.
            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert, X509IncludeOption.EndCertOnly));
            reference.DigestMethod = responseDigestMethod;

            signedXml.ComputeSignature();
            // Append the computed signature. The signature must be placed as the sibling of the Issuer element.
            XmlNodeList nodes = doc.DocumentElement.GetElementsByTagName("Status", Saml20Constants.PROTOCOL);
            nodes[0].ParentNode.InsertBefore(doc.ImportNode(signedXml.GetXml(), true), nodes[0]);
        }

        /// <summary>
        ///     Signs the assertion of a response message
        /// </summary>
        /// <param name="doc">Response xml document</param>
        /// <param name="id">Id of the element to sign. Usually it is the Id of the assertion element</param>
        /// <param name="cert">The signing certificate</param>
        /// <param name="assertionSignatureMethod">The signing method to use</param>
        /// <param name="assertionDigestMethod">The digest method to use</param>
        private static void SignAssertion(XmlDocument doc, string id, X509Certificate2 cert,
            string assertionSignatureMethod, string assertionDigestMethod)
        {
            SignedXml signedXml = new SignedXml(doc);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = assertionSignatureMethod;
            signedXml.SigningKey = cert.PrivateKey;

            // Retrieve the value of the "ID" attribute on the root assertion element.
            Reference reference = new Reference("#" + id);

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.DigestMethod = assertionDigestMethod;
            signedXml.AddReference(reference);

            // Include the public key of the certificate in the assertion.
            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert, X509IncludeOption.EndCertOnly));

            signedXml.ComputeSignature();
            // Append the computed signature. The signature must be placed as the sibling of the Issuer element.
            XmlNodeList nodes = doc.DocumentElement.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION);
            XmlNode assertionNode = nodes[nodes.Count - 1];
            // may return 2 nodes: Issuer of the response and issuer of the assertion
            // doc.DocumentElement.InsertAfter(doc.ImportNode(signedXml.GetXml(), true), nodes[0]);            
            assertionNode.ParentNode.InsertAfter(doc.ImportNode(signedXml.GetXml(), true), assertionNode);
        }

        /// <summary>
        ///     Gets first xml element by element name and namespace
        /// </summary>
        /// <param name="element">the element local name</param>
        /// <param name="elementNS">The namespace</param>
        /// <param name="doc">The source xml element</param>
        /// <returns>Null if not found. Otherwise, return the first found element.</returns>
        private static XmlElement GetElement(string element, string elementNS, XmlElement doc)
        {
            XmlNodeList list = doc.GetElementsByTagName(element, elementNS);
            if (list.Count == 0)
                return null;

            return (XmlElement) list[0];
        }

        /// <summary>
        ///     This class helps create security token reference that looks exactly the same as those found in messages generated
        ///     by well-known providers
        /// </summary>
        private class SecurityTokenReferenceKeyInfoX509Data : KeyInfoClause
        {
            private readonly X509IssuerSerialKeyIdentifierClause x509IssuerSerialKeyIdentifierClause;

            public SecurityTokenReferenceKeyInfoX509Data(X509Certificate2 certificate)
            {
                x509IssuerSerialKeyIdentifierClause = new X509IssuerSerialKeyIdentifierClause(certificate);
            }

            public override XmlElement GetXml()
            {
                var xmlDocument = new XmlDocument()
                {
                    //PreserveWhitespace = true
                };

                XmlElement securityTokenReference = xmlDocument.CreateElement("SecurityTokenReference",
                    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
                XmlElement x509DataElement = xmlDocument.CreateElement("X509Data", "http://www.w3.org/2000/09/xmldsig#");

                XmlElement x509IssuerSerialElement = xmlDocument.CreateElement("X509IssuerSerial",
                    "http://www.w3.org/2000/09/xmldsig#");
                XmlElement x509IssuerName = xmlDocument.CreateElement("X509IssuerName",
                    "http://www.w3.org/2000/09/xmldsig#");
                x509IssuerName.AppendChild(xmlDocument.CreateTextNode(x509IssuerSerialKeyIdentifierClause.IssuerName));
                x509IssuerSerialElement.AppendChild(x509IssuerName);
                XmlElement x509SerialNumber = xmlDocument.CreateElement("X509SerialNumber",
                    "http://www.w3.org/2000/09/xmldsig#");
                x509SerialNumber.AppendChild(
                    xmlDocument.CreateTextNode(x509IssuerSerialKeyIdentifierClause.IssuerSerialNumber));
                x509IssuerSerialElement.AppendChild(x509SerialNumber);
                x509DataElement.AppendChild(x509IssuerSerialElement);
                securityTokenReference.AppendChild(x509DataElement);
                return securityTokenReference;
            }

            public override void LoadXml(XmlElement element)
            {
                throw new NotImplementedException();
            }
        }
    }
}