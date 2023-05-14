using System;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace rsa_crypto
{

    partial class rsa_crypto
    {

        public byte[] CreateRSAHash(string data, RSAParameters privateKey)
        {
            byte[] messageBytes = Encoding.UTF8.GetBytes(data);
            using (var sha1 = new SHA1Managed())
            {
                byte[] hash = sha1.ComputeHash(messageBytes);
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(privateKey);
                    return rsa.SignHash(hash, CryptoConfig.MapNameToOID("SHA1")); ;
                }
            }
        }

        public bool VerifyRSAHashForMultipleRoots(string filePath, string data, byte[] signature)
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.Load(filePath);

            var rootElements = xmlDoc.DocumentElement.ChildNodes;

            foreach (XmlNode rootNode in rootElements)
            {
                var publicKeyXml = rootNode.SelectSingleNode("PublicKey");
                var publicKey = new RSAParameters();
                publicKey.Modulus = Convert.FromBase64String(publicKeyXml.SelectSingleNode("RSAKeyValue/Modulus").InnerText);
                publicKey.Exponent = Convert.FromBase64String(publicKeyXml.SelectSingleNode("RSAKeyValue/Exponent").InnerText);

                var signatureBase64String = rootNode.SelectSingleNode("Signature").InnerText;
                var signatureBytes = Convert.FromBase64String(signatureBase64String);

                if (VerifyRSAHash(data, signatureBytes, publicKey))
                {
                    return true;
                }
            }

            return false;
        }

        public bool VerifyRSAHashFromFile(string filePath, string data, byte[] signature)
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.Load(filePath);

            var publicKeyXml = xmlDoc.SelectSingleNode("//RSAData/PublicKey");
            var publicKey = new RSAParameters();
            publicKey.Modulus = Convert.FromBase64String(publicKeyXml.SelectSingleNode("RSAKeyValue/Modulus").InnerText);
            publicKey.Exponent = Convert.FromBase64String(publicKeyXml.SelectSingleNode("RSAKeyValue/Exponent").InnerText);

            return VerifyRSAHash(data, signature, publicKey);
        }

        public bool VerifyRSAHash(string data, byte[] signature, RSAParameters publicKey)
        {
            byte[] messageBytes = Encoding.UTF8.GetBytes(data);
            using (var sha1 = new SHA1Managed())
            {
                byte[] hash = sha1.ComputeHash(messageBytes);
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(publicKey);
                    return rsa.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), signature);
                }
            }
        }
        public void ExportRSAKeysAndDataToXml(RSAParameters privateKey, RSAParameters publicKey, string data, byte[] signature, string filePath)
        {
            var settings = new XmlWriterSettings
            {
                Indent = true,
                OmitXmlDeclaration = true,
            };

            XmlDocument xmlDoc = new XmlDocument();
            if (File.Exists(filePath))
            {
                xmlDoc.Load(filePath);
            }
            else
            {
                XmlElement root = xmlDoc.CreateElement("RSADatas");
                xmlDoc.AppendChild(root);
            }

            XmlElement rsaData = xmlDoc.CreateElement("RSAData");

            XmlElement privateKeyXml = xmlDoc.CreateElement("PrivateKey");
            ExportPrivateKeyToXml(privateKey, privateKeyXml);
            rsaData.AppendChild(privateKeyXml);

            XmlElement publicKeyXml = xmlDoc.CreateElement("PublicKey");
            ExportPublicKeyToXml(publicKey, publicKeyXml);
            rsaData.AppendChild(publicKeyXml);

            XmlElement encryptedDataXml = xmlDoc.CreateElement("EncryptedData");
            byte[] encryptedDataBytes = EncryptData(data, publicKey);
            string encryptedDataBase64String = Convert.ToBase64String(encryptedDataBytes);
            encryptedDataXml.InnerText = encryptedDataBase64String;
            rsaData.AppendChild(encryptedDataXml);

            XmlElement signatureXml = xmlDoc.CreateElement("Signature");
            string signatureBase64String = Convert.ToBase64String(signature);
            signatureXml.InnerText = signatureBase64String;
            rsaData.AppendChild(signatureXml);

            xmlDoc.DocumentElement.AppendChild(rsaData);

            using (var stream = new FileStream(filePath, FileMode.Create))
            using (var xmlWriter = XmlWriter.Create(stream, settings))
            {
                xmlDoc.WriteTo(xmlWriter);
            }
        }

        private static void ExportPrivateKeyToXml(RSAParameters privateKey, XmlElement privateKeyXml)
        {
            var modulusElement = privateKeyXml.OwnerDocument.CreateElement("Modulus");
            modulusElement.InnerText = Convert.ToBase64String(privateKey.Modulus);
            privateKeyXml.AppendChild(modulusElement);

            var exponentElement = privateKeyXml.OwnerDocument.CreateElement("Exponent");
            exponentElement.InnerText = Convert.ToBase64String(privateKey.Exponent);
            privateKeyXml.AppendChild(exponentElement);

            var dElement = privateKeyXml.OwnerDocument.CreateElement("D");
            dElement.InnerText = Convert.ToBase64String(privateKey.D);
            privateKeyXml.AppendChild(dElement);

            var pElement = privateKeyXml.OwnerDocument.CreateElement("P");
            pElement.InnerText = Convert.ToBase64String(privateKey.P);
            privateKeyXml.AppendChild(pElement);

            var qElement = privateKeyXml.OwnerDocument.CreateElement("Q");
            qElement.InnerText = Convert.ToBase64String(privateKey.Q);
            privateKeyXml.AppendChild(qElement);

            var dpElement = privateKeyXml.OwnerDocument.CreateElement("DP");
            dpElement.InnerText = Convert.ToBase64String(privateKey.DP);
            privateKeyXml.AppendChild(dpElement);

            var dqElement = privateKeyXml.OwnerDocument.CreateElement("DQ");
            dqElement.InnerText = Convert.ToBase64String(privateKey.DQ);
            privateKeyXml.AppendChild(dqElement);

            var inverseQElement = privateKeyXml.OwnerDocument.CreateElement("InverseQ");
            inverseQElement.InnerText = Convert.ToBase64String(privateKey.InverseQ);
            privateKeyXml.AppendChild(inverseQElement);
        }

        private static void ExportPublicKeyToXml(RSAParameters publicKey, XmlElement publicKeyXml)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(publicKey);
            var rsaFormatter = new RSAPKCS1KeyExchangeFormatter(rsa);
            var encryptedKey = rsaFormatter.CreateKeyExchange(publicKey.Exponent);

            var encryptedKeyElement = publicKeyXml.OwnerDocument.CreateElement("RSAKeyValue");
            var modulusElement = publicKeyXml.OwnerDocument.CreateElement("Modulus");
            var exponentElement = publicKeyXml.OwnerDocument.CreateElement("Exponent");

            modulusElement.InnerText = Convert.ToBase64String(publicKey.Modulus);
            exponentElement.InnerText = Convert.ToBase64String(publicKey.Exponent);
            encryptedKeyElement.AppendChild(modulusElement);
            encryptedKeyElement.AppendChild(exponentElement);

            publicKeyXml.AppendChild(encryptedKeyElement);
        }

        public byte[] EncryptData(string data, RSAParameters publicKey)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);
                return rsa.Encrypt(dataBytes, false);
            }
        }

    }
}
