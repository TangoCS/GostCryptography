using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using GostCryptography.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using BCX509 = Org.BouncyCastle.X509;

namespace GostCryptography
{
	class Program
	{
		static void Main(string[] args)
		{
			GostCryptoConfig.ProviderType = ProviderTypes.CryptoPro256;
			Config.InitCommon();

            var alg = GostCryptoConfig.CreateGost3410AsymmetricAlgorithm();
            var par = alg.ExportParameters(false);
            var b = Pkcs.SignedPkcs7.ComputeSignature(File.ReadAllBytes("d:/2018-09-12.zip"));

            File.WriteAllBytes("d:/2018-09-12.zip.sig", b);

            var smev = new Xml.SMEV.XmlDsigSmevTransform();
			var bytes = File.ReadAllBytes("d:/test_2.xml");
			XmlDocument doc = new XmlDocument();
			doc.LoadXml(Encoding.UTF8.GetString(bytes));
			smev.LoadInput(doc);
			var output = (MemoryStream)smev.GetOutput(typeof(Stream));
			File.WriteAllBytes("d:/test_2_result.xml", output.ToArray());

			//var signedXmlDocument = new XmlDocument();
			//signedXmlDocument.LoadXml(File.ReadAllText("saml.xml"));

			//// Создание подписчика XML-документа
			//var signedXml = new SignedXml(signedXmlDocument);

			//// Поиск узла с подписью
			//var nodeList = signedXmlDocument.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);

			//// Загрузка найденной подписи
			//signedXml.LoadXml((XmlElement)nodeList[0]);

			//// Проверка подписи
			//bool b = signedXml.CheckSignature();

			//var t = new SignedXmlKeyContainerTest();
			//t.SetUp();
			//t.ShouldSignXml();
			//t.TearDown();
		}

		public static string RsaEncryptWithPrivate(string clearText, string privateKey)
		{
			var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);
			var encryptEngine = new Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding(new Org.BouncyCastle.Crypto.Engines.RsaEngine());

			using (var txtreader = new StringReader(privateKey))
			{
				var keyPair = (AsymmetricCipherKeyPair)new Org.BouncyCastle.OpenSsl.PemReader(txtreader).ReadObject();
				encryptEngine.Init(true, keyPair.Public);
			}

			var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
			return encrypted;
		}

		static void PKCS7()
		{
			GostCryptoConfig.ProviderType = ProviderTypes.VipNet;
			Config.InitCommon();

			BCX509.X509Certificate bcCert = null;
            using (var g = GostCryptoConfig.CreateGost3410AsymmetricAlgorithm())
			{
				bool detached = false;
                byte[] data = File.ReadAllBytes("test.xml");

				var certBytes = g.ContainerCertificateRaw;

				BCX509.X509CertificateParser _x509CertificateParser = new BCX509.X509CertificateParser();
				bcCert = _x509CertificateParser.ReadCertificate(certBytes);

				ICollection<BCX509.X509Certificate> certPath = new List<BCX509.X509Certificate>();
				certPath.Add(bcCert);

				IDigest digest = new Gost3411Digest();
				string hashOid = GostCryptoConfig.DefaultHashOid;

				byte[] dataHash = ComputeDigest(digest, data);

				// Construct SignerInfo.signedAttrs
				Asn1EncodableVector signedAttributesVector = new Asn1EncodableVector();

				// Add PKCS#9 contentType signed attribute
				signedAttributesVector.Add(
					new Org.BouncyCastle.Asn1.Cms.Attribute(
						new DerObjectIdentifier("1.2.840.113549.1.9.3"),
						new DerSet(new DerObjectIdentifier("1.2.840.113549.1.7.1"))));

				// Add PKCS#9 messageDigest signed attribute
				signedAttributesVector.Add(
					new Org.BouncyCastle.Asn1.Cms.Attribute(
						new DerObjectIdentifier("1.2.840.113549.1.9.4"),
						new DerSet(new DerOctetString(dataHash))));

				// Add PKCS#9 signingTime signed attribute
				signedAttributesVector.Add(
					new Org.BouncyCastle.Asn1.Cms.Attribute(
						new DerObjectIdentifier("1.2.840.113549.1.9.5"),
						new DerSet(new Org.BouncyCastle.Asn1.Cms.Time(new DerUtcTime(DateTime.UtcNow)))));

				DerSet signedAttributes = new DerSet(signedAttributesVector);
				byte[] pkcs1Digest = ComputeDigest(digest, signedAttributes.GetDerEncoded());
				byte[] pkcs1DigestInfo = CreateDigestInfo(pkcs1Digest, hashOid);

				// hash


				//var signature = g.CreateSignature(hash);
				var formatter = new GostSignatureFormatter(g);
				var signature = formatter.CreateSignature(pkcs1Digest);

				// Construct SignerInfo
				SignerInfo signerInfo = new SignerInfo(
					new SignerIdentifier(new IssuerAndSerialNumber(bcCert.IssuerDN, bcCert.SerialNumber)),
					new AlgorithmIdentifier(new DerObjectIdentifier(hashOid), null),
					signedAttributes,
					new AlgorithmIdentifier(new DerObjectIdentifier(GostCryptoConfig.DefaultSignOid), null),
					new DerOctetString(signature),
					null);

				// Construct SignedData.digestAlgorithms
				Asn1EncodableVector digestAlgorithmsVector = new Asn1EncodableVector();
				digestAlgorithmsVector.Add(new AlgorithmIdentifier(new DerObjectIdentifier(hashOid), null));

				// Construct SignedData.encapContentInfo
				ContentInfo encapContentInfo = new ContentInfo(
					new DerObjectIdentifier("1.2.840.113549.1.7.1"),
					(detached) ? null : new DerOctetString(data));

				// Construct SignedData.certificates
				Asn1EncodableVector certificatesVector = new Asn1EncodableVector();
				foreach (BCX509.X509Certificate cert in certPath)
					certificatesVector.Add(X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(cert.GetEncoded())));

				// Construct SignedData.signerInfos
				Asn1EncodableVector signerInfosVector = new Asn1EncodableVector();
				signerInfosVector.Add(signerInfo.ToAsn1Object());

				// Construct SignedData
				SignedData signedData = new SignedData(
					new DerSet(digestAlgorithmsVector),
					encapContentInfo,
					new BerSet(certificatesVector),
					null,
					new DerSet(signerInfosVector));

				// Construct top level ContentInfo
				ContentInfo contentInfo = new ContentInfo(
					new DerObjectIdentifier("1.2.840.113549.1.7.2"),
					signedData);

				var res = contentInfo.GetDerEncoded();
				File.WriteAllBytes("test.p7", res);


				CmsSignedData cms = new CmsSignedData(res);

				var certStore = cms.GetCertificates("Collection");
				

				SignerInformationStore signers = cms.GetSignerInfos();
				var it = signers.GetSigners().GetEnumerator();
				it.MoveNext();
                var signer = it.Current as SignerInformation;

				var b = signer.Verify(bcCert);
			}
		}

		/// <summary>
		/// Creates PKCS#1 DigestInfo
		/// </summary>
		/// <param name="hash">Hash value</param>
		/// <param name="hashOid">Hash algorithm OID</param>
		/// <returns>DER encoded PKCS#1 DigestInfo</returns>
		private static byte[] CreateDigestInfo(byte[] hash, string hashOid)
		{
			DerObjectIdentifier derObjectIdentifier = new DerObjectIdentifier(hashOid);
			AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(derObjectIdentifier, null);
			DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, hash);
			return digestInfo.GetDerEncoded();
		}

		/// <summary>
		/// Computes hash of the data
		/// </summary>
		/// <param name="digest">Hash algorithm implementation</param>
		/// <param name="data">Data that should be processed</param>
		/// <returns>Hash of data</returns>
		private static byte[] ComputeDigest(IDigest digest, byte[] data)
		{
			if (digest == null)
				throw new ArgumentNullException("digest");

			if (data == null)
				throw new ArgumentNullException("data");

			byte[] hash = new byte[digest.GetDigestSize()];

			digest.Reset();
			digest.BlockUpdate(data, 0, data.Length);
			digest.DoFinal(hash, 0);

			return hash;
		}
	}
}
