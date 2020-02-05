using GostCryptography.Cryptography;
using System.Security.Cryptography;
using System.Xml;

namespace GostCryptography.Xml.SMEV
{
	public class SmevSignedXml : SignedXml
	{
		public static string XmlWsuNamespaceUrl = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
		public static string XmlWsseNamespaceUrl = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
		public static string XmlWssBinaryUrl = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
		public static string XmlWssTokenceUrl = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
		public static string XmlSoapNamespaceUrl = "http://schemas.xmlsoap.org/soap/envelope/";
		public static string XmlSoap12NamespaceUrl = "http://www.w3.org/2003/05/soap-envelope";

		public const string XmlDsigSmevTransformUrl = "urn://smev-gov-ru/xmldsig/transform";

		public SmevSignedXml(XmlDocument document)
			: base(document)
		{
		}

		public SmevSignedXml(XmlElement document)
			: base(document)
		{
		}

		public override XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			var nsmgr = new XmlNamespaceManager(document.NameTable);
			nsmgr.AddNamespace("wsu", XmlWsuNamespaceUrl);
			var e = document.SelectSingleNode("//*[@wsu:Id='" + idValue + "']", nsmgr) as XmlElement;
			if (e != null)
				return e;
			return document.SelectSingleNode("//*[@Id='" + idValue + "']") as XmlElement;
		}

		public void ComputeSignature(string prefix)
		{
			BuildDigestedReferences();
			SignatureDescription description = GostCryptoConfig.CreateFromName(this.SignedInfo.SignatureMethod) as SignatureDescription;

			HashAlgorithm hash = description.CreateDigest();

			GetDigest(hash, prefix);
			this.m_signature.SignatureValue = description.CreateFormatter(this.SigningKey).CreateSignature(hash);

		}

		private byte[] GetDigest(HashAlgorithm hash, string prefix)
		{
			XmlDocument document = new XmlDocument();
			document.PreserveWhitespace = true;

			XmlElement e = this.SignedInfo.GetXml();
			document.AppendChild(document.ImportNode(e, true));

			Transform canonicalizationMethodObject = this.SignedInfo.CanonicalizationMethodObject;
			SetPrefix(prefix, document);

			canonicalizationMethodObject.LoadInput(document);
			return canonicalizationMethodObject.GetDigestedOutput(hash);
		}

		private void SetPrefix(string prefix, XmlNode node)
		{
			foreach (XmlNode n in node.ChildNodes)
				SetPrefix(prefix, n);
			node.Prefix = prefix;
		}

		public XmlElement GetXml(string prefix)
		{
			XmlElement e = this.GetXml();
			SetPrefix(prefix, e);
			return e;
		}
	}
}
