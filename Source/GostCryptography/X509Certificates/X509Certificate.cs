//
// X509Certificates.cs: Handles X.509 certificates.
//
// Author:
//	Sebastien Pouliot  <sebastien@xamarin.com>
//
// (C) 2002, 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) 2004-2006 Novell, Inc (http://www.novell.com)
// Copyright 2013 Xamarin Inc. (http://www.xamarin.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;
using GostCryptography.Asn1;
using GostCryptography.Asn1.Common;
using GostCryptography.Cryptography;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.X509Certificates
{
	public enum X509NameType
	{
		SimpleName = 0,
		EmailName,
		UpnName,
		DnsName,
		DnsFromAlternativeName,
		UrlName
	}

	public enum X509IncludeOption
	{
		None = 0,
		ExcludeRoot,
		EndCertOnly,
		WholeChain
	}

	public enum X509ContentType
	{
		Unknown = 0x00,
		Cert = 0x01,
		SerializedCert = 0x02,
		Pfx = 0x03,
		Pkcs12 = Pfx,
		SerializedStore = 0x04,
		Pkcs7 = 0x05,
		Authenticode = 0x06
	}

	// DefaultKeySet, UserKeySet and MachineKeySet are mutually exclusive
	[Serializable]
	[Flags]
	public enum X509KeyStorageFlags
	{
		DefaultKeySet = 0x00,
		UserKeySet = 0x01,
		MachineKeySet = 0x02,
		Exportable = 0x04,
		UserProtected = 0x08,
		PersistKeySet = 0x10
	}

	[SecurityCritical]
	public sealed class PublicKey
	{
		private AsymmetricAlgorithm _key;
		private AsnEncodedData _keyValue;
		private AsnEncodedData _params;
		private Oid _oid;

		static byte[] Empty = new byte[0];

		public PublicKey(Oid oid, AsnEncodedData parameters, AsnEncodedData keyValue)
		{
			if (oid == null)
				throw new ArgumentNullException("oid");
			if (parameters == null)
				throw new ArgumentNullException("parameters");
			if (keyValue == null)
				throw new ArgumentNullException("keyValue");

			_oid = oid;//new Oid(oid);
			_params = new AsnEncodedData(parameters);
			_keyValue = new AsnEncodedData(keyValue);
		}

		//internal PublicKey(X509Certificate certificate)
		//{
		//	// note: _key MUSTonly contains the public part of the key
		//	_oid = new Oid(certificate.KeyAlgorithm);
		//	_keyValue = new AsnEncodedData(_oid, certificate.PublicKey);
		//	_params = new AsnEncodedData(_oid, certificate.KeyAlgorithmParameters ?? Empty);
		//}

		// properties

		public AsnEncodedData EncodedKeyValue
		{
			get { return _keyValue; }
		}

		public AsnEncodedData EncodedParameters
		{
			get { return _params; }
		}

		public AsymmetricAlgorithm Key
		{
			get
			{
				if (_key == null)
				{
					if (_key == null)
					{
						switch (_oid.Value)
						{
							case Constants.szOID_RSA:
								_key = CryptoApiHelper.DecodeRSA(_keyValue.RawData);
								break;
							case Constants.szOID_X957_DSA:
								_key = CryptoApiHelper.DecodeDSA(_keyValue.RawData, _params.RawData);
								break;
							case Constants.OID_GR3410_2001:
                            case Constants.OID_GR3410_12_256:
                            case Constants.OID_GR3410_12_512:
                                var cspObject = new GostKeyExchangeParameters();
								cspObject.DecodeParameters(_params.RawData);
								cspObject.DecodePublicKey(_keyValue.RawData);

								var cspBlobData = CryptoApiHelper.EncodePublicBlob(cspObject, 
                                                _oid.Value == Constants.OID_GR3410_12_256 ? GostAlgorithmType.Gost2012_256 :
                                                _oid.Value == Constants.OID_GR3410_12_512 ? GostAlgorithmType.Gost2012_512 : GostAlgorithmType.Gost2001);

                                if (_oid.Value == Constants.OID_GR3410_12_256)
                                {
                                    var publicKey = new Gost3410_2012_256AsymmetricAlgorithm();
                                    publicKey.ImportCspBlob(cspBlobData);

                                    _key = publicKey;
                                }
                                else
                                if (_oid.Value == Constants.OID_GR3410_12_512)
                                {
                                    var publicKey = new Gost3410_2012_512AsymmetricAlgorithm();
                                    publicKey.ImportCspBlob(cspBlobData);

                                    _key = publicKey;
                                }
                                else
                                {
                                    var publicKey = new Gost3410AsymmetricAlgorithm();
                                    publicKey.ImportCspBlob(cspBlobData);

                                    _key = publicKey;
                                }
                                break;
                            default:
								string msg = String.Format("Cannot decode public key from unknown OID '{0}'.", _oid.Value);
								throw new NotSupportedException(msg);
						}
					}
				}
				return _key;
			}
		}

		public Oid Oid
		{
			get { return _oid; }
		}
	}

	// References:
	// a.	Internet X.509 Public Key Infrastructure Certificate and CRL Profile
	//	http://www.ietf.org/rfc/rfc3280.txt
	// b.	ITU ASN.1 standards (free download)
	//	http://www.itu.int/ITU-T/studygroups/com17/languages/
	public class X509Certificate : ISerializable
	{

		private ASN1 decoder;

		private byte[] m_encodedcert;
		private DateTime m_from;
		private DateTime m_until;
		private ASN1 issuer;
		private string m_issuername;
		private string m_keyalgo;
		private byte[] m_keyalgoparams;
		private ASN1 subject;
		private string m_subject;
		private byte[] m_rawpublickey;
		private PublicKey m_publickey;
		private AsymmetricAlgorithm m_privatekey;
		private byte[] signature;
		private string m_signaturealgo;
		private byte[] m_signaturealgoparams;
		private byte[] certhash;
		private byte[] m_cachedCertificateHash;

		// from http://www.ietf.org/rfc/rfc2459.txt
		//
		//Certificate  ::=  SEQUENCE  {
		//     tbsCertificate       TBSCertificate,
		//     signatureAlgorithm   AlgorithmIdentifier,
		//     signature            BIT STRING  }
		//
		//TBSCertificate  ::=  SEQUENCE  {
		//     version         [0]  Version DEFAULT v1,
		//     serialNumber         CertificateSerialNumber,
		//     signature            AlgorithmIdentifier,
		//     issuer               Name,
		//     validity             Validity,
		//     subject              Name,
		//     subjectPublicKeyInfo SubjectPublicKeyInfo,
		//     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
		//                          -- If present, version shall be v2 or v3
		//     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
		//                          -- If present, version shall be v2 or v3
		//     extensions      [3]  Extensions OPTIONAL
		//                          -- If present, version shall be v3 --  }
		private int version;
		private byte[] serialnumber;

		private byte[] issuerUniqueID;
		private byte[] subjectUniqueID;
		private X509ExtensionCollection extensions;

		private static string encoding_error = Resources.EncodingError;


		// that's were the real job is!
		private void Parse(byte[] data)
		{
			try
			{
				decoder = new ASN1(data);
				// Certificate 
				if (decoder.Tag != 0x30)
					throw new CryptographicException(encoding_error);
				// Certificate / TBSCertificate
				if (decoder[0].Tag != 0x30)
					throw new CryptographicException(encoding_error);

				ASN1 tbsCertificate = decoder[0];

				int tbs = 0;
				// Certificate / TBSCertificate / Version
				ASN1 v = decoder[0][tbs];
				version = 1;            // DEFAULT v1
				if ((v.Tag == 0xA0) && (v.Count > 0))
				{
					// version (optional) is present only in v2+ certs
					version += v[0].Value[0];   // zero based
					tbs++;
				}

				// Certificate / TBSCertificate / CertificateSerialNumber
				ASN1 sn = decoder[0][tbs++];
				if (sn.Tag != 0x02)
					throw new CryptographicException(encoding_error);
				serialnumber = sn.Value;
				Array.Reverse(serialnumber, 0, serialnumber.Length);

				// Certificate / TBSCertificate / AlgorithmIdentifier
				tbs++;
				// ASN1 signatureAlgo = tbsCertificate.Element (tbs++, 0x30); 

				issuer = tbsCertificate.Element(tbs++, 0x30);
				m_issuername = X501.ToString(issuer);

				ASN1 validity = tbsCertificate.Element(tbs++, 0x30);
				ASN1 notBefore = validity[0];
				m_from = ASN1Convert.ToDateTime(notBefore);
				ASN1 notAfter = validity[1];
				m_until = ASN1Convert.ToDateTime(notAfter);

				subject = tbsCertificate.Element(tbs++, 0x30);
				m_subject = X501.ToString(subject);

				ASN1 subjectPublicKeyInfo = tbsCertificate.Element(tbs++, 0x30);

				ASN1 algorithm = subjectPublicKeyInfo.Element(0, 0x30);
				ASN1 algo = algorithm.Element(0, 0x06);
				m_keyalgo = ASN1Convert.ToOid(algo);
				// parameters ANY DEFINED BY algorithm OPTIONAL
				// so we dont ask for a specific (Element) type and return DER
				ASN1 parameters = algorithm[1];
				m_keyalgoparams = ((algorithm.Count > 1) ? parameters.GetBytes() : null);

				ASN1 subjectPublicKey = subjectPublicKeyInfo.Element(1, 0x03);
				// we must drop th first byte (which is the number of unused bits
				// in the BITSTRING)
				int n = subjectPublicKey.Length - 1;
				m_rawpublickey = new byte[n];
				Buffer.BlockCopy(subjectPublicKey.Value, 1, m_rawpublickey, 0, n);

				// signature processing
				byte[] bitstring = decoder[2].Value;
				// first byte contains unused bits in first byte
				signature = new byte[bitstring.Length - 1];
				Buffer.BlockCopy(bitstring, 1, signature, 0, signature.Length);

				algorithm = decoder[1];
				algo = algorithm.Element(0, 0x06);
				m_signaturealgo = ASN1Convert.ToOid(algo);
				parameters = algorithm[1];
				if (parameters != null)
					m_signaturealgoparams = parameters.GetBytes();
				else
					m_signaturealgoparams = null;

				// Certificate / TBSCertificate / issuerUniqueID
				ASN1 issuerUID = tbsCertificate.Element(tbs, 0x81);
				if (issuerUID != null)
				{
					tbs++;
					issuerUniqueID = issuerUID.Value;
				}

				// Certificate / TBSCertificate / subjectUniqueID
				ASN1 subjectUID = tbsCertificate.Element(tbs, 0x82);
				if (subjectUID != null)
				{
					tbs++;
					subjectUniqueID = subjectUID.Value;
				}

				// Certificate / TBSCertificate / Extensions
				ASN1 extns = tbsCertificate.Element(tbs, 0xA3);
				if ((extns != null) && (extns.Count == 1))
					extensions = new X509ExtensionCollection(extns[0]);
				else
					extensions = new X509ExtensionCollection(null);

				// keep a copy of the original data
				m_encodedcert = (byte[])data.Clone();
			}
			catch (Exception ex)
			{
				throw new CryptographicException(encoding_error, ex);
			}
		}

		// constructors

		public X509Certificate(byte[] data)
		{
			if (data != null)
			{
				// does it looks like PEM ?
				if ((data.Length > 0) && (data[0] != 0x30))
				{
					try
					{
						data = PEM("CERTIFICATE", data);
					}
					catch (Exception ex)
					{
						throw new CryptographicException(encoding_error, ex);
					}
				}
				Parse(data);
			}
		}

		private byte[] GetUnsignedBigInteger(byte[] integer)
		{
			if (integer[0] == 0x00)
			{
				// this first byte is added so we're sure it's an unsigned integer
				// however we can't feed it into RSAParameters or DSAParameters
				int length = integer.Length - 1;
				byte[] uinteger = new byte[length];
				Buffer.BlockCopy(integer, 1, uinteger, 0, length);
				return uinteger;
			}
			else
				return integer;
		}

		// public methods

		public X509ExtensionCollection Extensions
		{
			get { return extensions; }
		}

		public byte[] Hash
		{
			get
			{
				if (certhash == null)
				{
				//	if ((decoder == null) || (decoder.Count < 1))
				//		return null;
				//	string algo = PKCS1.HashNameFromOid(m_signaturealgo, false);
				//	if (algo == null)
				//		return null;
				//	byte[] toBeSigned = decoder[0].GetBytes();
				//	using (var hash = PKCS1.CreateFromName(algo))
				//		certhash = hash.ComputeHash(toBeSigned, 0, toBeSigned.Length);
					certhash = GetCertHash();
				}
				return (byte[])certhash.Clone();
			}
		}

		public virtual string IssuerName
		{
			get { return m_issuername; }
		}

		public virtual string KeyAlgorithm
		{
			get { return m_keyalgo; }
		}

		public virtual byte[] KeyAlgorithmParameters
		{
			get
			{
				if (m_keyalgoparams == null)
					return null;
				return (byte[])m_keyalgoparams.Clone();
			}
			set { m_keyalgoparams = value; }
		}

		public virtual byte[] RawPublicKey
		{
			get
			{
				if (m_rawpublickey == null)
					return null;
				return (byte[])m_rawpublickey.Clone();
			}
		}

		public PublicKey PublicKey
		{
			get
			{

				if (m_publickey == null)
				{
					byte[] parameters = this.KeyAlgorithmParameters;
					//Oid oid = new Oid(friendlyName, OidGroup.PublicKeyAlgorithm, true);
					//Oid oid = Oid.FromOidValue(KeyAlgorithm, OidGroup.PublicKeyAlgorithm);
					Oid oid = new Oid(KeyAlgorithm);
                    m_publickey = new PublicKey(oid, new AsnEncodedData(oid, parameters), new AsnEncodedData(oid, m_rawpublickey));
				}

				return m_publickey;
			}
		}

		public AsymmetricAlgorithm PrivateKey
		{
			get
			{
				if (m_privatekey == null)
				{
					CspParameters parameters = new CspParameters();
					// We never want to stomp over certificate private keys.
					parameters.Flags |= CspProviderFlags.UseExistingKey;
					switch (this.PublicKey.Oid.Value)
					{
						case Constants.szOID_RSA:
							m_privatekey = new RSACryptoServiceProvider(parameters);
							break;
						case Constants.szOID_X957_DSA:
							m_privatekey = new DSACryptoServiceProvider(parameters);
							break;
						case Constants.OID_GR3410_2001:
							m_privatekey = new Gost3410AsymmetricAlgorithm(GostCryptoConfig.KeyContainerParameters);
							break;
                        case Constants.OID_GR3410_12_256:
                            m_privatekey = new Gost3410_2012_256AsymmetricAlgorithm(GostCryptoConfig.KeyContainerParameters);
                            break;
                        case Constants.OID_GR3410_12_512:
                            m_privatekey = new Gost3410_2012_512AsymmetricAlgorithm(GostCryptoConfig.KeyContainerParameters);
                            break;
                        default:
							string msg = String.Format("Cannot decode private key from unknown OID '{0}'.", this.PublicKey.Oid.Value);
							throw new NotSupportedException(msg);
					}
				}

				return m_privatekey;
			}
		}

		public virtual byte[] RawData
		{
			get
			{
				if (m_encodedcert == null)
					return null;
				return (byte[])m_encodedcert.Clone();
			}
		}

		public virtual string SerialNumber
		{
			get
			{
				if (serialnumber == null)
					return null;
				return X509Utils.EncodeHexStringFromInt((byte[])serialnumber.Clone());
			}
		}

		public virtual byte[] Signature
		{
			get
			{
				if (signature == null)
					return null;

				switch (m_signaturealgo)
				{
					case "1.2.840.113549.1.1.2":    // MD2 with RSA encryption 
					case "1.2.840.113549.1.1.3":    // MD4 with RSA encryption 
					case "1.2.840.113549.1.1.4":    // MD5 with RSA encryption 
					case "1.2.840.113549.1.1.5":    // SHA-1 with RSA Encryption 
					case "1.3.14.3.2.29":           // SHA1 with RSA signature
					case "1.2.840.113549.1.1.11":   // SHA-256 with RSA Encryption
					case "1.2.840.113549.1.1.12":   // SHA-384 with RSA Encryption
					case "1.2.840.113549.1.1.13":   // SHA-512 with RSA Encryption
					case "1.3.36.3.3.1.2":          // RIPEMD160 with RSA Encryption
						return (byte[])signature.Clone();

					case "1.2.840.10040.4.3":   // SHA-1 with DSA
						ASN1 sign = new ASN1(signature);
						if ((sign == null) || (sign.Count != 2))
							return null;
						byte[] part1 = sign[0].Value;
						byte[] part2 = sign[1].Value;
						byte[] sig = new byte[40];
						// parts may be less than 20 bytes (i.e. first bytes were 0x00)
						// parts may be more than 20 bytes (i.e. first byte > 0x80, negative)
						int s1 = System.Math.Max(0, part1.Length - 20);
						int e1 = System.Math.Max(0, 20 - part1.Length);
						Buffer.BlockCopy(part1, s1, sig, e1, part1.Length - s1);
						int s2 = System.Math.Max(0, part2.Length - 20);
						int e2 = System.Math.Max(20, 40 - part2.Length);
						Buffer.BlockCopy(part2, s2, sig, e2, part2.Length - s2);
						return sig;

					default:
						throw new CryptographicException("Unsupported hash algorithm: " + m_signaturealgo);
				}
			}
		}

		public virtual string SignatureAlgorithm
		{
			get { return m_signaturealgo; }
		}

		public virtual byte[] SignatureAlgorithmParameters
		{
			get
			{
				if (m_signaturealgoparams == null)
					return m_signaturealgoparams;
				return (byte[])m_signaturealgoparams.Clone();
			}
		}

		public virtual string SubjectName
		{
			get { return m_subject; }
		}

		public virtual DateTime ValidFrom
		{
			get { return m_from; }
		}

		public virtual DateTime ValidUntil
		{
			get { return m_until; }
		}

		public int Version
		{
			get { return version; }
		}

		public bool IsCurrent
		{
			get { return WasCurrent(DateTime.UtcNow); }
		}

		public bool WasCurrent(DateTime instant)
		{
			return ((instant > ValidFrom) && (instant <= ValidUntil));
		}

		// uncommon v2 "extension"
		public byte[] IssuerUniqueIdentifier
		{
			get
			{
				if (issuerUniqueID == null)
					return null;
				return (byte[])issuerUniqueID.Clone();
			}
		}

		// uncommon v2 "extension"
		public byte[] SubjectUniqueIdentifier
		{
			get
			{
				if (subjectUniqueID == null)
					return null;
				return (byte[])subjectUniqueID.Clone();
			}
		}

		//public bool VerifySignature(AsymmetricAlgorithm aa)
		//{
		//	if (aa == null)
		//		throw new ArgumentNullException("aa");

		//	if (aa is RSA)
		//		return VerifySignature(aa as RSA);
		//	else if (aa is DSA)
		//		return VerifySignature(aa as DSA);
		//	else
		//		throw new NotSupportedException("Unknown Asymmetric Algorithm " + aa.ToString());
		//}

		//public bool CheckSignature(byte[] hash, string hashAlgorithm, byte[] signature)
		//{
		//	RSACryptoServiceProvider r = (RSACryptoServiceProvider)RSA;
		//	return r.VerifyHash(hash, hashAlgorithm, signature);
		//}

		//public bool IsSelfSigned
		//{
		//	get
		//	{
		//		if (m_issuername != m_subject)
		//			return false;

		//		try
		//		{
		//			if (RSA != null)
		//				return VerifySignature(RSA);
		//			else if (DSA != null)
		//				return VerifySignature(DSA);
		//			else
		//				return false; // e.g. a certificate with only DSA parameters
		//		}
		//		catch (CryptographicException)
		//		{
		//			return false;
		//		}
		//	}
		//}

		public ASN1 GetIssuerName()
		{
			return issuer;
		}

		public ASN1 GetSubjectName()
		{
			return subject;
		}

		protected X509Certificate(SerializationInfo info, StreamingContext context)
		{
			Parse((byte[])info.GetValue("raw", typeof(byte[])));
		}

		[SecurityCritical]
		[SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
		public virtual void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			info.AddValue("raw", m_encodedcert);
			// note: we NEVER serialize the private key
		}

		// LAMESPEC: This is the equivalent of the "thumbprint" that can be seen
		// in the certificate viewer of Windows. This is ALWAYS the SHA1 hash of
		// the certificate (i.e. it has nothing to do with the actual hash 
		// algorithm used to sign the certificate).		
        public virtual byte[] GetCertHash()
		{
			// we'll hash the cert only once and only if required
			if (m_cachedCertificateHash == null)
			{
				SHA1 sha = SHA1.Create();
				m_cachedCertificateHash = sha.ComputeHash(RawData);
			}
			return m_cachedCertificateHash;
		}

		public string Thumbprint
		{
			get
			{
				return X509Utils.EncodeHexString(GetCertHash());
			}
		}

		// FIXME - Could be more efficient
		public bool HasPrivateKey
		{
			get { return PrivateKey != null; }
		}

		static byte[] PEM(string type, byte[] data)
		{
			string pem = Encoding.ASCII.GetString(data);
			string header = String.Format("-----BEGIN {0}-----", type);
			string footer = String.Format("-----END {0}-----", type);
			int start = pem.IndexOf(header) + header.Length;
			int end = pem.IndexOf(footer, start);
			string base64 = pem.Substring(start, (end - start));
			return Convert.FromBase64String(base64);
		}
	}
}