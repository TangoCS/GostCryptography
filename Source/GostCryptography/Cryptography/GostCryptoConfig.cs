//
// CryptoConfig.cs: Handles cryptographic implementations and OIDs mappings.
//
// Author:
//	Sebastien Pouliot (sebastien@ximian.com)
//	Tim Coleman (tim@timcoleman.com)
//
// (C) 2002, 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) Tim Coleman, 2004
// Copyright (C) 2004-2007,2011 Novell, Inc (http://www.novell.com)
// Copyright (C) 2011 Xamarin Inc. http://www.xamarin.com
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
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Cryptography;
using GostCryptography.Xml;
using GostCryptography.Xml.SMEV;
using GostCryptography.Native;

namespace GostCryptography.Cryptography
{

	[ComVisible(true)]
	public partial class GostCryptoConfig
	{
		static private object lockObject;
		static private Dictionary<string, Type> algorithms;
		static private Dictionary<string, string> unresolved_algorithms;
		static private Dictionary<string, string> oids;

		/// <summary>
		/// Наименование алгоритма подписи по умолчанию.
		/// </summary>
		public const string DefaultSignName = "Gost3410";

        /// <summary>
        /// Идентификатор OID алгоритма подписи по умолчанию.
        /// </summary>
        /// <remarks>
        /// Алгоритм подписи по ГОСТ Р 34.10.
        /// </remarks>
        public const string DefaultSignOid = Constants.OID_GR3410_2001;

		/// <summary>
		/// Наименование алгоритма хэширования по умолчанию.
		/// </summary>
		public const string DefaultHashName = "Gost3411";

        /// <summary>
        /// Идентификатор OID алгоритма хэширования по умолчанию.
        /// </summary>
        /// <remarks>
        /// Алгоритм хэширования по ГОСТ Р 34.11-94.
        /// </remarks>
        public const string DefaultHashOid = Constants.OID_GR3411_2001;


		/// <summary>
		/// Наименование алгоритма шифрования по умолчанию.
		/// </summary>
		public const string DefaultEncryptionName = "Gost28147";

        /// <summary>
        /// Идентификатор OID алгоритма шифрования по умолчанию.
        /// </summary>
        /// <remarks>
        /// Алгоритм симметричного шифрования по ГОСТ 28147-89.
        /// </remarks>
        public const string DefaultEncryptionOid = Constants.OID_GR28147_89;

		/// <summary>
		/// Идентификатор типа криптографического провайдера.
		/// </summary>
		public static int ProviderType { get; set; }

		public static CspParameters KeyContainerParameters { get; set; }


		static GostCryptoConfig()
		{
			// lock(this) is bad
			// http://msdn.microsoft.com/library/en-us/dnaskdr/html/askgui06032003.asp?frame=true
			lockObject = new object();

			ProviderType = ProviderTypes.VipNet;
		}

        /*public static void InitOnFile(byte[] pfx, string password, int type)
        {
            ProviderType = type;
            var keyContainer = new CspParameters();
            keyContainer.ProviderType = ProviderType;
            var cer = new System.Security.Cryptography.X509Certificates.X509Certificate2(pfx, password);
            //var cer = new X509Certificates.X509Certificate(pfx);
            var gost = (Gost3410)cer.PrivateKey;
            keyContainer.KeyNumber = (int)gost.CspKeyContainerInfo.KeyNumber;
            keyContainer.KeyContainerName = gost.CspKeyContainerInfo.KeyContainerName;
            var secureString = new System.Security.SecureString();
            foreach (char c in password.ToCharArray())
                secureString.AppendChar(c);
            keyContainer.KeyPassword = secureString;

            KeyContainerParameters = keyContainer;
        }*/

        public static Gost3410 CreateGost3410AsymmetricAlgorithm()
		{
			if (KeyContainerParameters == null)
				throw new ArgumentNullException("KeyContainerParameters");

            if (ProviderType == ProviderTypes.CryptoPro256)
                return new Gost3410_2012_256AsymmetricAlgorithm(KeyContainerParameters);
            if (ProviderType == ProviderTypes.CryptoPro512)
                return new Gost3410_2012_512AsymmetricAlgorithm(KeyContainerParameters);

            return new Gost3410AsymmetricAlgorithm(KeyContainerParameters);
        }

        public static Gost3411 CreateGost3411HashAlgorithm()
        {
            //if (KeyContainerParameters == null)
            //    throw new ArgumentNullException("KeyContainerParameters");

            if (ProviderType == ProviderTypes.CryptoPro256)
                return new Gost3411_2012_256HashAlgorithm();
            if (ProviderType == ProviderTypes.CryptoPro512)
                return new Gost3411_2012_512HashAlgorithm();

            return new Gost3411HashAlgorithm();
        }

        public static RSACryptoServiceProvider CreateRSAAsymmetricAlgorithm()
		{
			if (KeyContainerParameters == null)
				throw new ArgumentNullException("KeyContainerParameters");

			return new RSACryptoServiceProvider(KeyContainerParameters);
		}

		private static void Initialize()
		{
			algorithms = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase);
			unresolved_algorithms = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			oids = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

			// Информация о свойствах цифровой подписи ГОСТ Р 34.10-2001
			AddAlgorithm<GostSignatureDescription>(SignedXml.XmlDsigGost3410UrlObsolete, SignedXml.XmlDsigGost3410Url);
            AddAlgorithm<Gost2012_256SignatureDescription>(SignedXml.XmlDsigGost3410_2012_256Url);
            AddAlgorithm<Gost2012_512SignatureDescription>(SignedXml.XmlDsigGost3410_2012_512Url);
            AddAlgorithm<RSAPKCS1SHA1SignatureDescription>("RSASignatureDescription", SignedXml.XmlDsigRSASHA1Url);

			// Реализация алгоритма подписи по ГОСТ Р 34.10
			AddAlgorithm<Gost3410AsymmetricAlgorithm>(DefaultSignName);
			AddAlgorithm<RSACryptoServiceProvider>("RSA");

			// Реализация алгоритма хэширования по ГОСТ Р 34.11
			AddAlgorithm<Gost3411HashAlgorithm>(DefaultHashName, SignedXml.XmlDsigGost3411UrlObsolete, SignedXml.XmlDsigGost3411Url);
            AddAlgorithm<Gost3411_2012_256HashAlgorithm>("Gost3411_2012_256", SignedXml.XmlDsigGost3411_2012_256Url);
            AddAlgorithm<Gost3411_2012_512HashAlgorithm>("Gost3411_2012_512", SignedXml.XmlDsigGost3411_2012_512Url);
            AddAlgorithm<SHA1CryptoServiceProvider>("SHA1", SignedXml.XmlDsigSHA1Url);

			// Реализация алгоритма симметричного шифрования по ГОСТ 28147
			AddAlgorithm<Gost28147SymmetricAlgorithm>(DefaultEncryptionName);

			// Реализация функции вычисления имитовставки по ГОСТ 28147
			AddAlgorithm<Gost28147ImitHashAlgorithm>("Gost28147Imit");

			// Реализация HMAC на базе алгоритма хэширования по ГОСТ Р 34.11
			AddAlgorithm<Gost3411Hmac>(SignedXml.XmlDsigGost3411HmacUrl);
            //AddAlgorithm<Gost3411_2012_256Hmac>(SignedXml.XmlDsigGost3411_2012_256HMACUrl);
            //AddAlgorithm<Gost3411_2012_512Hmac>(SignedXml.XmlDsigGost3411_2012_512HMACUrl);

            // Реализация алгоритма генерации псевдослучайной последовательности по ГОСТ Р 34.11
            AddAlgorithm<Gost3411Prf>();

			// Класс вычисления цифровой подписи по ГОСТ Р 34.10-2001
			AddAlgorithm<GostSignatureFormatter>();
			AddAlgorithm<RSAPKCS1SignatureFormatter>();

			// Класс проверки цифровой подписи по ГОСТ Р 34.10-2001
			AddAlgorithm<GostSignatureDeformatter>();
			AddAlgorithm<RSAPKCS1SignatureDeformatter>();

			// Параметры ключа цифровой подписи ГОСТ Р 34.10
			AddAlgorithm<GostKeyValue>(GostKeyValue.XmlDsigGostKeyValueUrl);
			AddAlgorithm<RSAKeyValue>("http://www.w3.org/2000/09/xmldsig# KeyValue/RSAKeyValue");

			// Реализация алгоритма подписи по ГОСТ Р 34.10
			AddOid<Gost3410AsymmetricAlgorithm>(DefaultSignOid, DefaultSignName);
            AddOid<Gost3410_2012_256AsymmetricAlgorithm>(Constants.OID_GR3410_12_256, "Gost3410_2012_256");
            AddOid<Gost3410_2012_512AsymmetricAlgorithm>(Constants.OID_GR3410_12_512, "Gost3410_2012_512");
            AddOid<RSACryptoServiceProvider>(Constants.szOID_RSA, "RSA");

			// Реализация алгоритма хэширования по ГОСТ Р 34.11
			AddOid<Gost3411HashAlgorithm>(DefaultHashOid, DefaultHashName, SignedXml.XmlDsigGost3411UrlObsolete, SignedXml.XmlDsigGost3411Url);
            AddOid<Gost3411_2012_256HashAlgorithm>(Constants.OID_GR3411_12_256, "Gost3411_2012_256", SignedXml.XmlDsigGost3411_2012_256Url);
            AddOid<Gost3411_2012_512HashAlgorithm>(Constants.OID_GR3411_12_512, "Gost3411_2012_512", SignedXml.XmlDsigGost3411_2012_512Url);
            AddOid<SHA1CryptoServiceProvider>(Constants.szOID_OIWSEC_sha1RSASign, "SHA1", "http://www.w3.org/2000/09/xmldsig#sha1");

			// Реализация алгоритма симметричного шифрования по ГОСТ 28147
			AddOid<Gost28147SymmetricAlgorithm>(DefaultEncryptionOid, DefaultEncryptionName);

			AddAlgorithm(typeof(XmlDsigExcC14NTransform), new string[] { SignedXml.XmlDsigExcC14NTransformUrl });
			AddAlgorithm(typeof(XmlDsigC14NTransform), new string[] { SignedXml.XmlDsigC14NTransformUrl });
			AddAlgorithm(typeof(XmlDsigEnvelopedSignatureTransform), new string[] { SignedXml.XmlDsigEnvelopedSignatureTransformUrl });
			AddAlgorithm(typeof(XmlDsigXPathTransform), new string[] { SignedXml.XmlDsigXPathTransformUrl });
			AddAlgorithm(typeof(XmlDsigXsltTransform), new string[] { SignedXml.XmlDsigXsltTransformUrl });
			AddAlgorithm(typeof(XmlDsigSmevTransform), new string[] { SmevSignedXml.XmlDsigSmevTransformUrl });

			AddAlgorithm(typeof(KeyInfoX509Data), new string[] { "http://www.w3.org/2000/09/xmldsig# X509Data" });
			AddAlgorithm(typeof(KeyInfoEncryptedKey), new string[] { "http://www.w3.org/2001/04/xmlenc# EncryptedKey" });
			AddAlgorithm(typeof(KeyInfoName), new string[] { "http://www.w3.org/2000/09/xmldsig# KeyName" });
		}

        //TODO Security [FileIOPermission(SecurityAction.Assert, Unrestricted = true)]
        private static void LoadConfig(string filename, IDictionary<string, Type> algorithms, IDictionary<string, string> oid)
		{
			if (!File.Exists(filename))
				return;

			try
			{
				using (TextReader reader = new StreamReader(filename))
				{
					CryptoHandler handler = new CryptoHandler(algorithms, oid);
					SmallXmlParser parser = new SmallXmlParser();
					parser.Parse(reader, handler);
				}
			}
			catch
			{
			}
		}

		public static object CreateFromName(string name)
		{
			return CreateFromName(name, null);
		}

        //TODO Security [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        public static object CreateFromName(string name, params object[] args)
		{
			if (name == null)
				throw new ArgumentNullException("name");

			lock (lockObject)
			{
				if (algorithms == null)
				{
					Initialize();
				}
			}

			try
			{
				Type algoClass = null;
				if (!algorithms.TryGetValue(name, out algoClass))
				{
					string algo = null;
					if (!unresolved_algorithms.TryGetValue(name, out algo))
						algo = name;
					algoClass = Type.GetType(algo);
				}
				if (algoClass == null)
					return null;
				// call the constructor for the type
				return Activator.CreateInstance(algoClass, args);
			}
			catch
			{
				// method doesn't throw any exception
				return null;
			}
		}

		internal static string MapNameToOID(string name, OidGroup oidGroup)
		{
			return MapNameToOID(name);
		}

		public static string MapNameToOID(string name)
		{
			if (name == null)
				throw new ArgumentNullException("name");

			lock (lockObject)
			{
				if (oids == null)
				{
					Initialize();
				}
			}

			string result = null;
			oids.TryGetValue(name, out result);
			return result;
		}

		public static void AddAlgorithm(Type algorithm, params string[] names)
		{
			if (algorithm == null)
				throw new ArgumentNullException("algorithm");
			if (names == null)
				throw new ArgumentNullException("names");

			foreach (string name in names)
			{
				if (String.IsNullOrWhiteSpace(name))
					throw new ArithmeticException("names");
				algorithms[name] = algorithm;
			}
		}

		public static void AddOID(string oid, params string[] names)
		{
			if (oid == null)
				throw new ArgumentNullException("oid");
			if (names == null)
				throw new ArgumentNullException("names");

			foreach (string name in names)
			{
				if (String.IsNullOrWhiteSpace(name))
					throw new ArithmeticException("names");
				oids[oid] = name;
			}
		}

		private static void AddAlgorithm<T>(params string[] names)
		{
			var type = typeof(T);

			if (names != null)
			{
				foreach (var name in names)
				{
					AddAlgorithm(type, name);
				}
			}

			AddAlgorithm(type, type.Name);
			AddAlgorithm(type, type.FullName);

			if (type.AssemblyQualifiedName != null)
			{
				AddAlgorithm(type, type.AssemblyQualifiedName);
			}
		}

		private static void AddOid<T>(string oid, params string[] names)
		{
			var type = typeof(T);

			if (names != null)
			{
				foreach (var name in names)
				{
					AddOID(oid, name);
				}
			}

			AddOID(oid, type.Name);
			AddOID(oid, type.FullName);

			if (type.AssemblyQualifiedName != null)
			{
				AddOID(oid, type.AssemblyQualifiedName);
			}
		}

		class CryptoHandler : SmallXmlParser.IContentHandler
		{

			IDictionary<string, Type> algorithms;
			IDictionary<string, string> oid;
			Dictionary<string, string> names;
			Dictionary<string, string> classnames;
			int level;

			public CryptoHandler(IDictionary<string, Type> algorithms, IDictionary<string, string> oid)
			{
				this.algorithms = algorithms;
				this.oid = oid;
				// temporary tables to reconstruct algorithms
				names = new Dictionary<string, string>();
				classnames = new Dictionary<string, string>();
			}

			public void OnStartParsing(SmallXmlParser parser)
			{
				// don't care
			}

			public void OnEndParsing(SmallXmlParser parser)
			{
				foreach (var kpv in names)
				{
					try
					{
						algorithms[kpv.Key] = Type.GetType(classnames[kpv.Value]);
					}
					catch
					{
					}
				}
				// matching is done, data no more required
				names.Clear();
				classnames.Clear();
			}

			private string Get(SmallXmlParser.IAttrList attrs, string name)
			{
				for (int i = 0; i < attrs.Names.Length; i++)
				{
					if (attrs.Names[i] == name)
						return attrs.Values[i];
				}
				return String.Empty;
			}

			public void OnStartElement(string name, SmallXmlParser.IAttrList attrs)
			{
				switch (level)
				{
					case 0:
						if (name == "configuration")
							level++;
						break;
					case 1:
						if (name == "mscorlib")
							level++;
						break;
					case 2:
						if (name == "cryptographySettings")
							level++;
						break;
					case 3:
						if (name == "oidMap")
							level++;
						else if (name == "cryptoNameMapping")
							level++;
						break;
					case 4:
						if (name == "oidEntry")
						{
							oid[Get(attrs, "name")] = Get(attrs, "OID");
						}
						else if (name == "nameEntry")
						{
							names[Get(attrs, "name")] = Get(attrs, "class");
						}
						else if (name == "cryptoClasses")
						{
							level++;
						}
						break;
					case 5:
						if (name == "cryptoClass")
							classnames[attrs.Names[0]] = attrs.Values[0];
						break;
				}
			}

			public void OnEndElement(string name)
			{
				// parser will make sure the XML structure is respected
				switch (level)
				{
					case 1:
						if (name == "configuration")
							level--;
						break;
					case 2:
						if (name == "mscorlib")
							level--;
						break;
					case 3:
						if (name == "cryptographySettings")
							level--;
						break;
					case 4:
						if ((name == "oidMap") || (name == "cryptoNameMapping"))
							level--;
						break;
					case 5:
						if (name == "cryptoClasses")
							level--;
						break;
				}
			}

			public void OnProcessingInstruction(string name, string text)
			{
				// don't care
			}

			public void OnChars(string text)
			{
				// don't care
			}

			public void OnIgnorableWhitespace(string text)
			{
				// don't care
			}
		}
	}

	public enum OidGroup
	{
		All = 0,
		HashAlgorithm = 1,
		EncryptionAlgorithm = 2,
		PublicKeyAlgorithm = 3,
		SignatureAlgorithm = 4,
		Attribute = 5,
		ExtensionOrAttribute = 6,
		EnhancedKeyUsage = 7,
		Policy = 8,
		Template = 9,
		KeyDerivationFunction = 10
	}
}