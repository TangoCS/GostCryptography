﻿using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;
using GostCryptography.Asn1.Common;
using GostCryptography.Native;
using GostCryptography.Properties;
using GostCryptography.X509Certificates;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Базовый класс для всех реализаций алгоритма ГОСТ Р 34.10.
	/// </summary>
	public abstract class Gost3410 : AsymmetricAlgorithm
	{
        /// <summary>
        /// Наименование алгоритма цифровой подписи по ГОСТ Р 34.10.
        /// </summary>
        protected abstract string Gost3410SignatureAlgorithm { get; }

		/// <summary>
		/// Наименование алгоритма обмена ключами по ГОСТ Р 34.10.
		/// </summary>
		protected abstract string Gost3410KeyExchangeAlgorithm { get; }

		/// <summary>
		/// Алгоритм цифровой подписи.
		/// </summary>
		public override string SignatureAlgorithm
		{
			get { return Gost3410SignatureAlgorithm; }
		}

		/// <summary>
		/// Алгоритм обмена ключами.
		/// </summary>
		public override string KeyExchangeAlgorithm
		{
			get { return Gost3410KeyExchangeAlgorithm; }
		}

        protected Func<SafeKeyHandleImpl> _keyHandleFunc = null;

        protected void UsingKey(Action<SafeKeyHandleImpl> operation)
        {
            if (_keyHandleFunc == null)
                throw new NullReferenceException("Cannot access key: handle function not found");

            SafeKeyHandleImpl keyHandle = _keyHandleFunc();
            operation(keyHandle);
            keyHandle.TryDispose();
        }

        public byte[] ContainerCertificateRaw
        {
            [SecuritySafeCritical, SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            get
            {
                byte[] containerCertificate = null;
                UsingKey(h =>
                {
                    containerCertificate = CryptoApiHelper.GetKeyParameter(h, 0x1a);
                });
                if (containerCertificate == null)
                {
                    return null;
                }
                return containerCertificate;
            }
        }

        public X509Certificate ContainerCertificate
        {
            get
            {
                return new X509Certificate(ContainerCertificateRaw);
            }
        }

        /// <summary>
        /// Вычисляет цифровую подпись.
        /// </summary>
        public abstract byte[] CreateSignature(byte[] hash);

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		public abstract bool VerifySignature(byte[] hash, byte[] signature);

		/// <summary>
		/// Создает общий секретный ключ.
		/// </summary>
		/// <param name="keyParameters">Параметры открытого ключа, используемого для создания общего секретного ключа.</param>
		public abstract GostSharedSecret CreateKeyExchange(GostKeyExchangeParameters keyParameters);

		/// <summary>
		/// Экспортирует (шифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="includePrivateKey">Включить секретный ключ.</param>
		public abstract GostKeyExchangeParameters ExportParameters(bool includePrivateKey);

		/// <summary>
		/// Импортирует (дешифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="keyParameters">Параметры ключа, используемого для создания общего секретного ключа.</param>
		public abstract void ImportParameters(GostKeyExchangeParameters keyParameters);

		/// <summary>
		/// Экспортирует (шифрует) в XML параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="includePrivateKey">Включить секретный ключ.</param>
		public override string ToXmlString(bool includePrivateKey)
		{
			var keyParameters = ExportParameters(includePrivateKey);
			return KeyParametersToXml(keyParameters);
		}

		/// <summary>
		/// Импортирует (дешифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="keyParametersXml">Параметры ключа, используемого для создания общего секретного ключа.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
        //TODO Security [ReflectionPermission(SecurityAction.Assert, MemberAccess = true)]
        public override void FromXmlString(string keyParametersXml)
		{
			if (string.IsNullOrEmpty(keyParametersXml))
			{
				throw ExceptionUtility.ArgumentNull("keyParametersXml");
			}

			var keyParameters = KeyParametersFromXml(keyParametersXml);
			ImportParameters(keyParameters);
		}

		private static string KeyParametersToXml(GostKeyExchangeParameters parameters)
		{
			var builder = new StringBuilder().AppendFormat("<{0}>", KeyValueXmlTag);

			if ((parameters.DigestParamSet != null) || (parameters.EncryptionParamSet != null) || (parameters.PublicKeyParamSet != null))
			{
				builder.AppendFormat("<{0}>", PublicKeyParametersXmlTag);
				builder.AppendFormat("<{0}>{1}{2}</{0}>", PublicKeyParamSetXmlTag, UrnOidXmlTerm, parameters.PublicKeyParamSet);
				builder.AppendFormat("<{0}>{1}{2}</{0}>", DigestParamSetXmlTag, UrnOidXmlTerm, parameters.DigestParamSet);

				if (parameters.EncryptionParamSet != null)
				{
					builder.AppendFormat("<{0}>{1}{2}</{0}>", EncryptionParamSetXmlTag, UrnOidXmlTerm, parameters.EncryptionParamSet);
				}

				builder.AppendFormat("</{0}>", PublicKeyParametersXmlTag);
			}

			builder.AppendFormat("<{0}>{1}</{0}>", PublicKeyXmlTag, Convert.ToBase64String(parameters.PublicKey));

			if (parameters.PrivateKey != null)
			{
				builder.AppendFormat("<{0}>{1}</{0}>", PrivateKeyXmlTag, Convert.ToBase64String(parameters.PublicKey));
			}

			builder.AppendFormat("</{0}>", KeyValueXmlTag);

			return builder.ToString();
		}

		[SecurityCritical]
		private static GostKeyExchangeParameters KeyParametersFromXml(string keyParametersXml)
		{
			var parameters = new GostKeyExchangeParameters();

			var keyValue = SecurityElement.FromString(keyParametersXml);

			if (keyValue == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, KeyValueXmlTag);
			}

			keyValue = SelectChildElement(keyValue, KeyValueXmlTag) ?? keyValue;

			var publicKeyParameters = SelectChildElement(keyValue, PublicKeyParametersXmlTag);

			if (publicKeyParameters != null)
			{
				var publicKeyParamSet = RemoveWhiteSpaces(SelectChildElementText(publicKeyParameters, PublicKeyParamSetXmlTag, false));

				if (!publicKeyParamSet.StartsWith(UrnOidXmlTerm, StringComparison.OrdinalIgnoreCase))
				{
					throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, PublicKeyParamSetXmlTag);
				}

				parameters.PublicKeyParamSet = publicKeyParamSet.Substring(UrnOidXmlTerm.Length);

				var digestParamSet = RemoveWhiteSpaces(SelectChildElementText(publicKeyParameters, DigestParamSetXmlTag, false));

				if (!digestParamSet.StartsWith(UrnOidXmlTerm, StringComparison.OrdinalIgnoreCase))
				{
					throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, DigestParamSetXmlTag);
				}

				parameters.DigestParamSet = digestParamSet.Substring(UrnOidXmlTerm.Length);

				var encryptionParamSet = SelectChildElementText(publicKeyParameters, EncryptionParamSetXmlTag, true);

				if (!string.IsNullOrEmpty(encryptionParamSet))
				{
					encryptionParamSet = RemoveWhiteSpaces(encryptionParamSet);

					if (!encryptionParamSet.StartsWith(UrnOidXmlTerm, StringComparison.OrdinalIgnoreCase))
					{
						throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, EncryptionParamSetXmlTag);
					}

					parameters.EncryptionParamSet = encryptionParamSet.Substring(UrnOidXmlTerm.Length);
				}
			}

			var publicKey = SelectChildElementText(keyValue, PublicKeyXmlTag, false);
			parameters.PublicKey = Convert.FromBase64String(RemoveWhiteSpaces(publicKey));

			var privateKey = SelectChildElementText(keyValue, PrivateKeyXmlTag, true);

			if (privateKey != null)
			{
				parameters.PrivateKey = Convert.FromBase64String(RemoveWhiteSpaces(privateKey));
			}

			return parameters;
		}

		private static string SelectChildElementText(SecurityElement element, string childName, bool canNull)
		{
			string text = null;

			var child = SelectChildElement(element, childName);

			if (child != null && (child.Children == null || child.Children.Count == 0))
			{
				text = child.Text;
			}

			if (string.IsNullOrEmpty(text) && !canNull)
			{
				throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, childName);
			}

			return text;
		}

		private static SecurityElement SelectChildElement(SecurityElement element, string childName)
		{
			var children = element.Children;

			if (children != null)
			{
				foreach (SecurityElement child in children)
				{
					if (string.Equals(child.Tag, childName, StringComparison.OrdinalIgnoreCase)
						|| child.Tag.EndsWith(":" + childName, StringComparison.OrdinalIgnoreCase))
					{
						return child;
					}
				}
			}

			return null;
		}

		private static string RemoveWhiteSpaces(string value)
		{
			var length = value.Length;

			var countWhiteSpace = 0;

			for (var i = 0; i < length; ++i)
			{
				if (char.IsWhiteSpace(value[i]))
				{
					++countWhiteSpace;
				}
			}

			var valueWithoutWhiteSpace = new char[length - countWhiteSpace];

			for (int i = 0, j = 0; i < length; ++i)
			{
				if (!char.IsWhiteSpace(value[i]))
				{
					valueWithoutWhiteSpace[j++] = value[i];
				}
			}

			return new string(valueWithoutWhiteSpace);
		}

		private const string UrnOidXmlTerm = "urn:oid:";
		private const string KeyValueXmlTag = "GostKeyValue";
		private const string PublicKeyParametersXmlTag = "PublicKeyParameters";
		private const string PublicKeyParamSetXmlTag = "publicKeyParamSet";
		private const string DigestParamSetXmlTag = "digestParamSet";
		private const string EncryptionParamSetXmlTag = "encryptionParamSet";
		private const string PublicKeyXmlTag = "PublicKey";
		private const string PrivateKeyXmlTag = "PrivateKey";
	}
}