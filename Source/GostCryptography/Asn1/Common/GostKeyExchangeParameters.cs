using System;
using GostCryptography.Properties;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1;

namespace GostCryptography.Asn1.Common
{
	/// <summary>
	/// Параметры алгоритма цифровой подписи ГОСТ Р 34.10 и алгоритма формирования общего секретного ключа, включая открытый ключ.
	/// </summary>
	public sealed class GostKeyExchangeParameters
	{
		public GostKeyExchangeParameters()
		{
		}

		public GostKeyExchangeParameters(GostKeyExchangeParameters parameters)
		{
			DigestParamSet = parameters.DigestParamSet;
			PublicKeyParamSet = parameters.PublicKeyParamSet;
			EncryptionParamSet = parameters.EncryptionParamSet;
			PublicKey = parameters.PublicKey;
			PrivateKey = parameters.PrivateKey;
		}


		/// <summary>
		/// Идентификатор OID параметров хэширования.
		/// </summary>
		public string DigestParamSet;

		/// <summary>
		/// Идентификатор OID параметров открытого ключа.
		/// </summary>
		public string PublicKeyParamSet;

		/// <summary>
		/// Идентификатор OID параметров шифрования.
		/// </summary>
		public string EncryptionParamSet;

		/// <summary>
		/// Открытый ключ.
		/// </summary>
		public byte[] PublicKey;

		/// <summary>
		/// Закрытый ключ.
		/// </summary>
		public byte[] PrivateKey;


		public void DecodeParameters(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull("data");
			}

			try
			{
				var s = Asn1Object.FromByteArray(data);
				var p = Gost3410PublicKeyAlgParameters.GetInstance(s);
				DigestParamSet = p.DigestParamSet == null ? null : p.DigestParamSet.Id;
				PublicKeyParamSet = p.PublicKeyParamSet == null ? null : p.PublicKeyParamSet.Id;
				EncryptionParamSet = p.EncryptionParamSet == null ? null : p.EncryptionParamSet.Id;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, typeof(Gost3410PublicKeyAlgParameters).FullName);
			}
		}


		public byte[] EncodeParameters()
		{
			byte[] data;

			try
			{
				Gost3410PublicKeyAlgParameters p = new Gost3410PublicKeyAlgParameters(
					new DerObjectIdentifier(PublicKeyParamSet),
					new DerObjectIdentifier(DigestParamSet),
					EncryptionParamSet == null ? null : new DerObjectIdentifier(EncryptionParamSet));
				data = p.GetDerEncoded();

            }
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1EncodeError, typeof(Gost3410PublicKeyAlgParameters).FullName);
			}

			return data;
		}


		public void DecodePublicKey(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull("data");
			}

			try
			{
				var input = new Asn1InputStream(data);
				var obj = input.ReadObject();
				PublicKey = Asn1OctetString.GetInstance(obj).GetOctets();
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, "PublicKey");
			}
		}
	}
}