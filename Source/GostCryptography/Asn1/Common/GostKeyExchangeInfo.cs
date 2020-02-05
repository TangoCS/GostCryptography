using System;
using GostCryptography.Properties;
using Org.BouncyCastle.Asn1;

namespace GostCryptography.Asn1.Common
{
	/// <summary>
	/// Информация о зашифрованном ключе по ГОСТ 28147.
	/// </summary>
	public sealed class GostKeyExchangeInfo
	{
		/// <summary>
		/// Идентификатор OID параметров шифрования.
		/// </summary>
		public string EncryptionParamSet;

		/// <summary>
		/// Зашифрованный ключ.
		/// </summary>
		public byte[] EncryptedKey;

		/// <summary>
		/// Контрольная сумма зашифрованного ключа (Message Authentication Code, MAC).
		/// </summary>
		public byte[] Mac;

		/// <summary>
		/// Материал ключа пользователя (User Keying Material, UKM).
		/// </summary>
		public byte[] Ukm;


		public byte[] Encode()
		{
			byte[] data;

			try
			{
				var s = new DerSequence(
					new DerSequence(
						new DerOctetString(EncryptedKey),
						new DerOctetString(Mac)
					),
					new DerSequence(
						new DerObjectIdentifier(EncryptionParamSet),
						new DerOctetString(Ukm)
					)
				);
				data = s.GetDerEncoded();
            }
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, "GostR3410KeyEncode");
			}

			return data;
		}

		public void Decode(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull("data");
			}

			try
			{
				var s = Asn1Sequence.FromByteArray(data) as Asn1Sequence;
				var key = s[0] as Asn1Sequence;
				var parms = s[1] as Asn1Sequence;
				EncryptionParamSet = (parms[0] as DerObjectIdentifier).Id;
				Ukm = (parms[1] as DerOctetString).GetOctets();
				EncryptedKey = (key[0] as DerOctetString).GetOctets();
				Mac = (key[1] as DerOctetString).GetOctets();
            }
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, "DecodeGostR3410Key");
			}
		}


		public static string DecodeEncryptionParamSet(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull("data");
			}

			string encryptionParamSet;

			try
			{
				var s = Asn1Sequence.FromByteArray(data) as Asn1Sequence;
				encryptionParamSet = (s[0] as DerObjectIdentifier).Id;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, "Gost2814789BlobParametersDecode");
			}

			return encryptionParamSet;
		}

		public static byte[] EncodeEncryptionParamSet(string encryptionParamSet)
		{
			if (encryptionParamSet == null)
			{
				throw ExceptionUtility.ArgumentNull("encryptionParamSet");
			}

			byte[] data;

			try
			{
				var s = new DerSequence(new DerObjectIdentifier(encryptionParamSet));
				data = s.GetDerEncoded();
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1EncodeError, "Gost2814789BlobParametersEncode");
			}

			return data;
		}
	}
}