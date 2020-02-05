using System;
using GostCryptography.Native;
using GostCryptography.Properties;
using Org.BouncyCastle.Asn1;

namespace GostCryptography.Asn1.Common
{
	/// <summary>
	/// Информация о зашифрованном общем секретном ключе.
	/// </summary>
	public sealed class GostKeyExchange
	{
		/// <summary>
		/// Информация о зашифрованном ключе по ГОСТ 28147.
		/// </summary>
		public GostKeyExchangeInfo SessionEncryptedKey;

		/// <summary>
		/// Параметры алгоритма цифровой подписи ГОСТ Р 34.10 и алгоритма формирования общего секретного ключа, включая открытый ключ.
		/// </summary>
		public GostKeyExchangeParameters TransportParameters;


		public void Decode(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull("data");
			}

			try
			{
				var s = Asn1Sequence.FromByteArray(data) as Asn1Sequence;
				var s0 = s[0] as Asn1Sequence;
				var s1 = (s[1] as Asn1TaggedObject).GetObject() as Asn1Sequence;
				var s11 = (s1[1] as Asn1TaggedObject).GetObject() as Asn1Sequence;
				var s1101 = (s11[0] as Asn1Sequence)[1] as Asn1Sequence;

				SessionEncryptedKey = new GostKeyExchangeInfo
				{
					EncryptionParamSet = (s1[0] as DerObjectIdentifier).Id,
					EncryptedKey = (s0[0] as DerOctetString).GetOctets(),
					Mac = (s0[1] as DerOctetString).GetOctets(),
					Ukm = (s1[2] as DerOctetString).GetOctets()
				};
				TransportParameters = new GostKeyExchangeParameters
				{
					PublicKeyParamSet = (s1101[0] as DerObjectIdentifier).Id,
					DigestParamSet = (s1101[1] as DerObjectIdentifier).Id,					
					EncryptionParamSet = s1101.Count > 2 ? (s1101[2] as DerObjectIdentifier).Id : null,
					PublicKey = (DerOctetString.FromByteArray((s11[1] as DerBitString).GetBytes()) as DerOctetString).GetOctets(),
                    PrivateKey = null
				};
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, "GostR3410KeyTransportDecode");
			}
		}

		public byte[] Encode()
		{
            var digestoid = TransportParameters.DigestParamSet;
            var s = new DerSequence(
						new DerSequence(
							new DerOctetString(SessionEncryptedKey.EncryptedKey),
							new DerOctetString(SessionEncryptedKey.Mac)
						),
						new DerTaggedObject(false, 0, new DerSequence(
								new DerObjectIdentifier(SessionEncryptedKey.EncryptionParamSet),
								new DerTaggedObject(false, 0, new DerSequence(
										new DerSequence(
											new DerObjectIdentifier(digestoid == Constants.OID_GR3411_12_256 ? Constants.OID_GR3410_12_256 : 
                                                                    digestoid == Constants.OID_GR3411_12_512 ? Constants.OID_GR3410_12_512 : 
                                                                    Constants.OID_GR3410_2001),
											new DerSequence(
												new DerObjectIdentifier(TransportParameters.PublicKeyParamSet),
												new DerObjectIdentifier(TransportParameters.DigestParamSet)/*,
												TransportParameters.EncryptionParamSet != null ? 
													new DerObjectIdentifier(TransportParameters.EncryptionParamSet) : null*/
											)
										),
										new DerBitString(new DerOctetString(TransportParameters.PublicKey))
								)),
								new DerOctetString(SessionEncryptedKey.Ukm)								
						))
				);

			return s.GetDerEncoded();
		}
	}
}