using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace GostCryptography.Pkcs
{
	public class SignedPkcs1
	{
		public static byte[] RsaEncryptWithPrivate(byte[] data, string privateKey, string algorithm)
		{
			ISigner sig = SignerUtilities.GetSigner(algorithm);

			using (var txtreader = new StringReader(privateKey))
			{
				var keyPair = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();
				sig.Init(true, keyPair.Private);
			}
			sig.BlockUpdate(data, 0, data.Length);

			return sig.GenerateSignature();
		}

		public byte[] RsaDecryptWithPrivate(byte[] bytesToDecrypt, string privateKey)
		{
			AsymmetricCipherKeyPair keyPair;

			var decryptEngine = new Pkcs1Encoding(new RsaEngine());

			using (var txtreader = new StringReader(privateKey))
			{
				keyPair = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();

				decryptEngine.Init(false, keyPair.Private);
			}

			return decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length);
		}
	}
}
