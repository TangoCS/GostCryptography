using System.IO;
using System.Text;

using GostCryptography.Cryptography;

using NUnit.Framework;

namespace GostCryptography.Tests.Sign
{
	/// <summary>
	/// Подпись и проверка подписи потока байт с помощью сертификата.
	/// </summary>
	/// <remarks>
	/// Тест создает поток байт, вычисляет цифровую подпись потока байт с использованием закрытого ключа сертификата,
	/// а затем с помощью открытого ключа сертификата проверяет полученную подпись.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка подписи потока байт с помощью сертификата")]
	public sealed class SignDataStreamCertificateTest
	{
		[Test]
		public void ShouldSignDataStream()
		{
			// Given
			var certificate = GostCryptoConfig.CreateGost3410AsymmetricAlgorithm().ContainerCertificate;
			var privateKey = (Gost3410)certificate.PrivateKey;
			var publicKey = (Gost3410)certificate.PublicKey.Key;
			var dataStream = CreateDataStream();

			// When

			dataStream.Seek(0, SeekOrigin.Begin);
			var signature = CreateSignature(privateKey, dataStream);

			dataStream.Seek(0, SeekOrigin.Begin);
			var isValidSignature = VerifySignature(publicKey, dataStream, signature);

			// Then
			Assert.IsTrue(isValidSignature);
		}

		private static Stream CreateDataStream()
		{
			// Некоторый поток байт для подписи

			return new MemoryStream(Encoding.UTF8.GetBytes("Some data for sign..."));
		}

		private static byte[] CreateSignature(Gost3410 privateKey, Stream dataStream)
		{
			byte[] hash;

			using (var hashAlg = new Gost3411HashAlgorithm())
			{
				hash = hashAlg.ComputeHash(dataStream);
			}

			return privateKey.CreateSignature(hash);
		}

		private static bool VerifySignature(Gost3410 publicKey, Stream dataStream, byte[] signature)
		{
			byte[] hash;

			using (var hashAlg = new Gost3411HashAlgorithm())
			{
				hash = hashAlg.ComputeHash(dataStream);
			}

			return publicKey.VerifySignature(hash, signature);
		}
	}
}