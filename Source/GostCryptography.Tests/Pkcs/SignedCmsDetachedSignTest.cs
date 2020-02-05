﻿
using GostCryptography.X509Certificates;
using System.Text;


using NUnit.Framework;

namespace GostCryptography.Tests.Pkcs
{
	/// <summary>
	/// Подпись и проверка отсоединенной подписи сообщения CMS/PKCS#7.
	/// </summary>
	/// <remarks>
	/// Тест создает сообщение, формирует отсоединенную подпись сообщения в формате CMS/PKCS#7, а затем проверяет
	/// подпись полученную цифровую подпись.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка отсоединенной подписи сообщения CMS/PKCS#7")]
	public sealed class SignedCmsDetachedSignTest
	{
		//[Test]
		//public void ShouldSign()
		//{
		//	// Given
		//	var certificate = Config.CreateGost3410AsymmetricAlgorithm().ContainerCertificate;
		//	var message = CreateMessage();

		//	// When
		//	var detachedSignature = SignMessage(certificate, message);
		//	var isValudDetachedSignature = VerifyMessage(message, detachedSignature);

		//	// Then
		//	Assert.IsTrue(isValudDetachedSignature);
		//}

		//private static byte[] CreateMessage()
		//{
		//	// Некоторое сообщение для подписи

		//	return Encoding.UTF8.GetBytes("Some message for sign...");
		//}

		//private static byte[] SignMessage(X509Certificate certificate, byte[] message)
		//{
		//	// Создание объекта для подписи сообщения
		//	var signedCms = new GostSignedCms(new ContentInfo(message), true);

		//	// Создание объектс с информацией о подписчике
		//	var signer = new CmsSigner(certificate);

		//	// Включение информации только о конечном сертификате (только для теста)
		//	signer.IncludeOption = X509IncludeOption.EndCertOnly;

		//	// Создание подписи для сообщения CMS/PKCS#7
		//	signedCms.ComputeSignature(signer);

		//	// Создание подписи CMS/PKCS#7
		//	return signedCms.Encode();
		//}

		//private static bool VerifyMessage(byte[] message, byte[] detachedSignature)
		//{
		//	// Создание объекта для проверки подписи сообщения
		//	var signedCms = new GostSignedCms(new ContentInfo(message), true);

		//	// Чтение подписи CMS/PKCS#7
		//	signedCms.Decode(detachedSignature);

		//	try
		//	{
		//		// Проверка подписи CMS/PKCS#7
		//		signedCms.CheckSignature(true);
		//	}
		//	catch
		//	{
		//		return false;
		//	}

		//	return true;
		//}
	}
}