﻿using System.Linq;
using GostCryptography.X509Certificates;
using System.Text;

using NUnit.Framework;

namespace GostCryptography.Tests.Pkcs
{
	/// <summary>
	/// Шифрация и дешифрация сообщения CMS/PKCS#7.
	/// </summary>
	/// <remarks>
	/// Тест создает сообщение, шифрует его в формате CMS/PKCS#7, а затем дешифрует зашифрованное сообщение.
	/// </remarks>
	[TestFixture(Description = "Шифрация и дешифрация сообщения CMS/PKCS#7")]
	public sealed class EnvelopedCmsEncryptTest
	{
		//[Test]
		//public void ShouldEncryptAndDecrypt()
		//{
		//	// Given
		//	var certificate = Config.CreateGost3410AsymmetricAlgorithm().ContainerCertificate;
		//	var message = CreateMessage();

		//	// When
		//	var encryptedMessage = EncryptMessage(certificate, message);
		//	var decryptedMessage = DecryptMessage(encryptedMessage);

		//	// Then
		//	Assert.IsTrue(message.SequenceEqual(decryptedMessage));
		//}

		//private static byte[] CreateMessage()
		//{
		//	// Некоторое сообщение для подписи

		//	return Encoding.UTF8.GetBytes("Some message for sign...");
		//}

		//private static byte[] EncryptMessage(X509Certificate certificate, byte[] message)
		//{
		//	// Создание объекта для шифрования сообщения
		//	var envelopedCms = new EnvelopedCms(new ContentInfo(message));

		//	// Создание объектс с информацией о получателе
		//	var recipient = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, certificate);

		//	// Шифрование сообщения CMS/PKCS#7
		//	envelopedCms.Encrypt(recipient);

		//	// Создание сообщения CMS/PKCS#7
		//	return envelopedCms.Encode();
		//}

		//private static byte[] DecryptMessage(byte[] encryptedMessage)
		//{
		//	// Создание объекта для расшифроваки сообщения
		//	var envelopedCms = new EnvelopedCms();

		//	// Чтение сообщения CMS/PKCS#7
		//	envelopedCms.Decode(encryptedMessage);

		//	// Расшифровка сообщения CMS/PKCS#7
		//	envelopedCms.Decrypt(envelopedCms.RecipientInfos[0]);

		//	return envelopedCms.ContentInfo.Content;
		//}
	}
}