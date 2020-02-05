﻿using GostCryptography.X509Certificates;
using System.Xml;

using GostCryptography.Tests.Properties;
using GostCryptography.Xml;

using NUnit.Framework;
using GostCryptography.Cryptography;

namespace GostCryptography.Tests.Xml.Encrypt
{
	/// <summary>
	/// Шифрация и дешифрация XML документа с использованием сертификата.
	/// </summary>
	/// <remarks>
	/// Тест создает XML-документ, выборочно шифрует элементы данного документа с использованием сертификата,
	/// а затем дешифрует полученный зашифрованный документ.
	/// </remarks>
	[TestFixture(Description = "Шифрация и дешифрация XML документа с использованием сертификата")]
	public sealed class EncryptedXmlCertificateTest
	{
		[Test]
		public void ShouldEncryptXml()
		{
			// Given
			var certificate = GostCryptoConfig.CreateGost3410AsymmetricAlgorithm().ContainerCertificate;
			var xmlDocument = CreateXmlDocument();
			var expectedXml = xmlDocument.OuterXml;

			// When
			var encryptedXmlDocument = EncryptXmlDocument(xmlDocument, certificate);
			var decryptedXmlDocument = DecryptXmlDocument(encryptedXmlDocument);
			var actualXml = decryptedXmlDocument.OuterXml;

			// Then
			Assert.AreEqual(expectedXml, actualXml);
		}

		private static XmlDocument CreateXmlDocument()
		{
			var document = new XmlDocument();
			document.LoadXml(Resources.EncryptedXmlExample);
			return document;
		}

		private static XmlDocument EncryptXmlDocument(XmlDocument xmlDocument, X509Certificate certificate)
		{
			// Создание объекта для шифрации XML
			var encryptedXml = new GostEncryptedXml();

			// Поиск элементов для шифрации
			var elements = xmlDocument.SelectNodes("//SomeElement[@Encrypt='true']");

			if (elements != null)
			{
				foreach (XmlElement element in elements)
				{
					// Шифрация элемента
					var elementEncryptedData = encryptedXml.Encrypt(element, certificate);

					// Замена элемента его зашифрованным представлением
					GostEncryptedXml.ReplaceElement(element, elementEncryptedData, false);
				}
			}

			return xmlDocument;
		}

		private static XmlDocument DecryptXmlDocument(XmlDocument encryptedXmlDocument)
		{
			// Создание объекта для дешифрации XML
			var encryptedXml = new GostEncryptedXml(encryptedXmlDocument);

			// Расшифровка зашифрованных элементов документа
			encryptedXml.DecryptDocument();

			return encryptedXmlDocument;
		}
	}
}