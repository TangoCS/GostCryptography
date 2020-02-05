using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using GostCryptography.X509Certificates;
using System.Xml;
using GostCryptography.Cryptography;
using GostCryptography.Tests.Properties;
using GostCryptography.Xml;
using NUnit.Framework;

namespace GostCryptography.Tests.Xml.Encrypt
{
	/// <summary>
	/// Шифрация и дешифрация XML для широковещательной рассылки.
	/// </summary>
	/// <remarks>
	/// Тест создает XML-документ, выборочно шифрует элементы данного документа, а затем дешифрует полученный зашифрованный документ.
	/// Элементы шифруются с использованием случайного сессионного ключа, который в свою очередь кодируется (экспортируетяся)
	/// с использованием публичного ключа сертификата получателя. Расшифровка документа происходит с использованием первого 
	/// найденного секретного ключа сертификата получателя.
	/// </remarks>
	[TestFixture(Description = "Шифрация и дешифрация XML для широковещательной рассылки")]
	public sealed class EncryptedXmlBroadcastTest
	{
		[Test]
		public void ShouldEncryptXml()
		{
			// Given
			var certificates = new[] { GostCryptoConfig.CreateGost3410AsymmetricAlgorithm().ContainerCertificate };
			var xmlDocument = CreateXmlDocument();
			var expectedXml = xmlDocument.OuterXml;

			// When
			var encryptedXmlDocument = EncryptXmlDocument(xmlDocument, certificates);
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

		private static XmlDocument EncryptXmlDocument(XmlDocument xmlDocument, IEnumerable<X509Certificate> certificates)
		{
			// Создание объекта для шифрации XML
			var encryptedXml = new GostEncryptedXml();

			// Поиск элементов для шифрации
			var elements = xmlDocument.SelectNodes("//SomeElement[@Encrypt='true']");

			if (elements != null)
			{
				var elementIndex = 0;

				foreach (XmlElement element in elements)
				{
					// Формирование элемента EncryptedData
					var elementEncryptedData = new EncryptedData();
					elementEncryptedData.Id = "EncryptedElement" + elementIndex++;
					elementEncryptedData.Type = EncryptedXml.XmlEncElementUrl;
					elementEncryptedData.EncryptionMethod = new EncryptionMethod(GostEncryptedXml.XmlEncGost28147Url);
					elementEncryptedData.KeyInfo = new KeyInfo();

					using (var sessionKey = new Gost28147SymmetricAlgorithm())
					{
						// Шифрация элемента с использованием симметричного ключа
						var encryptedElement = encryptedXml.EncryptData(element, sessionKey, false);

						foreach (var certificate in certificates)
						{
							// Шифрация сессионного ключа с использованием открытого ключа сертификата
							var encryptedSessionKeyData = GostEncryptedXml.EncryptKey(sessionKey, (Gost3410)certificate.PublicKey.Key);

							// Формирование информации о зашифрованном сессионном ключе
							var encryptedSessionKey = new EncryptedKey();
							encryptedSessionKey.CipherData = new CipherData(encryptedSessionKeyData);
							encryptedSessionKey.EncryptionMethod = new EncryptionMethod(GostEncryptedXml.XmlEncGostCryptoProKeyExportUrl);
							encryptedSessionKey.AddReference(new DataReference { Uri = "#" + elementEncryptedData.Id });
							encryptedSessionKey.KeyInfo.AddClause(new KeyInfoX509Data(certificate));

							// Добавление ссылки на зашифрованный ключ, используемый при шифровании данных
							elementEncryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedSessionKey));
						}

						// Установка зашифрованных данных у объекта EncryptedData
						elementEncryptedData.CipherData.CipherValue = encryptedElement;
					}

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

			var nsManager = new XmlNamespaceManager(encryptedXmlDocument.NameTable);
			nsManager.AddNamespace("enc", EncryptedXml.XmlEncNamespaceUrl);

			// Поиск всех зашифрованных XML-элементов
			var encryptedDataList = encryptedXmlDocument.SelectNodes("//enc:EncryptedData", nsManager);

			if (encryptedDataList != null)
			{
				foreach (XmlElement encryptedData in encryptedDataList)
				{
					// Загрузка элемента EncryptedData
					var elementEncryptedData = new EncryptedData();
					elementEncryptedData.LoadXml(encryptedData);

					// Извлечение симметричный ключ для расшифровки элемента EncryptedData
					var sessionKey = GetDecryptionKey(elementEncryptedData);

					if (sessionKey != null)
					{
						// Расшифровка элемента EncryptedData
						var decryptedData = encryptedXml.DecryptData(elementEncryptedData, sessionKey);

						// Замена элемента EncryptedData его расшифрованным представлением
						encryptedXml.ReplaceData(encryptedData, decryptedData);
					}
				}
			}

			return encryptedXmlDocument;
		}

		private static SymmetricAlgorithm GetDecryptionKey(EncryptedData encryptedData)
		{
			SymmetricAlgorithm sessionKey = null;

			foreach (var keyInfo in encryptedData.KeyInfo)
			{
				if (keyInfo is KeyInfoEncryptedKey)
				{
					var encryptedKey = ((KeyInfoEncryptedKey)keyInfo).EncryptedKey;

					if (encryptedKey != null)
					{
						foreach (var ekKeyInfo in encryptedKey.KeyInfo)
						{
							if (ekKeyInfo is KeyInfoX509Data)
							{
								var certificates = ((KeyInfoX509Data)ekKeyInfo).Certificates;

								// Поиск закрытого ключа для дешифрации сессионного ключа
								var privateKey = (certificates[0] as X509Certificate).PrivateKey;

								if (privateKey != null)
								{
									// Дешифрация сессионного ключа с использованием закрытого ключа сертификата
									sessionKey = GostEncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, privateKey);
									break;
								}
							}
						}
					}
				}
			}

			return sessionKey;
		}
	}
}