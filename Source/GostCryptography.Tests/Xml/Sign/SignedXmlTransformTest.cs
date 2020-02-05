﻿using GostCryptography.X509Certificates;
using System.Xml;
using GostCryptography.Tests.Properties;
using GostCryptography.Xml;
using NUnit.Framework;
using GostCryptography.Cryptography;

namespace GostCryptography.Tests.Xml.Sign
{
	/// <summary>
	/// Подпись и проверка подписи XML-документа с предварительным XSLT-преобразованием подписываемых данных.
	/// </summary>
	/// <remarks>
	/// Тест создает XML-документ, подписывает определенную часть данного документа с использованием сертификата, 
	/// предварительно осуществляя XSLT-преобразование подписываемых данных, а затем проверяет полученную цифровую подпись.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка подписи XML-документа с предварительным XSLT-преобразованием подписываемых данных")]
	public sealed class SignedXmlTransformTest
	{
		[Test]
		public void ShouldSignXml()
		{
			// Given
			var signingCertificate = GostCryptoConfig.CreateGost3410AsymmetricAlgorithm();
			var xmlDocument = CreateXmlDocument();

			// When
			var signedXmlDocument = SignXmlDocument(xmlDocument, signingCertificate);

			// Then
			Assert.IsTrue(VerifyXmlDocumentSignature(signedXmlDocument));
		}

		private static XmlDocument CreateXmlDocument()
		{
			var document = new XmlDocument();
			document.LoadXml(Resources.SignedXmlExample);
			return document;
		}

		private static XmlDocument SignXmlDocument(XmlDocument xmlDocument, Gost3410AsymmetricAlgorithm signingCertificate)
		{
			// Создание подписчика XML-документа
			var signedXml = new SignedXml(xmlDocument);

			// Установка ключа для создания подписи
			signedXml.SigningKey = signingCertificate;
			signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigGost3410Url;

			// Ссылка на узел, который нужно подписать, с указанием алгоритма хэширования
			var dataReference = new Reference { Uri = "#Id1", DigestMethod = SignedXml.XmlDsigGost3411Url };

			// Метод преобразования, применяемый к данным перед их подписью
			var dataTransform = CreateDataTransform();
			dataReference.AddTransform(dataTransform);

			// Установка ссылки на узел
			signedXml.AddReference(dataReference);

			// Установка информации о сертификате, который использовался для создания подписи
			var keyInfo = new KeyInfo();
			keyInfo.AddClause(new KeyInfoX509Data(signingCertificate.ContainerCertificate));
			signedXml.KeyInfo = keyInfo;

			// Вычисление подписи
			signedXml.ComputeSignature();

			// Получение XML-представления подписи
			var signatureXml = signedXml.GetXml();

			// Добавление подписи в исходный документ
			xmlDocument.DocumentElement.AppendChild(xmlDocument.ImportNode(signatureXml, true));

			return xmlDocument;
		}

		private static XmlDsigXsltTransform CreateDataTransform()
		{
			var dataTransformDocument = new XmlDocument();

			dataTransformDocument.LoadXml(@"
				<xsl:stylesheet version='1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform' xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
					<xsl:template match='/'>
						<xsl:apply-templates />
					</xsl:template>
					<xsl:template match='*'>
						<xsl:copy>
							<xsl:copy-of select='@*' />
							<xsl:apply-templates />
						</xsl:copy>
					</xsl:template>
					<xsl:template match='ds:Signature' />
				</xsl:stylesheet>");

			var dataTransform = new XmlDsigXsltTransform();
			dataTransform.LoadInnerXml(dataTransformDocument.ChildNodes);

			return dataTransform;
		}

		private static bool VerifyXmlDocumentSignature(XmlDocument signedXmlDocument)
		{
			// Создание подписчика XML-документа
			var signedXml = new SignedXml(signedXmlDocument);

			// Поиск узла с подписью
			var nodeList = signedXmlDocument.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);

			// Загрузка найденной подписи
			signedXml.LoadXml((XmlElement)nodeList[0]);

			// Проверка подписи
			return signedXml.CheckSignature();
		}
	}
}