using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;

namespace GostCryptography.Xml.SMEV
{
    /// <summary>
    /// Нормализация XML для СМЭВ3 "urn://smev-gov-ru/xmldsig/transform"
    /// </summary>
    //TODO Security [System.Security.Permissions.HostProtection(MayLeakOnAbort = true)]
    public class XmlDsigSmevTransform : Transform
	{
		private XmlDocument _document;
		private MemoryStream _outputStream;
		private int _nsCount;
		private int _currentLevel;
		private List<NamespaceInfo> _namespaceMapping = new List<NamespaceInfo>();
		private Type[] _inputTypes = { typeof(Stream), typeof(XmlDocument), typeof(XmlNodeList) };
		private Type[] _outputTypes = { typeof(Stream) };
		private const string _xmlns = "http://www.w3.org/2000/xmlns/";

		public XmlDsigSmevTransform()
		{
			Algorithm = SmevSignedXml.XmlDsigSmevTransformUrl;
		}

		/// <summary>
		/// Основной поток для трансформации XML
		/// </summary>
		private MemoryStream outputStream
		{
			get
			{
				if (_outputStream == null)
					SmevTransform();

				_outputStream.Position = 0L;

				return _outputStream;
			}
			set	{ _outputStream = value; }
		}

		/// <summary>
		/// Уровень вложенности элементов
		/// </summary>
		private int currentLevel
		{
			get { return _currentLevel; }
			set
			{
				if (value < _currentLevel)
					_namespaceMapping.RemoveAll((NamespaceInfo t) => t.Depth > value);

				_currentLevel = value;
			}
		}

		public override Type[] InputTypes
		{
			get { return _inputTypes; }
		}

		public override Type[] OutputTypes
		{
			get { return _outputTypes; }
		}

		public override object GetOutput()
		{
			return GetOutput(typeof(Stream));
		}

		public override object GetOutput(Type type)
		{
			if (type == typeof(XmlDocument))
			{
				var xmlDocument = new XmlDocument();
				xmlDocument.Load(outputStream);
				return xmlDocument;
			}
			else if (type == typeof(Stream))
			{
				return outputStream;
			}

			throw new ArgumentException(type.Name);
		}

		public override void LoadInnerXml(XmlNodeList nodeList)
		{
		}

		protected override XmlNodeList GetInnerXml()
		{
			return null;
		}

		public override void LoadInput(Object obj)
		{
			_outputStream = null;

			if (obj is Stream)
			{
				LoadStreamInput((Stream)obj);
			}
			else if (obj is XmlNodeList)
			{
				LoadXmlNodeListInput((XmlNodeList)obj);
			}
			else if (obj is XmlDocument)
			{
				LoadXmlDocumentInput((XmlDocument)obj);
			}
			else
				throw new ArgumentException(obj.GetType().Name);
		}

		private void LoadStreamInput(Stream stream)
		{
			XmlResolver resolver = this.ResolverSet ? this.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), this.BaseURI);
			XmlReader xmlReader = Utils.PreProcessStreamInput(stream, resolver, this.BaseURI);
			_document = new XmlDocument();
			_document.PreserveWhitespace = true;
			_document.Load(xmlReader);
		}

		private void LoadXmlNodeListInput(XmlNodeList nodeList)
		{
			// Use C14N to get a document
			XmlResolver resolver = (this.ResolverSet ? this.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), this.BaseURI));
			CanonicalXml c14n = new CanonicalXml(nodeList, resolver, true);
			using (MemoryStream ms = new MemoryStream(c14n.GetBytes()))
			{
				LoadStreamInput(ms);
			}
		}

		private void LoadXmlDocumentInput(XmlDocument doc)
		{
			// Use C14N to get a document
			XmlResolver resolver = (this.ResolverSet ? this.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), this.BaseURI));
			CanonicalXml c14n = new CanonicalXml(doc, resolver, true);
			using (MemoryStream ms = new MemoryStream(c14n.GetBytes()))
			{
				LoadStreamInput(ms);
			}
		}

		/// <summary>
		/// Обработка XML 
		/// </summary>
		private void SmevTransform()
		{
			if (_document == null)
				throw new ArgumentNullException("Not initalized XmlDocument");

			_nsCount = 0;
			_currentLevel = 0;
			_namespaceMapping.Clear();

			// правило №2 СМЭВ3
			XmlWriterSettings settings = new XmlWriterSettings
			{
				NewLineHandling = NewLineHandling.Replace,
				OmitXmlDeclaration = true,
				ConformanceLevel = ConformanceLevel.Fragment,
				Encoding = new UTF8Encoding(false)
			};

			_outputStream = new MemoryStream();
			var xmlWriter = XmlWriter.Create(_outputStream, settings);

			using (XmlNodeReader xmlNodeReader = new XmlNodeReader(_document))
			{
				while (xmlNodeReader.Read())
				{
					switch (xmlNodeReader.NodeType)
					{
						case XmlNodeType.Element:
							currentLevel++;
							string namespaceURI = xmlNodeReader.NamespaceURI;

							if (!string.IsNullOrEmpty(namespaceURI))
							{
								string prefix;
								bool namespacePrefix = GetNamespacePrefix(namespaceURI, out prefix);
								xmlWriter.WriteStartElement(prefix, xmlNodeReader.LocalName, namespaceURI);
								if (!namespacePrefix)
									WriteAttribute(xmlWriter, namespaceURI, prefix);
							}
							else
								xmlWriter.WriteStartElement(xmlNodeReader.LocalName);

							if (xmlNodeReader.HasAttributes)
								ProcessAttributes(xmlNodeReader, xmlWriter, namespaceURI);

							if (xmlNodeReader.IsEmptyElement)
							{
								xmlWriter.WriteFullEndElement(); // правило №3 СМЭВ3
								currentLevel--;
							}
							break;
						case XmlNodeType.Text:
							if (!string.IsNullOrEmpty(xmlNodeReader.Value.Trim()))
								xmlWriter.WriteString(xmlNodeReader.Value);
							break;
						case XmlNodeType.EndElement:
							xmlWriter.WriteFullEndElement(); // правило №3 СМЭВ3
							currentLevel--;
							break;
						default: // правило №1 СМЭВ3 пропускаем все, что не относится к элементу и атрибуты, атрибуты обрабатываются внутри элемента
						/*case XmlNodeType.XmlDeclaration:
						case XmlNodeType.ProcessingInstruction:
						case XmlNodeType.Comment:
						case XmlNodeType.Attribute:*/
							break;
					}
				}
			}
			xmlWriter.Close();
		}

		/// <summary>
		/// Определение префикса пространства имен и формирование нового по правилу №6 (4,5,7,8) СМЭВ3
		/// </summary>
		/// <param name="orginalUri"></param>
		/// <param name="prefix"></param>
		/// <returns></returns>
		private bool GetNamespacePrefix(string orginalUri, out string prefix)
		{
			bool result = true;
			var namespaceInfo = _namespaceMapping.Find((NamespaceInfo t) => t.NamespaceURI.Equals(orginalUri));

			if (namespaceInfo == null)
			{
				result = false;
				namespaceInfo = new NamespaceInfo(orginalUri, _currentLevel, string.Format("ns{0}", ++_nsCount));
				_namespaceMapping.Add(namespaceInfo);
			}
			prefix = namespaceInfo.Prefix;

			return result;
		}

		/// <summary>
		/// Запись атрибута в XmlWriter
		/// </summary>
		/// <param name="writer"></param>
		/// <param name="namespaceURI"></param>
		/// <param name="prefix"></param>
		private void WriteAttribute(XmlWriter writer, string namespaceURI, string prefix)
		{
			writer.WriteStartAttribute("xmlns", prefix, _xmlns);
			writer.WriteString(namespaceURI);
			writer.WriteEndAttribute();
		}

		/// <summary>
		/// Обработка и сортировка атрибутов и пространств имен элемента по правилам №4,5,7,8 СМЭВ3
		/// </summary>
		/// <param name="reader"></param>
		/// <param name="writer"></param>
		/// <param name="namespaceuri"></param>
		private void ProcessAttributes(XmlReader reader, XmlWriter writer, string namespaceuri)
		{
			var listattribute = new List<SmevXmlComparator>();
			var listnamespace = new List<string>();

			reader.MoveToFirstAttribute();
			do
			{
				if (reader.NamespaceURI == _xmlns)
				{
					if (!(reader.Value == namespaceuri))
						listnamespace.Add(reader.Value);
				}
				else
					listattribute.Add(new SmevXmlComparator(reader));
			}
			while (reader.MoveToNextAttribute());

			listattribute.Sort();
			listnamespace.Sort();

			using (var enumerator = listnamespace.GetEnumerator())
			{
				while (enumerator.MoveNext())
				{
					string nscurrent = enumerator.Current;
					string prefix;
					if (listattribute.Exists((SmevXmlComparator a) => a.NamespaceURI.Equals(nscurrent)) && !GetNamespacePrefix(nscurrent, out prefix))
						WriteAttribute(writer, nscurrent, prefix);
				}
			}
			foreach (SmevXmlComparator current in listattribute)
			{
				if (string.IsNullOrEmpty(current.NamespaceURI))
					writer.WriteAttributeString(current.LocalName, current.Value);
				else
				{
					string prefix;
					GetNamespacePrefix(current.NamespaceURI, out prefix);
					writer.WriteAttributeString(prefix, current.LocalName, current.NamespaceURI, current.Value);
				}
			}
			reader.MoveToElement();
		}
	}
}
