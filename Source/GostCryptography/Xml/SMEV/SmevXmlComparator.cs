using System;
using System.Xml;

namespace GostCryptography.Xml.SMEV
{
	public class SmevXmlComparator : IComparable
	{
		public string Value { get; private set; }
		public string LocalName { get; private set; }
		public string NamespaceURI { get; private set; }

		public SmevXmlComparator(XmlReader reader) : this(reader.LocalName, reader.NamespaceURI, reader.Value)
		{
		}

		public SmevXmlComparator(string localName, string namespaceURI, string value)
		{
			LocalName = localName;
			NamespaceURI = namespaceURI;
			Value = value;
		}

		public int CompareTo(object obj)
		{
			if (!(obj is SmevXmlComparator))
				throw new ArgumentException();

			var xmlComparator = (SmevXmlComparator)obj;

			if (string.IsNullOrEmpty(NamespaceURI) && !string.IsNullOrEmpty(xmlComparator.NamespaceURI))
				return 1;

			if (!string.IsNullOrEmpty(NamespaceURI) && string.IsNullOrEmpty(xmlComparator.NamespaceURI))
				return -1;

			int comparisonResult = NamespaceURI.CompareTo(xmlComparator.NamespaceURI);

			if (comparisonResult == 0)
			{
				if (LocalName == "Id")
					return -1;
				if (xmlComparator.LocalName == "Id")
					return 1;

				comparisonResult = LocalName.CompareTo(xmlComparator.LocalName);
			}
			return comparisonResult;
		}
	}

	public class NamespaceInfo
	{
		public string NamespaceURI { get; private set; }
		public int Depth { get; private set; }
		public string Prefix { get; private set; }

		public NamespaceInfo(string namespaceURI, int depth, string prefix)
		{
			NamespaceURI = namespaceURI;
			Depth = depth;
			Prefix = prefix;
		}
	}
}
