//
// X501Name.cs: X.501 Distinguished Names stuff 
//
// Author:
//	Sebastien Pouliot <sebastien@ximian.com>
//
// (C) 2002, 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) 2004-2006 Novell, Inc (http://www.novell.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Globalization;
using System.Text;
using GostCryptography.Asn1;
using GostCryptography.Properties;

namespace GostCryptography.X509Certificates
{

	// References:
	// 1.	Information technology - Open Systems Interconnection - The Directory: Models
	//	http://www.itu.int/rec/recommendation.asp?type=items&lang=e&parent=T-REC-X.501-200102-I
	// 2.	RFC2253: Lightweight Directory Access Protocol (v3): UTF-8 String Representation of Distinguished Names
	//	http://www.ietf.org/rfc/rfc2253.txt

	/*
	 * Name ::= CHOICE { RDNSequence }
	 * 
	 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
	 * 
	 * RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
	 */
	public sealed class X501
	{

		static byte[] countryName = { 0x55, 0x04, 0x06 };
		static byte[] organizationName = { 0x55, 0x04, 0x0A };
		static byte[] organizationalUnitName = { 0x55, 0x04, 0x0B };
		static byte[] commonName = { 0x55, 0x04, 0x03 };
		static byte[] localityName = { 0x55, 0x04, 0x07 };
		static byte[] stateOrProvinceName = { 0x55, 0x04, 0x08 };
		static byte[] streetAddress = { 0x55, 0x04, 0x09 };
		//static byte[] serialNumber = { 0x55, 0x04, 0x05 };
		static byte[] domainComponent = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19 };
		static byte[] userid = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01 };
		static byte[] email = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01 };
		static byte[] dnQualifier = { 0x55, 0x04, 0x2E };
		static byte[] title = { 0x55, 0x04, 0x0C };
		static byte[] surname = { 0x55, 0x04, 0x04 };
		static byte[] givenName = { 0x55, 0x04, 0x2A };
		static byte[] initial = { 0x55, 0x04, 0x2B };
		static byte[] unstructuredName = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x02 };
		static byte[] inn = { 0x2a, 0x85, 0x03, 0x03, 0x81, 0x03, 0x01, 0x01 };
        static byte[] innle = { 0x2a, 0x85, 0x03, 0x64, 0x04 };
        static byte[] ogrn = { 0x2a, 0x85, 0x03, 0x64, 0x01 };
        static byte[] ogrnip = { 0x2a, 0x85, 0x03, 0x64, 0x05 };
        static byte[] snils = { 0x2a, 0x85, 0x03, 0x64, 0x03 };

		private X501()
		{
		}

		static public string ToString(ASN1 seq)
		{
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < seq.Count; i++)
			{
				ASN1 entry = seq[i];
				AppendEntry(sb, entry, true);

				// separator (not on last iteration)
				if (i < seq.Count - 1)
					sb.Append(", ");
			}
			return sb.ToString();
		}

		static public string ToString(ASN1 seq, bool reversed, string separator, bool quotes)
		{
			StringBuilder sb = new StringBuilder();

			if (reversed)
			{
				for (int i = seq.Count - 1; i >= 0; i--)
				{
					ASN1 entry = seq[i];
					AppendEntry(sb, entry, quotes);

					// separator (not on last iteration)
					if (i > 0)
						sb.Append(separator);
				}
			}
			else
			{
				for (int i = 0; i < seq.Count; i++)
				{
					ASN1 entry = seq[i];
					AppendEntry(sb, entry, quotes);

					// separator (not on last iteration)
					if (i < seq.Count - 1)
						sb.Append(separator);
				}
			}
			return sb.ToString();
		}

		static private void AppendEntry(StringBuilder sb, ASN1 entry, bool quotes)
		{
			// multiple entries are valid
			for (int k = 0; k < entry.Count; k++)
			{
				ASN1 pair = entry[k];
				ASN1 s = pair[1];
				if (s == null)
					continue;

				ASN1 poid = pair[0];
				if (poid == null)
					continue;

				if (poid.CompareValue(countryName))
					sb.Append("C=");
				else if (poid.CompareValue(organizationName))
					sb.Append("O=");
				else if (poid.CompareValue(organizationalUnitName))
					sb.Append("OU=");
				else if (poid.CompareValue(commonName))
					sb.Append("CN=");
				else if (poid.CompareValue(localityName))
					sb.Append("L=");
				else if (poid.CompareValue(stateOrProvinceName))
					sb.Append("S=");    // NOTE: RFC2253 uses ST=
				else if (poid.CompareValue(streetAddress))
					sb.Append("STREET=");
				else if (poid.CompareValue(domainComponent))
					sb.Append("DC=");
				else if (poid.CompareValue(userid))
					sb.Append("UID=");
				else if (poid.CompareValue(email))
					sb.Append("E=");    // NOTE: Not part of RFC2253
				else if (poid.CompareValue(dnQualifier))
					sb.Append("dnQualifier=");
				else if (poid.CompareValue(title))
					sb.Append("T=");
				else if (poid.CompareValue(surname))
					sb.Append("SN=");
				else if (poid.CompareValue(givenName))
					sb.Append("G=");
				else if (poid.CompareValue(initial))
					sb.Append("I=");
				else if (poid.CompareValue(unstructuredName))
					sb.Append("UN=");
				else if (poid.CompareValue(inn))
					sb.Append("ИНН=");
                else if (poid.CompareValue(innle))
                    sb.Append("ИННЮЛ=");
                else if (poid.CompareValue(ogrn))
					sb.Append("ОГРН=");
                else if (poid.CompareValue(ogrnip))
                    sb.Append("ОГРНИП=");
                else if (poid.CompareValue(snils))
					sb.Append("СНИЛС=");
				else
				{
					// unknown OID
					//sb.Append("OID.");  // NOTE: Not present as RFC2253
					sb.Append(ASN1Convert.ToOid(poid));
					sb.Append("=");
				}

				string sValue = null;
				// 16bits or 8bits string ? TODO not complete (+special chars!)
				if (s.Tag == 0x1E)
				{
					// BMPSTRING
					/*StringBuilder sb2 = new StringBuilder();
					for (int j = 1; j < s.Value.Length; j += 2)
						sb2.Append((char)s.Value[j]);
					sValue = sb2.ToString();*/

					char[] ch = new char[s.Value.Length / 2];

					for (int i = 0; i != ch.Length; i++)
					{
						ch[i] = (char)((s.Value[2 * i] << 8) | (s.Value[2 * i + 1] & 0xff));
					}
					sValue = new string(ch);

					//sValue = Encoding.BigEndianUnicode.GetString(s.Value);
				}
				else
				{
					if (s.Tag == 0x14)
						sValue = Encoding.UTF7.GetString(s.Value);
					else
						sValue = Encoding.UTF8.GetString(s.Value);
					// in some cases we must quote (") the value
					// Note: this doesn't seems to conform to RFC2253
					char[] specials = { ',', '+', '"', '\\', '<', '>', ';' };
					if (quotes)
					{
						if ((sValue.IndexOfAny(specials, 0, sValue.Length) > 0) ||
							sValue.StartsWith(" ") || (sValue.EndsWith(" ")))
							sValue = "\"" + sValue + "\"";
					}
				}

				sb.Append(sValue);

				// separator (not on last iteration)
				if (k < entry.Count - 1)
					sb.Append(", ");
			}
		}

		static private X520.AttributeTypeAndValue GetAttributeFromOid(string attributeType)
		{
			string s = attributeType.ToUpper(CultureInfo.InvariantCulture).Trim();
			switch (s)
			{
				case "C":
					return new X520.CountryName();
				case "O":
					return new X520.OrganizationName();
				case "OU":
					return new X520.OrganizationalUnitName();
				case "CN":
					return new X520.CommonName();
				case "L":
					return new X520.LocalityName();
				case "S":   // Microsoft
				case "ST":  // RFC2253
					return new X520.StateOrProvinceName();
				case "E":   // NOTE: Not part of RFC2253
					return new X520.EmailAddress();
				case "DC":  // RFC2247
					return new X520.DomainComponent();
				case "UID": // RFC1274
					return new X520.UserId();
				case "DNQUALIFIER":
					return new X520.DnQualifier();
				case "T":
					return new X520.Title();
				case "SN":
					return new X520.Surname();
				case "G":
					return new X520.GivenName();
				case "I":
					return new X520.Initial();
				case "UN":
					return new X520.UnstructuredName();
				case "ОГРН":
					return new X520.OGRN();
                case "ОГРНИП":
                    return new X520.OGRNIP();
                case "ИНН":
					return new X520.INN();
                case "ИННЮЛ":
                    return new X520.INNLE();
                case "СНИЛС":
					return new X520.SNILS();
				default:
					if (s.StartsWith("OID."))
					{
						// MUST support it but it OID may be without it
						return new X520.Oid(s.Substring(4));
					}
					else
					{
						if (IsOid(s))
							return new X520.Oid(s);
						else
							return null;
					}
			}
		}

		static private bool IsOid(string oid)
		{
			try
			{
				ASN1 asn = ASN1Convert.FromOid(oid);
				return (asn.Tag == 0x06);
			}
			catch
			{
				return false;
			}
		}

		// no quote processing
		static private X520.AttributeTypeAndValue ReadAttribute(string value, ref int pos)
		{
			while ((value[pos] == ' ') && (pos < value.Length))
				pos++;

			// get '=' position in substring
			int equal = value.IndexOf('=', pos);
			if (equal == -1)
			{
				string msg = Resources.X501NoAttributeFound;
				throw new FormatException(msg);
			}

			string s = value.Substring(pos, equal - pos);
			X520.AttributeTypeAndValue atv = GetAttributeFromOid(s);
			if (atv == null)
			{
				string msg = Resources.X501UnknownAttribute;
				throw new FormatException(String.Format(msg, s));
			}
			pos = equal + 1; // skip the '='
			return atv;
		}

		static private bool IsHex(char c)
		{
			if (Char.IsDigit(c))
				return true;
			char up = Char.ToUpper(c, CultureInfo.InvariantCulture);
			return ((up >= 'A') && (up <= 'F'));
		}

		static byte[] FromHex(string hex)
		{
			if (hex == null)
				return null;
			if ((hex.Length & 0x1) == 0x1)
				throw new ArgumentException("Length must be a multiple of 2");

			byte[] result = new byte[hex.Length >> 1];
			int n = 0;
			int i = 0;
			while (n < result.Length)
			{
				result[n] = (byte)(FromHexChar(hex[i++]) << 4);
				result[n++] += FromHexChar(hex[i++]);
			}
			return result;
		}

		static byte FromHexChar(char c)
		{
			if ((c >= 'a') && (c <= 'f'))
				return (byte)(c - 'a' + 10);
			if ((c >= 'A') && (c <= 'F'))
				return (byte)(c - 'A' + 10);
			if ((c >= '0') && (c <= '9'))
				return (byte)(c - '0');
			throw new ArgumentException("invalid hex char");
		}

		static string ReadHex(string value, ref int pos)
		{
			StringBuilder sb = new StringBuilder();
			// it is (at least an) 8 bits char
			sb.Append(value[pos++]);
			sb.Append(value[pos]);
			// look ahead for a 16 bits char
			if ((pos < value.Length - 4) && (value[pos + 1] == '\\') && IsHex(value[pos + 2]))
			{
				pos += 2; // pass last char and skip \
				sb.Append(value[pos++]);
				sb.Append(value[pos]);
			}
			byte[] data = FromHex(sb.ToString());
			return Encoding.UTF8.GetString(data);
		}

		static private int ReadEscaped(StringBuilder sb, string value, int pos)
		{
			switch (value[pos])
			{
				case '\\':
				case '"':
				case '=':
				case ';':
				case '<':
				case '>':
				case '+':
				case '#':
				case ',':
					sb.Append(value[pos]);
					return pos;
				default:
					if (pos >= value.Length - 2)
					{
						string msg = Resources.X501MalformedEscapedValue;
						throw new FormatException(string.Format(msg, value.Substring(pos)));
					}
					// it's either a 8 bits or 16 bits char
					sb.Append(ReadHex(value, ref pos));
					return pos;
			}
		}

		static private int ReadQuoted(StringBuilder sb, string value, int pos)
		{
			int original = pos;
			while (pos <= value.Length)
			{
				switch (value[pos])
				{
					case '"':
						return pos;
					case '\\':
						return ReadEscaped(sb, value, pos);
					default:
						sb.Append(value[pos]);
						pos++;
						break;
				}
			}
			string msg = Resources.X501MalformedQuotedValue;
			throw new FormatException(string.Format(msg, value.Substring(original)));
		}

		static private string ReadValue(string value, ref int pos)
		{
			int original = pos;
			StringBuilder sb = new StringBuilder();
			while (pos < value.Length)
			{
				switch (value[pos])
				{
					case '\\':
						pos = ReadEscaped(sb, value, ++pos);
						break;
					case '"':
						pos = ReadQuoted(sb, value, ++pos);
						break;
					case '=':
					case ';':
					case '<':
					case '>':
						string msg = Resources.X501MalformedValueContains;
						throw new FormatException(string.Format(msg, value.Substring(original), value[pos]));
					case '+':
					case '#':
						throw new NotImplementedException();
					case ',':
						pos++;
						return sb.ToString();
					default:
						sb.Append(value[pos]);
						break;
				}
				pos++;
			}
			return sb.ToString();
		}

		static public ASN1 FromString(string rdn)
		{
			if (rdn == null)
				throw new ArgumentNullException("rdn");

			int pos = 0;
			ASN1 asn1 = new ASN1(0x30);
			while (pos < rdn.Length)
			{
				X520.AttributeTypeAndValue atv = ReadAttribute(rdn, ref pos);
				atv.Value = ReadValue(rdn, ref pos);

				ASN1 sequence = new ASN1(0x31);
				sequence.Add(atv.GetASN1());
				asn1.Add(sequence);
			}
			return asn1;
		}
	}
}