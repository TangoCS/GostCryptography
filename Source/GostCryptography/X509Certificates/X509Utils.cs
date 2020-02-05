// ==++==
// 
//   Copyright (c) Microsoft Corporation.  All rights reserved.
// 
// ==--==
// <OWNER>[....]</OWNER>
// 

//
// X509Utils.cs
//

using System;
using GostCryptography.Xml;

namespace GostCryptography.X509Certificates
{
	internal class X509Utils {
        private X509Utils () {}

        private static readonly char[] hexValues = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        internal static string EncodeHexString (byte[] sArray) {
            return EncodeHexString(sArray, 0, (uint) sArray.Length);
        }

        internal static string EncodeHexString (byte[] sArray, uint start, uint end) {
            String result = null;
            if (sArray != null) {
                char[] hexOrder = new char[(end - start) * 2];
                uint digit;
                for (uint i = start, j = 0; i < end; i++) {
                    digit = (uint) ((sArray[i] & 0xf0) >> 4);
                    hexOrder[j++] = hexValues[digit];
                    digit = (uint) (sArray[i] & 0x0f);
                    hexOrder[j++] = hexValues[digit];
                }
                result = new String(hexOrder);
            }
            return result;
        }

        internal static string EncodeHexStringFromInt (byte[] sArray) {
            return EncodeHexStringFromInt(sArray, 0, (uint) sArray.Length);
        }

        internal static string EncodeHexStringFromInt (byte[] sArray, uint start, uint end) {
            String result = null;
            if(sArray != null) {
                char[] hexOrder = new char[(end - start) * 2];
                uint i = end;
                uint digit, j=0;
                while (i-- > start) {
                    digit = (uint) (sArray[i] & 0xf0) >> 4;
                    hexOrder[j++] = hexValues[digit];
                    digit = (uint) (sArray[i] & 0x0f);
                    hexOrder[j++] = hexValues[digit];
                }
                result = new String(hexOrder);
            }
            return result;
        }

        internal static byte HexToByte (char val) {
            if (val <= '9' && val >= '0')
                return (byte) (val - '0');
            else if (val >= 'a' && val <= 'f')
                return (byte) ((val - 'a') + 10);
            else if (val >= 'A' && val <= 'F')
                return (byte) ((val - 'A') + 10);
            else
                return 0xFF;
        }

        internal static byte[] DecodeHexString (string s) {
            string hexString = Utils.DiscardWhiteSpaces(s);
            uint cbHex = (uint) hexString.Length / 2;
            byte[] hex = new byte[cbHex];
            int i = 0;
            for (int index = 0; index < cbHex; index++) {
                hex[index] = (byte) ((HexToByte(hexString[i]) << 4) | HexToByte(hexString[i+1]));
                i += 2;
            }
            return hex;
        }
	}
}
