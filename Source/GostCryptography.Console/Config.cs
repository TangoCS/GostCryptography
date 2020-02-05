using System;
using System.Security;
using System.Security.Cryptography;
using GostCryptography.Cryptography;

namespace GostCryptography
{
	public static class Config
	{
		public static void InitCommon()
		{
			CspParameters parms = null;
			if (GostCryptoConfig.ProviderType == ProviderTypes.VipNet)
				parms = VipNetParameters();
			else
				parms = CryptoProParameters();

			GostCryptoConfig.KeyContainerParameters = parms;
		}

		static CspParameters VipNetParameters()
		{
			SecureString pass = "111111".ToSecureString();

			var keyContainer = new CspParameters();
			keyContainer.KeyPassword = pass;
			keyContainer.ProviderType = ProviderTypes.VipNet;
			if (Environment.OSVersion.Platform == PlatformID.Win32NT)
				keyContainer.KeyContainerName = "c:\\infotecs\\containers\\le-7d27cd76-37b9-4fff-aae3-be6bc89bb56d";
			else if (Environment.OSVersion.Platform == PlatformID.Unix)
				keyContainer.KeyContainerName = "/var/opt/infotecs/vipnet-csp/containers/le-7d27cd76-37b9-4fff-aae3-be6bc89bb56d";
			keyContainer.KeyNumber = 0;
			return keyContainer;
		}

		static CspParameters CryptoProParameters()
		{
			SecureString pass = "111111".ToSecureString();

			var keyContainer = new CspParameters();
			keyContainer.KeyContainerName = "REGISTRY\\\\025392336-30b1-6dd0-48ea-23f093c9f71"; //653347bfa-c98b-2f8d-8cf1-3f9a33f8e6c
            keyContainer.ProviderType = GostCryptoConfig.ProviderType;
			keyContainer.KeyPassword = pass;
			keyContainer.KeyNumber = 1;

			return keyContainer;
		}

		static SecureString ToSecureString(this string source)
		{
			if (string.IsNullOrWhiteSpace(source))
				return null;
			else
			{
				SecureString res = new SecureString();
				foreach (char c in source.ToCharArray())
					res.AppendChar(c);
				return res;
			}
		}
	}
}
