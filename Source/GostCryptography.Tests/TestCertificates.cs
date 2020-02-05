using System.Security.Cryptography;
using GostCryptography.X509Certificates;

using GostCryptography.Cryptography;

namespace GostCryptography.Tests
{
	//static class TestCertificates
	//{
	//	/// <summary>
	//	/// Имя хранилища для поиска тестового сертификата.
	//	/// </summary>
	//	/// <remarks>
	//	/// Значение равно <see cref="StoreName.My"/>.
	//	/// </remarks>
	//	public const StoreName CertStoreName = StoreName.My;

	//	/// <summary>
	//	/// Местоположение для поиска тестового сертификата.
	//	/// </summary>
	//	/// <remarks>
	//	/// Значение равно <see cref="StoreLocation.LocalMachine"/>.
	//	/// </remarks>
	//	public const StoreLocation CertStoreLocation = StoreLocation.CurrentUser;

	//	/// <summary>
	//	/// Сертификат ГОСТ Р 34.10-2001 с закрытым ключем.
	//	/// </summary>
	//	private static readonly X509Certificate GostCetificate = FindGostCertificate();


	//	/// <summary>
	//	/// Возвращает тестовый контейнер ключей ГОСТ.
	//	/// </summary>
	//	/// <remarks>
	//	/// Для простоты берется контейнер ключей сертификата, однако можно явно указать контейнер, например так:
	//	/// <code>
	//	/// var keyContainer1 = new CspParameters(ProviderTypes.VipNet, null, "MyVipNetContainer");
	//	/// var keyContainer2 = new CspParameters(ProviderTypes.CryptoPro, null, "MyCryptoProContainer");
	//	/// </code>
	//	/// </remarks>
	//	public static CspParameters GetKeyContainer()
	//	{
	//		//var parms = GostCetificate.GetPrivateKeyInfo();
	//		var parms = new CspParameters(ProviderTypes.CryptoPro, null, "le-45468d92-f11e-4b2f-bcea-644caae3b737");
 //           parms.KeyNumber = 1;
	//		return parms;
	//	}

	//	/// <summary>
	//	/// Возвращает тестовый сертификат ГОСТ с закрытым ключем.
	//	/// </summary>
	//	public static X509Certificate GetCertificate()
	//	{
	//		return GostCetificate;
	//	}


	//	private static X509Certificate FindGostCertificate()
	//	{
	//		// Для тестирования берется первый найденный сертификат ГОСТ с закрытым ключем.

	//		var store = new X509Store3(CertStoreName, CertStoreLocation);
	//		store.Open(OpenFlags.ReadOnly);

	//		try
	//		{
	//			foreach (var certificate in store.Certificates)
	//			{
	//				if (certificate.HasPrivateKey && certificate.SignatureAlgorithm == "1.2.643.2.2.3")
	//				{
	//					return certificate;
	//				}
	//			}
	//		}
	//		finally
	//		{
	//			store.Close();
	//		}

	//		return null;
	//	}
	//}
}