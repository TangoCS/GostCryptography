using System.Security;
using GostCryptography.Native;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализация алгоритма хэширования по ГОСТ Р 34.11-94
	/// </summary>
	public sealed class Gost3411HashAlgorithm : Gost3411
	{
        public const int DefaultHashSizeValue = 256;

        [SecuritySafeCritical]
		public Gost3411HashAlgorithm()
		{
            HashSizeValue = DefaultHashSizeValue;
        }

        [SecuritySafeCritical]
        protected override SafeHashHandleImpl CreateHashHandle()
        {
            return CryptoApiHelper.CreateHash_3411_94(CryptoApiHelper.ProviderHandle);
        }
    }
}