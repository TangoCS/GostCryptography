using System.Security;
using GostCryptography.Native;

namespace GostCryptography.Cryptography
{
    /// <summary>
    /// Реализация алгоритма хэширования по ГОСТ Р 34.11-2012-512
    /// </summary>
    public sealed class Gost3411_2012_512HashAlgorithm : Gost3411
    {
        public const int DefaultHashSizeValue = 512;

        [SecuritySafeCritical]
        public Gost3411_2012_512HashAlgorithm()
        {
            HashSizeValue = DefaultHashSizeValue;
        }

        [SecuritySafeCritical]
        protected override SafeHashHandleImpl CreateHashHandle()
        {
            return CryptoApiHelper.CreateHash_3411_2012_512(CryptoApiHelper.ProviderHandle);
        }
    }
}
