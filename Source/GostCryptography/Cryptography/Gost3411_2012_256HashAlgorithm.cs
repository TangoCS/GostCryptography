using System.Security;
using GostCryptography.Native;

namespace GostCryptography.Cryptography
{
    /// <summary>
    /// Реализация алгоритма хэширования по ГОСТ Р 34.11-2012-256
    /// </summary>
    public sealed class Gost3411_2012_256HashAlgorithm : Gost3411
    {
        public const int DefaultHashSizeValue = 256;

        [SecuritySafeCritical]
        public Gost3411_2012_256HashAlgorithm()
        {
            HashSizeValue = DefaultHashSizeValue;
        }

        [SecuritySafeCritical]
        protected override SafeHashHandleImpl CreateHashHandle()
        {
            return CryptoApiHelper.CreateHash_3411_2012_256(CryptoApiHelper.ProviderHandle);
        }
    }
}
