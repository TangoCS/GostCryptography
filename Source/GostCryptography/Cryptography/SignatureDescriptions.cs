using System.Security.Cryptography;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Информация о свойствах цифровой подписи ГОСТ Р 34.10-2001.
	/// </summary>
	public sealed class GostSignatureDescription : SignatureDescription
	{
		public GostSignatureDescription()
		{
			KeyAlgorithm = typeof(Gost3410AsymmetricAlgorithm).AssemblyQualifiedName;
			DigestAlgorithm = typeof(Gost3411HashAlgorithm).AssemblyQualifiedName;
			FormatterAlgorithm = typeof(GostSignatureFormatter).AssemblyQualifiedName;
			DeformatterAlgorithm = typeof(GostSignatureDeformatter).AssemblyQualifiedName;
		}
	}

    /// <summary>
    /// Информация о свойствах цифровой подписи ГОСТ Р 34.10-2012-256.
    /// </summary>
    public sealed class Gost2012_256SignatureDescription : SignatureDescription
    {
        public Gost2012_256SignatureDescription()
        {
            KeyAlgorithm = typeof(Gost3410_2012_256AsymmetricAlgorithm).AssemblyQualifiedName;
            DigestAlgorithm = typeof(Gost3411_2012_256HashAlgorithm).AssemblyQualifiedName;
            FormatterAlgorithm = typeof(GostSignatureFormatter).AssemblyQualifiedName;
            DeformatterAlgorithm = typeof(GostSignatureDeformatter).AssemblyQualifiedName;
        }
    }

    /// <summary>
    /// Информация о свойствах цифровой подписи ГОСТ Р 34.10-2012-512.
    /// </summary>
    public sealed class Gost2012_512SignatureDescription : SignatureDescription
    {
        public Gost2012_512SignatureDescription()
        {
            KeyAlgorithm = typeof(Gost3410_2012_512AsymmetricAlgorithm).AssemblyQualifiedName;
            DigestAlgorithm = typeof(Gost3411_2012_512HashAlgorithm).AssemblyQualifiedName;
            FormatterAlgorithm = typeof(GostSignatureFormatter).AssemblyQualifiedName;
            DeformatterAlgorithm = typeof(GostSignatureDeformatter).AssemblyQualifiedName;
        }
    }

    public class RSAPKCS1SHA1SignatureDescription : SignatureDescription
	{
		public RSAPKCS1SHA1SignatureDescription()
		{
			KeyAlgorithm = "System.Security.Cryptography.RSACryptoServiceProvider";
			DigestAlgorithm = "System.Security.Cryptography.SHA1CryptoServiceProvider";
			FormatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureFormatter";
			DeformatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureDeformatter";
		}

		public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
		{
			AsymmetricSignatureDeformatter item = (AsymmetricSignatureDeformatter)GostCryptoConfig.CreateFromName(DeformatterAlgorithm);
			item.SetKey(key);
			item.SetHashAlgorithm("SHA1");
			return item;
		}
	}

	public class DSASignatureDescription : SignatureDescription
	{
		public DSASignatureDescription()
		{
			KeyAlgorithm = "System.Security.Cryptography.DSACryptoServiceProvider";
			DigestAlgorithm = "System.Security.Cryptography.SHA1CryptoServiceProvider";
			FormatterAlgorithm = "System.Security.Cryptography.DSASignatureFormatter";
			DeformatterAlgorithm = "System.Security.Cryptography.DSASignatureDeformatter";
		}
	}
}