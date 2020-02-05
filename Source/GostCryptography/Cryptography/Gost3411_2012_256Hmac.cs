using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using GostCryptography.Native;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализация HMAC (Hash-based Message Authentication Code) на базе алгоритма хэширования по ГОСТ Р 34.11.
	/// </summary>
	public sealed class Gost3411_2012_256Hmac : HMAC
	{
        public const string DefaultHashName = "GOST3411_2012_256";
        public const int DefaultHashSize = 256;

        /// <summary>
        /// Конструктор.
        /// </summary>
        [SecuritySafeCritical]
		public Gost3411_2012_256Hmac()
		{
			HashName = DefaultHashName;
			HashSizeValue = DefaultHashSize;

			_keyAlgorithm = new Gost28147SymmetricAlgorithm();
			_hashHandle = CryptoApiHelper.CreateHashHmac(CryptoApiHelper.ProviderHandle, _keyAlgorithm.InternalKeyHandle, Constants.CALG_GR3411_2012_256_HMAC);
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="key">Ключ для вычисления HMAC.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public Gost3411_2012_256Hmac(byte[] key)
		{
			if (key == null)
			{
				throw ExceptionUtility.ArgumentNull("key");
			}

			HashName = DefaultHashName;
			HashSizeValue = DefaultHashSize;

			_keyAlgorithm = new Gost28147SymmetricAlgorithm { Key = key };
			_hashHandle = CryptoApiHelper.CreateHashHmac(CryptoApiHelper.ProviderHandle, _keyAlgorithm.InternalKeyHandle, Constants.CALG_GR3411_2012_256_HMAC);
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="keyAlgorithm">Алгоритм для вычисления HMAC.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public Gost3411_2012_256Hmac(Gost28147 keyAlgorithm)
		{
			if (keyAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull("keyAlgorithm");
			}

			HashName = DefaultHashName;
			HashSizeValue = DefaultHashSize;

			_keyAlgorithm = DuplicateKeyAlg(keyAlgorithm);
			_hashHandle = CryptoApiHelper.CreateHashHmac(CryptoApiHelper.ProviderHandle, _keyAlgorithm.InternalKeyHandle, Constants.CALG_GR3411_2012_256_HMAC);
		}

		[SecurityCritical]
		private SafeHashHandleImpl _hashHandle;
		private Gost28147SymmetricAlgorithm _keyAlgorithm;

		[SecurityCritical]
		private static Gost28147SymmetricAlgorithm DuplicateKeyAlg(Gost28147 keyAlgorithm)
		{
			var keySymmetricAlgorithm = keyAlgorithm as Gost28147SymmetricAlgorithm;

			return (keySymmetricAlgorithm != null)
				? new Gost28147SymmetricAlgorithm(keySymmetricAlgorithm.InternalProvHandle, keySymmetricAlgorithm.InternalKeyHandle)
				: new Gost28147SymmetricAlgorithm { Key = keyAlgorithm.Key };
		}

		/// <summary>
		/// Приватный дескриптор функции хэширования.
		/// </summary>
		internal SafeHashHandleImpl InternalHashHandle
		{
			[SecurityCritical]
			get { return _hashHandle; }
		}

		/// <summary>
		/// Дескриптор функции хэширования.
		/// </summary>
		public IntPtr HashHandle
		{
			[SecurityCritical]
			[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
			get { return InternalHashHandle.DangerousGetHandle(); }
		}

		/// <summary>
		/// Алгоритм для вычисления HMAC.
		/// </summary>
		public Gost28147 KeyAlgorithm
		{
			get
			{
				return _keyAlgorithm;
			}
			[SecuritySafeCritical]
			set
			{
				_keyAlgorithm = DuplicateKeyAlg(value);
			}
		}

		/// <summary>
		/// Ключ для вычисления HMAC.
		/// </summary>
		public override byte[] Key
		{
			get
			{
				return _keyAlgorithm.Key;
			}
			set
			{
				_keyAlgorithm = new Gost28147SymmetricAlgorithm { Key = value };

				Initialize();
			}
		}

		[SecuritySafeCritical]
		public override void Initialize()
		{
			var hashHmacHandle = CryptoApiHelper.CreateHashHmac(CryptoApiHelper.ProviderHandle, _keyAlgorithm.InternalKeyHandle, Constants.CALG_GR3411_2012_256_HMAC);

			_hashHandle.TryDispose();

			_hashHandle = hashHmacHandle;
		}

		[SecuritySafeCritical]
		protected override void HashCore(byte[] data, int dataOffset, int dataLength)
		{
			CryptoApiHelper.HashData(_hashHandle, data, dataOffset, dataLength);
		}

		[SecuritySafeCritical]
		protected override byte[] HashFinal()
		{
			return CryptoApiHelper.EndHashData(_hashHandle);
		}

		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				if (_keyAlgorithm != null)
				{
					_keyAlgorithm.Clear();
				}

				_hashHandle.TryDispose();
			}

			base.Dispose(disposing);
		}
	}
}