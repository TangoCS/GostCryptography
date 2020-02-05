using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using GostCryptography.Asn1.Common;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализация алгоритма ГОСТ Р 34.10.
	/// </summary>
	[SecurityCritical]
	[SecuritySafeCritical]
	public sealed class Gost3410AsymmetricAlgorithm : Gost3410, ICspAsymmetricAlgorithm
	{
        /// <summary>
        /// Наименование алгоритма цифровой подписи по ГОСТ Р 34.10.
        /// </summary>
        protected override string Gost3410SignatureAlgorithm { get { return "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411"; } }

        /// <summary>
        /// Наименование алгоритма обмена ключами по ГОСТ Р 34.10.
        /// </summary>
        protected override string Gost3410KeyExchangeAlgorithm { get { return "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2001"; } }

        /// <summary>
        /// Конструктор.
        /// </summary>
        [SecuritySafeCritical]
        //TODO Security [ReflectionPermission(SecurityAction.Assert, MemberAccess = true)]
        public Gost3410AsymmetricAlgorithm() : this(null)
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerParameters">Параметры криптографического провайдера.</param>
		[SecuritySafeCritical]
		public Gost3410AsymmetricAlgorithm(CspParameters providerParameters)
		{
			LegalKeySizesValue = DefaultLegalKeySizes;
			_providerParameters = providerParameters;

			if (_providerParameters == null)
			{
				_providerParameters = new CspParameters { ProviderType = GostCryptoConfig.ProviderType };
			}

			AcquireContext();
			SetPassword();
		}

		/// <summary>
		/// 
		/// </summary>
		public const int DefaultKeySize = 512;

		/// <summary>
		/// 
		/// </summary>
		public static readonly KeySizes[] DefaultLegalKeySizes = { new KeySizes(DefaultKeySize, DefaultKeySize, 0) };

		private readonly CspParameters _providerParameters;

		[SecurityCritical]
		private SafeProvHandleImpl _providerHandle;

		private void AcquireContext()
		{
			if (_providerHandle != null && !_providerHandle.IsInvalid) return;

			var dwFlags = Constants.CRYPT_SILENT;
			if (_providerParameters.KeyContainerName == null)
			{
				dwFlags |= Constants.CRYPT_VERIFYCONTEXT;
				//dwFlags |= Constants.CRYPT_MACHINE_KEYSET;
			}
			else
			{
				_keyHandleFunc = PrivateKey;
            }

			_providerHandle = SafeProvHandleImpl.InvalidHandle;
            if (!CryptoApi.CryptAcquireContext(ref _providerHandle, _providerParameters.KeyContainerName, _providerParameters.ProviderName,
                (uint)_providerParameters.ProviderType, dwFlags))
			{
				throw new Win32Exception();
			}
		}

		private void SetPassword()
		{
			if (_providerParameters.KeyPassword != null)
			{
				var keyPasswordData = Marshal.SecureStringToCoTaskMemAnsi(_providerParameters.KeyPassword);
				try
				{
					CryptoApiHelper.SetProviderParameter(_providerHandle, (int)_providerParameters.KeyNumber, Constants.PP_SIGNATURE_PIN, keyPasswordData);
				}
				finally
				{
					if (keyPasswordData != IntPtr.Zero)
					{
						Marshal.ZeroFreeCoTaskMemAnsi(keyPasswordData);
					}
				}
			}
		}

		/// <summary>
		/// Приватный дескриптор провайдера.
		/// </summary>
		internal SafeProvHandleImpl InternalProvHandle
		{
			[SecurityCritical]
			get
			{
				return _providerHandle;
			}
		}

		/// <summary>
		/// Дескрипор провайдера.
		/// </summary>
		public IntPtr ProviderHandle
		{
			[SecurityCritical]
			[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
			get { return InternalProvHandle.DangerousGetHandle(); }
		}

		/// <summary>
		/// Размер ключа.
		/// </summary>
		public override int KeySize
		{
			[SecuritySafeCritical]
			get
			{
				//GetKeyPair();
				return DefaultKeySize;
			}
		}

		/// <summary>
		/// Информация о контейнере ключей.
		/// </summary>
		public CspKeyContainerInfo CspKeyContainerInfo
		{
			[SecuritySafeCritical]
			get
			{
				//GetKeyPair();
				return new CspKeyContainerInfo(_providerParameters);
				//return CspKeyContainerInfoHelper.CreateCspKeyContainerInfo(_providerParameters, _isRandomKeyContainer);
			}
		}

		/// <summary>
		/// Экспортирует параметры алгоритма в BLOB.
		/// </summary>
		[SecuritySafeCritical]
		public byte[] ExportCspBlob(bool includePrivateParameters)
		{
			byte[] res = null;
			if (includePrivateParameters)
			{
				UsingKey(h =>
				{
					res = CryptoApiHelper.ExportCspBlob(h, SafeKeyHandleImpl.InvalidHandle, Constants.PLAINTEXTKEYBLOB);
				});
			}
			else
			{
				UsingKey(h =>
				{
					res = CryptoApiHelper.ExportCspBlob(h, SafeKeyHandleImpl.InvalidHandle, Constants.PUBLICKEYBLOB);
				});
			}			
			
            return res;
		}

		/// <summary>
		/// Импортирует параметры алгоритма в BLOB.
		/// </summary>
		/// <exception cref="ArgumentException"></exception>
		[SecuritySafeCritical]
		public void ImportCspBlob(byte[] importedKeyBytes)
		{
			if (importedKeyBytes == null)
			{
				throw ExceptionUtility.ArgumentNull("importedKeyBytes");
			}

			if (!IsPublicKeyBlob(importedKeyBytes))
			{
				throw ExceptionUtility.Argument("importedKeyBytes", Resources.UserImportBulkBlob);
			}

			_keyHandleFunc = () =>
			{
				SafeKeyHandleImpl hKey;
				_providerParameters.KeyNumber = CryptoApiHelper.ImportCspBlob(importedKeyBytes, _providerHandle, SafeKeyHandleImpl.InvalidHandle, out hKey);
				return hKey;
			};
		}

		bool IsPublicKeyBlob(byte[] importedKeyBytes)
		{
			if ((importedKeyBytes[0] != Constants.PUBLICKEYBLOB) || (importedKeyBytes.Length < 12))
			{
				return false;
			}

			var gostKeyMask = BitConverter.GetBytes(Constants.GR3410_1_MAGIC);

			return (importedKeyBytes[8] == gostKeyMask[0])
				   && (importedKeyBytes[9] == gostKeyMask[1])
				   && (importedKeyBytes[10] == gostKeyMask[2])
				   && (importedKeyBytes[11] == gostKeyMask[3]);
		}

		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		public override byte[] CreateSignature(byte[] hash)
		{
			return SignHash(hash);
		}

		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public byte[] CreateSignature(byte[] data, object hashAlgorithm)
		{
			var hash = CreateHashAlgorithm(hashAlgorithm).ComputeHash(data);
			return SignHash(hash);
		}

		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public byte[] CreateSignature(Stream data, object hashAlgorithm)
		{
			var hash = CreateHashAlgorithm(hashAlgorithm).ComputeHash(data);
			return SignHash(hash);
		}

		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public byte[] CreateSignature(byte[] data, int dataOffset, int dataLength, object hashAlgorithm)
		{
			var hash = CreateHashAlgorithm(hashAlgorithm).ComputeHash(data, dataOffset, dataLength);
			return SignHash(hash);
		}

		[SecuritySafeCritical]
		private byte[] SignHash(byte[] hash)
		{
			if (hash == null)
			{
				throw ExceptionUtility.ArgumentNull("hash");
			}

			if (hash.Length != 32)
			{
				throw ExceptionUtility.ArgumentOutOfRange("hash", "InvalidHashSize");
			}

			var res = CryptoApiHelper.SignValue(_providerHandle, _providerParameters.KeyNumber, hash, GostAlgorithmType.Gost2001);

			return res;
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		public override bool VerifySignature(byte[] hash, byte[] signature)
		{
			return VerifyHash(hash, signature);
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public bool VerifySignature(byte[] buffer, object hashAlgorithm, byte[] signature)
		{
			var hash = CreateHashAlgorithm(hashAlgorithm).ComputeHash(buffer);
			return VerifyHash(hash, signature);
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		[SecuritySafeCritical]
		public bool VerifySignature(Stream inputStream, object hashAlgorithm, byte[] signature)
		{
			var hash = CreateHashAlgorithm(hashAlgorithm).ComputeHash(inputStream);
			return VerifyHash(hash, signature);
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		public bool VerifySignature(byte[] data, int dataOffset, int dataLength, object hashAlgorithm, byte[] signature)
		{
			var hash = CreateHashAlgorithm(hashAlgorithm).ComputeHash(data, dataOffset, dataLength);
			return VerifyHash(hash, signature);
		}

		[SecuritySafeCritical]
		private bool VerifyHash(byte[] hash, byte[] signature)
		{
			if (hash == null)
			{
				throw ExceptionUtility.ArgumentNull("hash");
			}

			if (signature == null)
			{
				throw ExceptionUtility.ArgumentNull("signature");
			}

			if (hash.Length != 32)
			{
				throw ExceptionUtility.ArgumentOutOfRange("InvalidHashSize");
			}

			bool res = false;
			UsingKey(h =>
			{
				res = CryptoApiHelper.VerifySign(_providerHandle, h, hash, signature, GostAlgorithmType.Gost2001);
			});
			return res;
		}

		/// <summary>
		/// Создает общий секретный ключ.
		/// </summary>
		/// <param name="keyParameters">Параметры открытого ключа, используемого для создания общего секретного ключа.</param>
		[SecuritySafeCritical]
		public override GostSharedSecret CreateKeyExchange(GostKeyExchangeParameters keyParameters)
		{
			GostSharedSecret res = null;
			UsingKey(h =>
			{
				res = new GostSharedSecretAlgorithm(_providerHandle, h, new GostKeyExchangeParameters(keyParameters), GostAlgorithmType.Gost2001);
			});

			return res;
		}

		/// <summary>
		/// Экспортирует (шифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="includePrivateKey">Включить секретный ключ.</param>
		/// <exception cref="NotSupportedException"></exception>
		[SecuritySafeCritical]
		public override GostKeyExchangeParameters ExportParameters(bool includePrivateKey)
		{
			if (includePrivateKey)
			{
				throw new NotSupportedException();
			}

			GostKeyExchangeParameters res = null;
            UsingKey(h =>
			{
				res = CryptoApiHelper.ExportPublicKey(h, GostAlgorithmType.Gost2001);
			});
			return res;
		}

		/// <summary>
		/// Импортирует (дешифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="keyParameters">Параметры ключа, используемого для создания общего секретного ключа.</param>
		/// <exception cref="NotSupportedException"></exception>
		[SecuritySafeCritical]
		public override void ImportParameters(GostKeyExchangeParameters keyParameters)
		{
			if (keyParameters.PrivateKey != null)
			{
				throw ExceptionUtility.NotSupported(Resources.UserImportBulkKeyNotSupported);
			}

			_keyHandleFunc = () =>
			{
				return CryptoApiHelper.ImportPublicKey(_providerHandle, new GostKeyExchangeParameters(keyParameters), GostAlgorithmType.Gost2001);
			};
		}

		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			_providerHandle.TryDispose();

			base.Dispose(disposing);
		}

		// Helpers

		private static readonly object ObjToHashAlgorithmMethodSync = new object();

		private static volatile MethodInfo _objToHashAlgorithmMethod;

		private static HashAlgorithm CreateHashAlgorithm(object hashAlg)
		{
			if (hashAlg == null)
			{
				throw ExceptionUtility.ArgumentNull("hashAlg");
			}

			if (!GetHashAlgorithmOid(hashAlg).Equals(Constants.OID_GR3411_2001, StringComparison.OrdinalIgnoreCase))
			{
				throw ExceptionUtility.Argument("hashAlg", Resources.RequiredGost3411);
			}

			HashAlgorithm hashAlgorithm = null;

			if (_objToHashAlgorithmMethod == null)
			{
				lock (ObjToHashAlgorithmMethodSync)
				{
					if (_objToHashAlgorithmMethod == null)
					{
						var utilsType = Type.GetType("System.Security.Cryptography.Utils");

						if (utilsType != null)
						{
							_objToHashAlgorithmMethod = utilsType.GetMethod("ObjToHashAlgorithm", BindingFlags.Static | BindingFlags.NonPublic, null, new[] { typeof(object) }, null);
						}
					}
				}
			}

			if (_objToHashAlgorithmMethod != null)
			{
				try
				{
					hashAlgorithm = _objToHashAlgorithmMethod.Invoke(null, new[] { hashAlg }) as HashAlgorithm;
				}
				catch (TargetInvocationException exception)
				{
					if (exception.InnerException != null)
					{
						throw exception.InnerException;
					}

					throw;
				}
			}

			return hashAlgorithm;
		}

		private static string GetHashAlgorithmOid(object hashAlg)
		{
			string hashAlgOid = null;

			if (hashAlg is string)
			{
				hashAlgOid = GostCryptoConfig.MapNameToOID((string)hashAlg);

				if (string.IsNullOrEmpty(hashAlgOid))
				{
					hashAlgOid = (string)hashAlg;
				}
			}
			else if (hashAlg is HashAlgorithm)
			{
				hashAlgOid = GostCryptoConfig.MapNameToOID(hashAlg.GetType().ToString());
			}
			else if (hashAlg is Type)
			{
				hashAlgOid = GostCryptoConfig.MapNameToOID(hashAlg.ToString());
			}

			if (string.IsNullOrEmpty(hashAlgOid))
			{
				throw ExceptionUtility.Argument("hashAlg", Resources.InvalidHashAlgorithm);
			}

			return hashAlgOid;
		}

		SafeKeyHandleImpl PrivateKey()
		{
			SafeKeyHandleImpl keyHandle = SafeKeyHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptGetUserKey(_providerHandle, (uint)_providerParameters.KeyNumber, ref keyHandle))
			{
				throw ExceptionUtility.CryptographicException(Marshal.GetLastWin32Error());
			}

			return keyHandle;
        }
	}
}