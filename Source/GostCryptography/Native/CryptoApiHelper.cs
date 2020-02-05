using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using GostCryptography.Asn1;
using GostCryptography.Asn1.Common;
using GostCryptography.Cryptography;
using GostCryptography.Properties;

namespace GostCryptography.Native
{
	/// <summary>
	/// Вспомогательные методы для работы с Microsoft CryptoAPI.
	/// </summary>
	[SecurityCritical]
	static class CryptoApiHelper
	{
		#region Общие объекты

		private static readonly object ProviderHandleSync = new object();
		private static volatile Dictionary<int, SafeProvHandleImpl> _providerHandles = new Dictionary<int, SafeProvHandleImpl>();

		public static SafeProvHandleImpl ProviderHandle
		{
			get
			{
				var providerType = GostCryptoConfig.ProviderType;

				if (!_providerHandles.ContainsKey(providerType))
				{
					lock (ProviderHandleSync)
					{
						if (!_providerHandles.ContainsKey(providerType))
						{
							var providerParams = new CspParameters(providerType);
							var providerHandle = AcquireProvider(providerParams);

							Thread.MemoryBarrier();

							_providerHandles.Add(providerType, providerHandle);
						}
					}
				}

				return _providerHandles[providerType];
			}
		}

		private static readonly object RandomNumberGeneratorSync = new object();
		private static volatile Dictionary<int, RNGCryptoServiceProvider> _randomNumberGenerators = new Dictionary<int, RNGCryptoServiceProvider>();

		public static RNGCryptoServiceProvider RandomNumberGenerator
		{
			get
			{
				var providerType = GostCryptoConfig.ProviderType;

				if (!_randomNumberGenerators.ContainsKey(providerType))
				{
					lock (RandomNumberGeneratorSync)
					{
						if (!_randomNumberGenerators.ContainsKey(providerType))
						{
							var providerParams = new CspParameters(GostCryptoConfig.ProviderType);
							var randomNumberGenerator = new RNGCryptoServiceProvider(providerParams);

							Thread.MemoryBarrier();

							_randomNumberGenerators.Add(providerType, randomNumberGenerator);
						}
					}
				}

				return _randomNumberGenerators[providerType];
			}
		}

		#endregion

		#region Для работы с криптографическим провайдером

		public static SafeProvHandleImpl AcquireProvider(CspParameters providerParameters)
		{
			var providerHandle = SafeProvHandleImpl.InvalidHandle;

			if (providerParameters == null)
			{
				providerParameters = new CspParameters(GostCryptoConfig.ProviderType);
			}

			var dwFlags = Constants.CRYPT_VERIFYCONTEXT;

			if ((providerParameters.Flags & CspProviderFlags.UseMachineKeyStore) != CspProviderFlags.NoFlags)
			{
				dwFlags |= Constants.CRYPT_MACHINE_KEYSET;
			}

			if (!CryptoApi.CryptAcquireContext(ref providerHandle, providerParameters.KeyContainerName, providerParameters.ProviderName, (uint)providerParameters.ProviderType, dwFlags))
			{
				throw CreateWin32Error();
			}

			return providerHandle;
		}

		public static int OpenProvider(CspParameters providerParameters, ref SafeProvHandleImpl hProv)
		{
			uint dwFlags = MapCspProviderFlags(providerParameters.Flags);
			if (!CryptoApi.CryptAcquireContext(ref hProv, providerParameters.KeyContainerName, providerParameters.ProviderName, (uint)providerParameters.ProviderType, dwFlags))
			{
				return Marshal.GetLastWin32Error();
			}
			return 0;


			//var providerHandle = SafeProvHandleImpl.InvalidHandle;
			//var dwFlags = MapCspProviderFlags(providerParameters.Flags);

			//if (!CryptoApi.CryptAcquireContext(ref providerHandle, providerParameters.KeyContainerName, providerParameters.ProviderName, (uint)providerParameters.ProviderType, dwFlags))
			//{
			//             throw CreateWin32Error();
			//}

			//return providerHandle;
		}

		public static SafeProvHandleImpl CreateProvider(CspParameters providerParameters)
		{
			var providerHandle = SafeProvHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptAcquireContext(ref providerHandle, providerParameters.KeyContainerName, providerParameters.ProviderName, (uint)providerParameters.ProviderType, Constants.CRYPT_NEWKEYSET))
			{
				throw CreateWin32Error();
			}

			return providerHandle;
		}

		private static uint MapCspProviderFlags(CspProviderFlags flags)
		{
			uint dwFlags = 0;

			if ((flags & CspProviderFlags.UseMachineKeyStore) != CspProviderFlags.NoFlags)
			{
				dwFlags |= Constants.CRYPT_MACHINE_KEYSET;
			}

			if ((flags & CspProviderFlags.NoPrompt) != CspProviderFlags.NoFlags)
			{
				dwFlags |= Constants.CRYPT_PREGEN;
			}

			return dwFlags;
		}

		public static void SetProviderParameter(SafeProvHandleImpl providerHandle, int keyNumber, uint keyParamId, IntPtr keyParamValue)
		{
			//if ((keyParamId == Constants.PP_KEYEXCHANGE_PIN) || (keyParamId == Constants.PP_SIGNATURE_PIN))
			//{
			//	if (keyNumber == Constants.AT_KEYEXCHANGE)
			//	{
			//		keyParamId = Constants.PP_KEYEXCHANGE_PIN;
			//	}
			//	else if (keyNumber == Constants.AT_SIGNATURE)
			//	{
			//		keyParamId = Constants.PP_SIGNATURE_PIN;
			//	}
			//	else
			//	{
			//		throw ExceptionUtility.NotSupported(Resources.KeyAlgorithmNotSupported);
			//	}
			//}

			if (!CryptoApi.CryptSetProvParam(providerHandle, keyParamId, keyParamValue, 0))
			{
				throw CreateWin32Error();
			}
		}

        #endregion

        #region Для работы с функцией хэширования криптографического провайдера

        private static SafeHashHandleImpl CreateHash(SafeProvHandleImpl providerHandle, int hashAlgId)
        {
            var hashHandle = SafeHashHandleImpl.InvalidHandle;

            if (!CryptoApi.CryptCreateHash(providerHandle, (uint)hashAlgId, SafeKeyHandleImpl.InvalidHandle, 0, ref hashHandle))
            {
                throw CreateWin32Error();
            }

            return hashHandle;
        }

        public static SafeHashHandleImpl CreateHash_3411_94(SafeProvHandleImpl providerHandle)
		{
			return CreateHash(providerHandle, Constants.CALG_GR3411);
        }

        public static SafeHashHandleImpl CreateHash_3411_2012_256(SafeProvHandleImpl providerHandle)
        {
            return CreateHash(providerHandle, Constants.CALG_GR3411_2012_256);
        }

        public static SafeHashHandleImpl CreateHash_3411_2012_512(SafeProvHandleImpl providerHandle)
        {
            return CreateHash(providerHandle, Constants.CALG_GR3411_2012_512);
        }

        public static SafeHashHandleImpl CreateHashImit(SafeProvHandleImpl providerHandle, SafeKeyHandleImpl symKeyHandle)
		{
			var hashImitHandle = SafeHashHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptCreateHash(providerHandle, Constants.CALG_G28147_IMIT, symKeyHandle, 0, ref hashImitHandle))
			{
				throw CreateWin32Error();
			}

			return hashImitHandle;
		}

		public static SafeHashHandleImpl CreateHashHmac(SafeProvHandleImpl providerHandle, SafeKeyHandleImpl symKeyHandle, int hashAlgId)
		{
			var hashHmacHandle = SafeHashHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptCreateHash(providerHandle, (uint)hashAlgId, symKeyHandle, 0, ref hashHmacHandle))
			{
				var errorCode = Marshal.GetLastWin32Error();

				if (errorCode == Constants.NTE_BAD_ALGID)
				{
					throw ExceptionUtility.CryptographicException(Resources.AlgorithmNotAvailable);
				}

				throw ExceptionUtility.CryptographicException(errorCode);
			}

			return hashHmacHandle;
		}

		public static unsafe void HashData(SafeHashHandleImpl hashHandle, byte[] data, int dataOffset, int dataLength)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull("data");
			}

			if (dataOffset < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange("dataOffset");
			}

			if (dataLength < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange("dataLength");
			}

			if (data.Length < dataOffset + dataLength)
			{
				throw ExceptionUtility.ArgumentOutOfRange("dataLength");
			}

			if (dataLength > 0)
			{
				fixed (byte* dataRef = data)
				{
					var dataOffsetRef = dataRef + dataOffset;

					if (!CryptoApi.CryptHashData(hashHandle, dataOffsetRef, (uint)dataLength, 0))
					{
						throw CreateWin32Error();
					}
				}
			}
		}

		public static byte[] EndHashData(SafeHashHandleImpl hashHandle)
		{
			uint dataLength = 0;

			if (!CryptoApi.CryptGetHashParam(hashHandle, Constants.HP_HASHVAL, null, ref dataLength, 0))
			{
				throw CreateWin32Error();
			}

			var data = new byte[dataLength];

			if (!CryptoApi.CryptGetHashParam(hashHandle, Constants.HP_HASHVAL, data, ref dataLength, 0))
			{
				throw CreateWin32Error();
			}

			return data;
		}

		public static void HashKeyExchange(SafeHashHandleImpl hashHandle, SafeKeyHandleImpl keyExchangeHandle)
		{
			if (!CryptoApi.CryptHashSessionKey(hashHandle, keyExchangeHandle, 0))
			{
				throw CreateWin32Error();
			}
		}

		#endregion

		#region Для работы с функцией шифрования криптографического провайдера

		public static int EncryptData(SafeKeyHandleImpl symKeyHandle, byte[] data, int dataOffset, int dataLength, ref byte[] encryptedData, int encryptedDataOffset, PaddingMode paddingMode, bool isDone, bool isStream)
		{
			if (dataOffset < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange("dataOffset");
			}

			if (dataLength < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange("dataLength");
			}

			if (dataOffset > data.Length)
			{
				throw ExceptionUtility.ArgumentOutOfRange("dataOffset", Resources.InvalidDataOffset);
			}

			var length = dataLength;

			if (isDone)
			{
				length += 8;
			}

			// Выровненные данные
			var dataAlignLength = (uint)dataLength;
			var dataAlignArray = new byte[length];
			Array.Clear(dataAlignArray, 0, length);
			Array.Copy(data, dataOffset, dataAlignArray, 0, dataLength);

			if (isDone)
			{
				var dataPadding = dataLength & 7;
				var dataPaddingSize = (byte)(8 - dataPadding);

				// Добпаление дополнения данных в зависимости от настроек
				switch (paddingMode)
				{
					case PaddingMode.None:
						if ((dataPadding != 0) && !isStream)
						{
							throw ExceptionUtility.CryptographicException(Resources.EncryptInvalidDataSize);
						}
						break;
					case PaddingMode.Zeros:
						if (dataPadding != 0)
						{
							dataAlignLength += dataPaddingSize;

							// Дополнение заполняется нулевыми байтами
						}
						break;
					case PaddingMode.PKCS7:
						{
							dataAlignLength += dataPaddingSize;

							var paddingIndex = dataLength;

							// Дополнение заполняется байтами, в каждый из которых записывается размер дополнения
							while (paddingIndex < dataAlignLength)
							{
								dataAlignArray[paddingIndex++] = dataPaddingSize;
							}
						}
						break;
					case PaddingMode.ANSIX923:
						{
							dataAlignLength += dataPaddingSize;

							// Дополнение заполняется нулевыми, кроме последнего - в него записывается размер дополнения
							dataAlignArray[(int)((IntPtr)(dataAlignLength - 1))] = dataPaddingSize;
						}
						break;
					case PaddingMode.ISO10126:
						{
							dataAlignLength += dataPaddingSize;

							// Дополнение заполняется случайными байтами, кроме последнего - в него записывается размер дополнения
							var randomPadding = new byte[dataPaddingSize - 1];
							RandomNumberGenerator.GetBytes(randomPadding);
							randomPadding.CopyTo(dataAlignArray, dataLength);
							dataAlignArray[(int)((IntPtr)(dataAlignLength - 1))] = dataPaddingSize;
						}
						break;
					default:
						throw ExceptionUtility.Argument("paddingMode", Resources.InvalidPaddingMode);
				}
			}

			// Шифрование данных
			if (!CryptoApi.CryptEncrypt(symKeyHandle, SafeHashHandleImpl.InvalidHandle, false, 0, dataAlignArray, ref dataAlignLength, (uint)length))
			{
				throw CreateWin32Error();
			}

			// Копирование результата шифрования данных

			if (encryptedData == null)
			{
				encryptedData = new byte[dataAlignLength];

				Array.Copy(dataAlignArray, 0L, encryptedData, 0L, dataAlignLength);
			}
			else
			{
				if (encryptedDataOffset < 0)
				{
					throw ExceptionUtility.ArgumentOutOfRange("encryptedDataOffset");
				}

				if ((encryptedData.Length < dataAlignLength) || ((encryptedData.Length - dataAlignLength) < encryptedDataOffset))
				{
					throw ExceptionUtility.ArgumentOutOfRange("encryptedDataOffset", Resources.InvalidDataOffset);
				}

				Array.Copy(dataAlignArray, 0L, encryptedData, encryptedDataOffset, dataAlignLength);
			}

			return (int)dataAlignLength;
		}

		public static int DecryptData(SafeKeyHandleImpl symKeyHandle, byte[] data, int dataOffset, int dataLength, ref byte[] decryptedData, int decryptedDataOffset, PaddingMode paddingMode, bool isDone)
		{
			if (dataOffset < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange("dataOffset");
			}

			if (dataLength < 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange("dataLength");
			}

			if ((dataOffset > data.Length) || ((dataOffset + dataLength) > data.Length))
			{
				throw ExceptionUtility.ArgumentOutOfRange("dataOffset", Resources.InvalidDataOffset);
			}

			// Выровненные данные
			var dataAlignLength = (uint)dataLength;
			var dataAlign = new byte[dataAlignLength];
			Array.Copy(data, dataOffset, dataAlign, 0L, dataAlignLength);

			// Расшифровка данных
			if (!CryptoApi.CryptDecrypt(symKeyHandle, SafeHashHandleImpl.InvalidHandle, false, 0, dataAlign, ref dataAlignLength))
			{
				throw CreateWin32Error();
			}

			var length = (int)dataAlignLength;

			if (isDone)
			{
				byte dataPaddingSize = 0;

				// Удаление дополнения данных в зависимости от настроек
				if (((paddingMode == PaddingMode.PKCS7) || (paddingMode == PaddingMode.ANSIX923)) || (paddingMode == PaddingMode.ISO10126))
				{
					if (dataAlignLength < 8)
					{
						throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
					}

					// Размер дополнения находится в последнем байте
					dataPaddingSize = dataAlign[(int)((IntPtr)(dataAlignLength - 1))];

					if (dataPaddingSize > 8)
					{
						throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
					}

					// Проверка корректности дополнения данных
					if (paddingMode == PaddingMode.PKCS7)
					{
						for (var paddingIndex = dataAlignLength - dataPaddingSize; paddingIndex < (dataAlignLength - 1); paddingIndex++)
						{
							if (dataAlign[paddingIndex] != dataPaddingSize)
							{
								throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
							}
						}
					}
					else if (paddingMode == PaddingMode.ANSIX923)
					{
						for (var paddingIndex = dataAlignLength - dataPaddingSize; paddingIndex < (dataAlignLength - 1); paddingIndex++)
						{
							if (dataAlign[paddingIndex] != 0)
							{
								throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
							}
						}
					}
				}
				else if ((paddingMode != PaddingMode.None) && (paddingMode != PaddingMode.Zeros))
				{
					throw ExceptionUtility.Argument("paddingMode", Resources.InvalidPaddingMode);
				}

				length -= dataPaddingSize;
			}

			if (decryptedData == null)
			{
				decryptedData = new byte[length];

				Array.Copy(dataAlign, 0, decryptedData, 0, length);
			}
			else
			{
				if (decryptedDataOffset < 0)
				{
					throw ExceptionUtility.ArgumentOutOfRange("decryptedDataOffset");
				}

				if ((decryptedData.Length < length) || ((decryptedData.Length - length) < decryptedDataOffset))
				{
					throw ExceptionUtility.ArgumentOutOfRange("decryptedData", Resources.InvalidDataOffset);
				}

				Array.Copy(dataAlign, 0, decryptedData, decryptedDataOffset, length);
			}

			return length;
		}

		public static void EndCrypt(SafeKeyHandleImpl symKeyHandle, Gost28147CryptoTransformMode transformMode)
		{
			bool success;
			uint dataLength = 0;

			if (transformMode == Gost28147CryptoTransformMode.Encrypt)
			{
				var data = new byte[32];
				success = CryptoApi.CryptEncrypt(symKeyHandle, SafeHashHandleImpl.InvalidHandle, true, 0, data, ref dataLength, (uint)data.Length);
			}
			else
			{
				var data = new byte[0];
				success = CryptoApi.CryptDecrypt(symKeyHandle, SafeHashHandleImpl.InvalidHandle, true, 0, data, ref dataLength) || (GostCryptoConfig.ProviderType == ProviderTypes.VipNet);
			}

			if (!success)
			{
				throw CreateWin32Error();
			}
		}

		#endregion

		#region Для работы с ключами криптографического провайдера

		public static SafeKeyHandleImpl GenerateKey(SafeProvHandleImpl providerHandle, int algId, CspProviderFlags flags)
		{
			var keyHandle = SafeKeyHandleImpl.InvalidHandle;
			var dwFlags = MapCspKeyFlags(flags);

			if (!CryptoApi.CryptGenKey(providerHandle, (uint)algId, dwFlags, ref keyHandle))
			{
				throw CreateWin32Error();
			}

			return keyHandle;
		}

		public static SafeKeyHandleImpl GenerateDhEphemeralKey(SafeProvHandleImpl providerHandle, int algId, string digestParamSet, string publicKeyParamSet)
		{
			var keyHandle = SafeKeyHandleImpl.InvalidHandle;
			var dwFlags = MapCspKeyFlags(CspProviderFlags.NoFlags) | Constants.CRYPT_PREGEN;

			if (!CryptoApi.CryptGenKey(providerHandle, (uint)algId, dwFlags, ref keyHandle))
			{
				throw CreateWin32Error();
			}

			SetKeyParameterString(keyHandle, Constants.KP_HASHOID, digestParamSet);
			SetKeyParameterString(keyHandle, Constants.KP_DHOID, publicKeyParamSet);
			SetKeyParameter(keyHandle, Constants.KP_X, null);

			return keyHandle;
		}

		private static uint MapCspKeyFlags(CspProviderFlags flags)
		{
			uint dwFlags = 0;

			if ((flags & CspProviderFlags.UseNonExportableKey) == CspProviderFlags.NoFlags)
			{
				dwFlags |= Constants.CRYPT_EXPORTABLE;
			}

			if ((flags & CspProviderFlags.UseArchivableKey) != CspProviderFlags.NoFlags)
			{
				dwFlags |= Constants.CRYPT_ARCHIVABLE;
			}

			if ((flags & CspProviderFlags.UseUserProtectedKey) != CspProviderFlags.NoFlags)
			{
				dwFlags |= Constants.CRYPT_USER_PROTECTED;
			}

			return dwFlags;
		}

		public static int GetUserKey(SafeProvHandleImpl providerHandle, int keyNumber, ref SafeKeyHandleImpl keyHandle)
		{
			if (!CryptoApi.CryptGetUserKey(providerHandle, (uint)keyNumber, ref keyHandle))
			{
				return Marshal.GetLastWin32Error();
			}
			return 0;
		}

		public static SafeKeyHandleImpl DeriveSymKey(SafeProvHandleImpl providerHandle, SafeHashHandleImpl hashHandle)
		{
			var symKeyHandle = SafeKeyHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptDeriveKey(providerHandle, Constants.CALG_G28147, hashHandle, Constants.CRYPT_EXPORTABLE, ref symKeyHandle))
			{
				throw CreateWin32Error();
			}

			return symKeyHandle;
		}

		public static SafeKeyHandleImpl DuplicateKey(IntPtr sourceKeyHandle)
		{
			var keyHandle = SafeKeyHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptDuplicateKey(sourceKeyHandle, null, 0, ref keyHandle))
			{
				throw CreateWin32Error();
			}

			return keyHandle;
		}

		public static SafeKeyHandleImpl DuplicateKey(SafeKeyHandleImpl sourceKeyHandle)
		{
			return DuplicateKey(sourceKeyHandle.DangerousGetHandle());
		}

		public static int GetKeyParameterInt32(SafeKeyHandleImpl keyHandle, uint keyParamId)
		{
			const int doubleWordSize = 4;

			uint dwDataLength = doubleWordSize;
			var dwDataBytes = new byte[doubleWordSize];

			if (!CryptoApi.CryptGetKeyParam(keyHandle, keyParamId, dwDataBytes, ref dwDataLength, 0))
			{
				throw CreateWin32Error();
			}

			if (dwDataLength != doubleWordSize)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			return BitConverter.ToInt32(dwDataBytes, 0);
		}

		private static string GetKeyParameterString(SafeKeyHandleImpl keyHandle, uint keyParamId)
		{
			var paramValue = GetKeyParameter(keyHandle, keyParamId);

			return BytesToString(paramValue);
		}

		private static string BytesToString(byte[] value)
		{
			string valueString;

			try
			{
				valueString = Encoding.GetEncoding(0).GetString(value);

				var length = 0;

				while (length < valueString.Length)
				{
					// Строка заканчивается нулевым символом
					if (valueString[length] == '\0')
					{
						break;
					}

					length++;
				}

				if (length == valueString.Length)
				{
					throw ExceptionUtility.CryptographicException(Resources.InvalidString);
				}

				valueString = valueString.Substring(0, length);
			}
			catch (DecoderFallbackException exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.InvalidString);
			}

			return valueString;
		}

		public static byte[] GetKeyParameter(SafeKeyHandleImpl keyHandle, uint keyParamId)
		{
			uint dataLength = 0;

			if (!CryptoApi.CryptGetKeyParam(keyHandle, keyParamId, null, ref dataLength, 0))
			{
				throw CreateWin32Error();
			}

			var dataBytes = new byte[dataLength];

			if (!CryptoApi.CryptGetKeyParam(keyHandle, keyParamId, dataBytes, ref dataLength, 0))
			{
				throw CreateWin32Error();
			}

			return dataBytes;
		}

		public static void SetKeyParameterInt32(SafeKeyHandleImpl keyHandle, int keyParamId, int keyParamValue)
		{
			var dwDataBytes = BitConverter.GetBytes(keyParamValue);

			if (!CryptoApi.CryptSetKeyParam(keyHandle, (uint)keyParamId, dwDataBytes, 0))
			{
				throw CreateWin32Error();
			}
		}

		private static void SetKeyParameterString(SafeKeyHandleImpl keyHandle, int keyParamId, string keyParamValue)
		{
			var stringDataBytes = Encoding.GetEncoding(0).GetBytes(keyParamValue);

			if (!CryptoApi.CryptSetKeyParam(keyHandle, (uint)keyParamId, stringDataBytes, 0))
			{
				throw CreateWin32Error();
			}
		}

		public static void SetKeyParameter(SafeKeyHandleImpl keyHandle, int keyParamId, byte[] keyParamValue)
		{
			if (!CryptoApi.CryptSetKeyParam(keyHandle, (uint)keyParamId, keyParamValue, 0))
			{
				throw CreateWin32Error();
			}
		}

		//public static void UsingKey(SafeProvHandleImpl providerHandle, uint keyNumber, Action<SafeKeyHandleImpl> operation)
		//{
		//	SafeKeyHandleImpl keyHandle = SafeKeyHandleImpl.InvalidHandle;

		//	if (!CryptoApi.CryptGetUserKey(providerHandle, keyNumber, ref keyHandle))
		//	{
		//		throw CreateWin32Error();
		//	}

		//	operation(keyHandle);
		//	keyHandle.TryDispose();
		//}

		#endregion

		#region Для экспорта ключей криптографического провайдера

		public static byte[] ExportCspBlob(SafeKeyHandleImpl symKeyHandle, SafeKeyHandleImpl keyExchangeHandle, int blobType)
		{
			uint exportedKeyLength = 0;

			if (!CryptoApi.CryptExportKey(symKeyHandle, keyExchangeHandle, (uint)blobType, 0, null, ref exportedKeyLength))
			{
				throw CreateWin32Error();
			}

			var exportedKeyBytes = new byte[exportedKeyLength];

			if (!CryptoApi.CryptExportKey(symKeyHandle, keyExchangeHandle, (uint)blobType, 0, exportedKeyBytes, ref exportedKeyLength))
			{
				throw CreateWin32Error();
			}

			return exportedKeyBytes;
		}

		public static GostKeyExchangeParameters ExportPublicKey(SafeKeyHandleImpl symKeyHandle, GostAlgorithmType algorithm)
		{
			var exportedKeyBytes = ExportCspBlob(symKeyHandle, SafeKeyHandleImpl.InvalidHandle, Constants.PUBLICKEYBLOB);
			return DecodePublicBlob(exportedKeyBytes, algorithm);
		}

		private static GostKeyExchangeParameters DecodePublicBlob(byte[] encodedPublicBlob, GostAlgorithmType algorithm)
		{
			if (encodedPublicBlob == null)
			{
				throw ExceptionUtility.ArgumentNull("encodedPublicBlob");
			}

            int size;
            switch (algorithm)
            {
                case GostAlgorithmType.Gost2001:
                    size = 512;
                    break;
                case GostAlgorithmType.Gost2012_256:
                    size = 512;
                    break;
                case GostAlgorithmType.Gost2012_512:
                    size = 1024;
                    break;
                default:
                    throw new CryptographicException(Resources.AlgorithmNotAvailable);
            }

            if (encodedPublicBlob.Length < 16 + size / 8)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			var gostKeyMask = BitConverter.ToUInt32(encodedPublicBlob, 8);

			if (gostKeyMask != Constants.GR3410_1_MAGIC)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			var gostKeySize = BitConverter.ToUInt32(encodedPublicBlob, 12);

			if (gostKeySize != size)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			var publicKeyParameters = new GostKeyExchangeParameters();

			var encodeKeyParameters = new byte[(encodedPublicBlob.Length - 16) - size / 8];
			Array.Copy(encodedPublicBlob, 16, encodeKeyParameters, 0, (encodedPublicBlob.Length - 16) - size / 8);
			publicKeyParameters.DecodeParameters(encodeKeyParameters);

			var publicKey = new byte[64];
			Array.Copy(encodedPublicBlob, encodedPublicBlob.Length - size / 8, publicKey, 0, size / 8);
			publicKeyParameters.PublicKey = publicKey;

			return publicKeyParameters;
		}

		public static GostKeyExchangeInfo ExportKeyExchange(SafeKeyHandleImpl symKeyHandle, SafeKeyHandleImpl keyExchangeHandle)
		{
			var exportedKeyBytes = ExportCspBlob(symKeyHandle, keyExchangeHandle, Constants.SIMPLEBLOB);

			return DecodeSimpleBlob(exportedKeyBytes);
		}

		private static GostKeyExchangeInfo DecodeSimpleBlob(byte[] exportedKeyBytes)
		{
			if (exportedKeyBytes == null)
			{
				throw ExceptionUtility.ArgumentNull("exportedKeyBytes");
			}

			if (exportedKeyBytes.Length < 16)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			if (BitConverter.ToUInt32(exportedKeyBytes, 4) != Constants.CALG_G28147)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			if (BitConverter.ToUInt32(exportedKeyBytes, 8) != Constants.G28147_MAGIC)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			if (BitConverter.ToUInt32(exportedKeyBytes, 12) != Constants.CALG_G28147)
			{
				throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_DATA);
			}

			var keyExchangeInfo = new GostKeyExchangeInfo();

			var sourceIndex = 16;
			keyExchangeInfo.Ukm = new byte[8];
			Array.Copy(exportedKeyBytes, sourceIndex, keyExchangeInfo.Ukm, 0, 8);
			sourceIndex += 8;

			keyExchangeInfo.EncryptedKey = new byte[32];
			Array.Copy(exportedKeyBytes, sourceIndex, keyExchangeInfo.EncryptedKey, 0, 32);
			sourceIndex += 32;

			keyExchangeInfo.Mac = new byte[4];
			Array.Copy(exportedKeyBytes, sourceIndex, keyExchangeInfo.Mac, 0, 4);
			sourceIndex += 4;

			var encryptionParamSet = new byte[exportedKeyBytes.Length - sourceIndex];
			Array.Copy(exportedKeyBytes, sourceIndex, encryptionParamSet, 0, exportedKeyBytes.Length - sourceIndex);
			keyExchangeInfo.EncryptionParamSet = GostKeyExchangeInfo.DecodeEncryptionParamSet(encryptionParamSet);

			return keyExchangeInfo;
		}

		#endregion

		#region Для импорта ключей криптографического провайдера

		public static int ImportCspBlob(byte[] importedKeyBytes, SafeProvHandleImpl providerHandle, SafeKeyHandleImpl publicKeyHandle, out SafeKeyHandleImpl keyExchangeHandle)
		{
			var dwFlags = MapCspKeyFlags(CspProviderFlags.NoFlags);
			var keyExchangeRef = SafeKeyHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptImportKey(providerHandle, importedKeyBytes, (uint)importedKeyBytes.Length, publicKeyHandle, dwFlags, ref keyExchangeRef))
			{
				throw CreateWin32Error();
			}

			var keyNumberMask = BitConverter.ToInt32(importedKeyBytes, 4) & 0xE000;
			var keyNumber = (keyNumberMask == 0xA000) ? Constants.AT_KEYEXCHANGE : Constants.AT_SIGNATURE;

			keyExchangeHandle = keyExchangeRef;

			return keyNumber;
		}

		public static SafeKeyHandleImpl ImportPublicKey(SafeProvHandleImpl providerHandle, GostKeyExchangeParameters publicKeyParameters, GostAlgorithmType algorithm)
		{
			if (publicKeyParameters == null)
			{
				throw ExceptionUtility.ArgumentNull("publicKeyParameters");
			}

			var importedKeyBytes = EncodePublicBlob(publicKeyParameters, algorithm);

			SafeKeyHandleImpl hKeyExchange;
			ImportCspBlob(importedKeyBytes, providerHandle, SafeKeyHandleImpl.InvalidHandle, out hKeyExchange);

			return hKeyExchange;
		}

		public static byte[] EncodePublicBlob(GostKeyExchangeParameters publicKeyParameters, GostAlgorithmType algorithm)
		{
			if (publicKeyParameters == null)
			{
				throw ExceptionUtility.ArgumentNull("publicKeyParameters");
			}

            int size;
            int value;
            switch (algorithm)
            {
                case GostAlgorithmType.Gost2001:
                    size = 512;
                    value = Constants.CALG_GR3410EL;
                    break;
                case GostAlgorithmType.Gost2012_256:
                    size = 512;
                    value = Constants.CALG_GR3410_2012_256;
                    break;
                case GostAlgorithmType.Gost2012_512:
                    size = 1024;
                    value = Constants.CALG_GR3410_2012_512;
                    break;
                default:
                    throw new CryptographicException(Resources.AlgorithmNotAvailable);
            }

            var encodeKeyParameters = publicKeyParameters.EncodeParameters();
			var importedKeyBytes = new byte[(encodeKeyParameters.Length + 16) + publicKeyParameters.PublicKey.Length];
			importedKeyBytes[0] = 6;
			importedKeyBytes[1] = 32;
			Array.Copy(BitConverter.GetBytes(value), 0, importedKeyBytes, 4, 4);
			Array.Copy(BitConverter.GetBytes(Constants.GR3410_1_MAGIC), 0, importedKeyBytes, 8, 4);
			Array.Copy(BitConverter.GetBytes(size), 0, importedKeyBytes, 12, 4);
			Array.Copy(encodeKeyParameters, 0, importedKeyBytes, 16, encodeKeyParameters.Length);
			Array.Copy(publicKeyParameters.PublicKey, 0, importedKeyBytes, encodeKeyParameters.Length + 16, publicKeyParameters.PublicKey.Length);

			return importedKeyBytes;
		}

		public static SafeKeyHandleImpl ImportKeyExchange(SafeProvHandleImpl providerHandle, GostKeyExchangeInfo keyExchangeInfo, SafeKeyHandleImpl keyExchangeHandle)
		{
			if (keyExchangeInfo == null)
			{
				throw ExceptionUtility.ArgumentNull("keyExchangeInfo");
			}

			var importedKeyBytes = EncodeSimpleBlob(keyExchangeInfo);

			SafeKeyHandleImpl hKeyExchange;
			ImportCspBlob(importedKeyBytes, providerHandle, keyExchangeHandle, out hKeyExchange);

			return hKeyExchange;
		}

		public static SafeKeyHandleImpl ImportBulkSessionKey(SafeProvHandleImpl providerHandle, byte[] bulkSessionKey, RNGCryptoServiceProvider randomNumberGenerator)
		{
			if (bulkSessionKey == null)
			{
				throw ExceptionUtility.ArgumentNull("bulkSessionKey");
			}

			if (randomNumberGenerator == null)
			{
				throw ExceptionUtility.ArgumentNull("randomNumberGenerator");
			}

			var hSessionKey = SafeKeyHandleImpl.InvalidHandle;

			if (!CryptoApi.CryptGenKey(providerHandle, Constants.CALG_G28147, 0, ref hSessionKey))
			{
				throw CreateWin32Error();
			}

			var keyWrap = new GostKeyExchangeInfo { EncryptedKey = new byte[32] };
			Array.Copy(bulkSessionKey, keyWrap.EncryptedKey, 32);
			SetKeyParameterInt32(hSessionKey, Constants.KP_MODE, Constants.CRYPT_MODE_ECB);
			SetKeyParameterInt32(hSessionKey, Constants.KP_ALGID, Constants.CALG_G28147);
			SetKeyParameterInt32(hSessionKey, Constants.KP_PADDING, Constants.ZERO_PADDING);

			uint sessionKeySize = 32;

			if (!CryptoApi.CryptEncrypt(hSessionKey, SafeHashHandleImpl.InvalidHandle, true, 0, keyWrap.EncryptedKey, ref sessionKeySize, sessionKeySize))
			{
				throw CreateWin32Error();
			}

			SetKeyParameterInt32(hSessionKey, Constants.KP_MODE, Constants.CRYPT_MODE_CFB);

			var hashHandle = CreateHashImit(providerHandle, hSessionKey);

			keyWrap.Ukm = new byte[8];
			randomNumberGenerator.GetBytes(keyWrap.Ukm);

			if (!CryptoApi.CryptSetHashParam(hashHandle, Constants.HP_HASHSTARTVECT, keyWrap.Ukm, 0))
			{
				throw CreateWin32Error();
			}

			if (!CryptoApi.CryptHashData(hashHandle, bulkSessionKey, 32, 0))
			{
				throw CreateWin32Error();
			}

			keyWrap.Mac = EndHashData(hashHandle);
			keyWrap.EncryptionParamSet = GetKeyParameterString(hSessionKey, Constants.KP_CIPHEROID);

			SetKeyParameterInt32(hSessionKey, Constants.KP_ALGID, Constants.CALG_SIMPLE_EXPORT);
			SetKeyParameterInt32(hSessionKey, Constants.KP_MODE, Constants.CRYPT_MODE_ECB);
			SetKeyParameterInt32(hSessionKey, Constants.KP_PADDING, Constants.ZERO_PADDING);

			return ImportKeyExchange(providerHandle, keyWrap, hSessionKey);
		}

		private static byte[] EncodeSimpleBlob(GostKeyExchangeInfo keyExchangeInfo)
		{
			if (keyExchangeInfo == null)
			{
				throw ExceptionUtility.ArgumentNull("keyExchangeInfo");
			}

			var encryptionParamSet = GostKeyExchangeInfo.EncodeEncryptionParamSet(keyExchangeInfo.EncryptionParamSet);
			var importedKeyBytes = new byte[encryptionParamSet.Length + 60];

			var sourceIndex = 0;
			importedKeyBytes[sourceIndex] = 1;
			sourceIndex++;

			importedKeyBytes[sourceIndex] = 32;
			sourceIndex++;
			sourceIndex += 2;

			Array.Copy(BitConverter.GetBytes(Constants.CALG_G28147), 0, importedKeyBytes, sourceIndex, 4);
			sourceIndex += 4;

			Array.Copy(BitConverter.GetBytes(Constants.G28147_MAGIC), 0, importedKeyBytes, sourceIndex, 4);
			sourceIndex += 4;

			Array.Copy(BitConverter.GetBytes(Constants.CALG_G28147), 0, importedKeyBytes, sourceIndex, 4);
			sourceIndex += 4;

			Array.Copy(keyExchangeInfo.Ukm, 0, importedKeyBytes, sourceIndex, 8);
			sourceIndex += 8;

			Array.Copy(keyExchangeInfo.EncryptedKey, 0, importedKeyBytes, sourceIndex, 32);
			sourceIndex += 32;

			Array.Copy(keyExchangeInfo.Mac, 0, importedKeyBytes, sourceIndex, 4);
			sourceIndex += 4;

			Array.Copy(encryptionParamSet, 0, importedKeyBytes, sourceIndex, encryptionParamSet.Length);

			return importedKeyBytes;
		}

		public static SafeKeyHandleImpl ImportAndMakeKeyExchange(SafeProvHandleImpl providerHandle, GostKeyExchangeParameters keyExchangeParameters, SafeKeyHandleImpl publicKeyHandle, GostAlgorithmType alg)
		{
			if (keyExchangeParameters == null)
			{
				throw ExceptionUtility.ArgumentNull("keyExchangeParameters");
			}

			var importedKeyBytes = EncodePublicBlob(keyExchangeParameters, alg);

			SafeKeyHandleImpl keyExchangeHandle;
			ImportCspBlob(importedKeyBytes, providerHandle, publicKeyHandle, out keyExchangeHandle);

			return keyExchangeHandle;
		}

		#endregion

		#region Для импорта ключей криптографического провайдера RSA, DSA

		static byte[] GetUnsignedBigInteger(byte[] integer)
		{
			if (integer[0] != 0x00)
				return integer;

			// this first byte is added so we're sure it's an unsigned integer
			// however we can't feed it into RSAParameters or DSAParameters
			int length = integer.Length - 1;
			byte[] uinteger = new byte[length];
			Buffer.BlockCopy(integer, 1, uinteger, 0, length);
			return uinteger;
		}

		public static DSA DecodeDSA(byte[] rawPublicKey, byte[] rawParameters)
		{
			DSAParameters dsaParams = new DSAParameters();
			try
			{
				// for DSA rawPublicKey contains 1 ASN.1 integer - Y
				ASN1 pubkey = new ASN1(rawPublicKey);
				if (pubkey.Tag != 0x02)
					throw new CryptographicException("Missing DSA Y integer.");
				dsaParams.Y = GetUnsignedBigInteger(pubkey.Value);

				ASN1 param = new ASN1(rawParameters);
				if ((param == null) || (param.Tag != 0x30) || (param.Count < 3))
					throw new CryptographicException("Missing DSA parameters.");
				if ((param[0].Tag != 0x02) || (param[1].Tag != 0x02) || (param[2].Tag != 0x02))
					throw new CryptographicException("Invalid DSA parameters.");

				dsaParams.P = GetUnsignedBigInteger(param[0].Value);
				dsaParams.Q = GetUnsignedBigInteger(param[1].Value);
				dsaParams.G = GetUnsignedBigInteger(param[2].Value);
			}
			catch (Exception e)
			{
				throw new CryptographicException("Error decoding the ASN.1 structure.", e);
			}

			DSA dsa = (DSA)new DSACryptoServiceProvider(dsaParams.Y.Length << 3);
			dsa.ImportParameters(dsaParams);
			return dsa;
		}

		public static RSA DecodeRSA(byte[] rawPublicKey)
		{
			RSAParameters rsaParams = new RSAParameters();
			try
			{
				// for RSA rawPublicKey contains 2 ASN.1 integers
				// the modulus and the public exponent
				ASN1 pubkey = new ASN1(rawPublicKey);
				if (pubkey.Count == 0)
					throw new CryptographicException("Missing RSA modulus and exponent.");
				ASN1 modulus = pubkey[0];
				if ((modulus == null) || (modulus.Tag != 0x02))
					throw new CryptographicException("Missing RSA modulus.");
				ASN1 exponent = pubkey[1];
				if (exponent.Tag != 0x02)
					throw new CryptographicException("Missing RSA public exponent.");

				rsaParams.Modulus = GetUnsignedBigInteger(modulus.Value);
				rsaParams.Exponent = exponent.Value;
			}
			catch (Exception e)
			{
				throw new CryptographicException("Error decoding the ASN.1 structure.", e);
			}

			int keySize = (rsaParams.Modulus.Length << 3);
			RSA rsa = (RSA)new RSACryptoServiceProvider(keySize);
			rsa.ImportParameters(rsaParams);
			return rsa;
		}

		#endregion

		#region Для работы с цифровой подписью

		public static byte[] SignValue(SafeProvHandleImpl hProv, int keyNumber, byte[] hashValue, GostAlgorithmType alg)
		{
            using (var hashHandle = SetupHashAlgorithm(hProv, hashValue, alg))
			{
				int signatureLength = 0;

				// Вычисление размера подписи
				if (!CryptoApi.CryptSignHash(hashHandle, (int)keyNumber, null, 0, null, ref signatureLength))
				{
					throw new Win32Exception(Marshal.GetLastWin32Error());
				}

				var signatureValue = new byte[signatureLength];

				// Вычисление значения подписи
				if (!CryptoApi.CryptSignHash(hashHandle, (int)keyNumber, null, 0, signatureValue, ref signatureLength))
				{
					throw new Win32Exception(Marshal.GetLastWin32Error());
				}

				return signatureValue;
			}
		}

		public static bool VerifySign(SafeProvHandleImpl providerHandle, SafeKeyHandleImpl keyHandle, byte[] hashValue, byte[] signatureValue, GostAlgorithmType alg)
		{
			using (var hashHandle = SetupHashAlgorithm(providerHandle, hashValue, alg))
			{
				return CryptoApi.CryptVerifySignature(hashHandle, signatureValue, (uint)signatureValue.Length, keyHandle, null, 0);
			}
		}

		private static SafeHashHandleImpl SetupHashAlgorithm(SafeProvHandleImpl providerHandle, byte[] hashValue, GostAlgorithmType alg)
		{
            SafeHashHandleImpl hashHandle;
            if (alg == GostAlgorithmType.Gost2012_256)
                hashHandle = CreateHash_3411_2012_256(providerHandle);
            else if (alg == GostAlgorithmType.Gost2012_512)
                hashHandle = CreateHash_3411_2012_512(providerHandle);
            else
                hashHandle = CreateHash_3411_94(providerHandle);

            //uint hashLength = 0;

            //if (!CryptoApi.CryptGetHashParam(hashHandle, Constants.HP_HASHVAL, null, ref hashLength, 0))
            //{
            //	throw CreateWin32Error();
            //}

            //if (hashValue.Length != hashLength)
            //{
            //	throw ExceptionUtility.CryptographicException(Constants.NTE_BAD_HASH);
            //}

            if (!CryptoApi.CryptSetHashParam(hashHandle, Constants.HP_HASHVAL, hashValue, 0))
			{
				throw CreateWin32Error();
			}

			return hashHandle;
		}

		#endregion

		public static T DangerousAddRef<T>(this T handle) where T : SafeHandle
		{
			var success = false;
			handle.DangerousAddRef(ref success);

			return handle;
		}

		public static void TryDispose(this SafeHandle handle)
		{
			if ((handle != null) && !handle.IsClosed)
			{
				handle.Dispose();
			}
		}

		private static CryptographicException CreateWin32Error()
		{
			return ExceptionUtility.CryptographicException(Marshal.GetLastWin32Error());
		}
	}
}