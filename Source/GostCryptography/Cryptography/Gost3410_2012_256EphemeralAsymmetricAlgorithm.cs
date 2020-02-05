﻿using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using GostCryptography.Asn1.Common;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализация алгоритма формирования общих ключей на основе алгоритма ГОСТ Р 34.10 и эфимерного ключа.
	/// </summary>
	public sealed class Gost3410_2012_256EphemeralAsymmetricAlgorithm : Gost3410
	{
        protected override string Gost3410SignatureAlgorithm { get { return "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256"; } }

        protected override string Gost3410KeyExchangeAlgorithm { get { return "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-256"; } }

        /// <summary>
        /// Конструктор.
        /// </summary>
        [SecuritySafeCritical]
		public Gost3410_2012_256EphemeralAsymmetricAlgorithm()
		{
			_provHandle = CryptoApiHelper.ProviderHandle.DangerousAddRef();
			_keyHandle = CryptoApiHelper.GenerateKey(_provHandle, Constants.CALG_DH_GR3410_12_256_EPHEM, CspProviderFlags.NoFlags);
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="keyParameters">Параметры ключа, используемого для создания общего секретного ключа.</param>
		/// <exception cref="ArgumentNullException"></exception>
		/// <remarks>
		/// В параметре <paramref name="keyParameters"/> достаточно передать идентификатор OID параметров хэширования <see cref="GostKeyExchangeParameters.DigestParamSet"/>
		/// и идентификатор OID параметров открытого ключа <see cref="GostKeyExchangeParameters.PublicKeyParamSet"/>. Остальные параметры не используются.
		/// </remarks>
		[SecuritySafeCritical]
		public Gost3410_2012_256EphemeralAsymmetricAlgorithm(GostKeyExchangeParameters keyParameters)
		{
			if (keyParameters == null)
			{
				throw ExceptionUtility.ArgumentNull("keyParameters");
			}

			_provHandle = CryptoApiHelper.ProviderHandle.DangerousAddRef();
			_keyHandle = CryptoApiHelper.GenerateDhEphemeralKey(_provHandle, Constants.CALG_DH_GR3410_12_256_EPHEM, keyParameters.DigestParamSet, keyParameters.PublicKeyParamSet);
		}

		[SecurityCritical]
		private readonly SafeKeyHandleImpl _keyHandle;

		[SecurityCritical]
		private readonly SafeProvHandleImpl _provHandle;

		/// <summary>
		/// Приватный дескриптор провайдера.
		/// </summary>
		internal SafeProvHandleImpl InternalProvHandle
		{
			[SecurityCritical]
			get { return _provHandle; }
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
		/// Приватный дескриптор ключа.
		/// </summary>
		internal SafeKeyHandleImpl InternalKeyHandle
		{
			[SecurityCritical]
			get { return _keyHandle; }
		}

		/// <summary>
		/// Дескриптор ключа.
		/// </summary>
		public IntPtr KeyHandle
		{
			[SecurityCritical]
			[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
			get { return InternalKeyHandle.DangerousGetHandle(); }
		}

		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		/// <exception cref="NotSupportedException"></exception>
		public override byte[] CreateSignature(byte[] hash)
		{
			throw ExceptionUtility.NotSupported(Resources.EphemKeyOperationNotSupported);
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		/// <exception cref="NotSupportedException"></exception>
		public override bool VerifySignature(byte[] hash, byte[] signature)
		{
			throw ExceptionUtility.NotSupported(Resources.EphemKeyOperationNotSupported);
		}

		/// <summary>
		/// Создает общий секретный ключ.
		/// </summary>
		/// <param name="keyParameters">Параметры открытого ключа, используемого для создания общего секретного ключа.</param>
		[SecuritySafeCritical]
		public override GostSharedSecret CreateKeyExchange(GostKeyExchangeParameters keyParameters)
		{
			return new GostSharedSecretAlgorithm(_provHandle, _keyHandle, new GostKeyExchangeParameters(keyParameters), GostAlgorithmType.Gost2012_256);
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
				throw ExceptionUtility.NotSupported(Resources.EphemKeyOperationNotSupported);
			}

			return CryptoApiHelper.ExportPublicKey(_keyHandle, GostAlgorithmType.Gost2012_256);
		}

		/// <summary>
		/// Импортирует (дешифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="keyParameters">Параметры ключа, используемого для создания общего секретного ключа.</param>
		/// <exception cref="NotSupportedException"></exception>
		public override void ImportParameters(GostKeyExchangeParameters keyParameters)
		{
			throw ExceptionUtility.NotSupported(Resources.EphemKeyOperationNotSupported);
		}

		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			_keyHandle.TryDispose();
			_provHandle.TryDispose();

			base.Dispose(disposing);
		}
	}
}