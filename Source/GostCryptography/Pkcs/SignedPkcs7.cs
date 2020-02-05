using System;
using System.Collections.Generic;
using GostCryptography.Cryptography;
using GostCryptography.Native;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using BCX509 = Org.BouncyCastle.X509;

namespace GostCryptography.Pkcs
{
	public class SignedPkcs7
	{
        /// <summary>
        /// Формирование сигнатуры для серверной подписи
        /// </summary>
        /// <param name="alg"></param>
        /// <param name="data"></param>
        /// <param name="detached"></param>
        /// <returns></returns>
        public static byte[] ComputeSignature(Gost3410 alg, byte[] data, bool detached = true)
        {
            var certBytes = alg.ContainerCertificateRaw;

            var _x509CertificateParser = new BCX509.X509CertificateParser();
            var bcCert = _x509CertificateParser.ReadCertificate(certBytes);

            ICollection<BCX509.X509Certificate> certPath = new List<BCX509.X509Certificate>();
            certPath.Add(bcCert);

            IDigest digest;
            string hashOid;
            string signOid;
            if (GostCryptoConfig.ProviderType == ProviderTypes.CryptoPro256)
            {
                digest = new GOST3411_2012_256Digest();
                signOid = Constants.OID_GR3410_12_256;
                hashOid = Constants.OID_GR3411_12_256;
            }
            else if (GostCryptoConfig.ProviderType == ProviderTypes.CryptoPro512)
            {
                digest = new GOST3411_2012_512Digest();
                signOid = Constants.OID_GR3410_12_512;
                hashOid = Constants.OID_GR3411_12_512;
            }
            else
            {
                digest = new Gost3411Digest();
                signOid = Constants.OID_GR3410_2001;
                hashOid = Constants.OID_GR3411_2001;
            }

            byte[] dataHash = ComputeDigest(digest, data);

            // Construct SignerInfo.signedAttrs
            Asn1EncodableVector signedAttributesVector = new Asn1EncodableVector();

            // Add PKCS#9 contentType signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    new DerObjectIdentifier(Constants.szOID_RSA_contentType),
                    new DerSet(new DerObjectIdentifier(Constants.szOID_RSA_data))));

            // Add PKCS#9 messageDigest signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    new DerObjectIdentifier(Constants.szOID_RSA_messageDigest),
                    new DerSet(new DerOctetString(dataHash))));

            // Add PKCS#9 signingTime signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    new DerObjectIdentifier(Constants.szOID_RSA_signingTime),
                    new DerSet(new Org.BouncyCastle.Asn1.Cms.Time(new DerUtcTime(DateTime.UtcNow)))));

            DerSet signedAttributes = new DerSet(signedAttributesVector);
            byte[] pkcs1Digest = ComputeDigest(digest, signedAttributes.GetDerEncoded());
            //byte[] pkcs1DigestInfo = CreateDigestInfo(pkcs1Digest, hashOid);

            var formatter = new GostSignatureFormatter(alg);
            var signature = formatter.CreateSignature(pkcs1Digest);

            // Construct SignerInfo
            SignerInfo signerInfo = new SignerInfo(
                new SignerIdentifier(new IssuerAndSerialNumber(bcCert.IssuerDN, bcCert.SerialNumber)),
                new AlgorithmIdentifier(new DerObjectIdentifier(hashOid), null),
                signedAttributes,
                new AlgorithmIdentifier(new DerObjectIdentifier(signOid), null),
                new DerOctetString(signature),
                null);

            // Construct SignedData.digestAlgorithms
            Asn1EncodableVector digestAlgorithmsVector = new Asn1EncodableVector();
            digestAlgorithmsVector.Add(new AlgorithmIdentifier(new DerObjectIdentifier(hashOid), null));

            // Construct SignedData.encapContentInfo
            ContentInfo encapContentInfo = new ContentInfo(
                new DerObjectIdentifier(Constants.szOID_RSA_data),
                (detached) ? null : new DerOctetString(data));

            // Construct SignedData.certificates
            Asn1EncodableVector certificatesVector = new Asn1EncodableVector();
            foreach (BCX509.X509Certificate cert in certPath)
                certificatesVector.Add(X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(cert.GetEncoded())));

            // Construct SignedData.signerInfos
            Asn1EncodableVector signerInfosVector = new Asn1EncodableVector();
            signerInfosVector.Add(signerInfo.ToAsn1Object());

            // Construct SignedData
            SignedData signedData = new SignedData(
                new DerSet(digestAlgorithmsVector),
                encapContentInfo,
                new BerSet(certificatesVector),
                null,
                new DerSet(signerInfosVector));

            // Construct top level ContentInfo
            ContentInfo contentInfo = new ContentInfo(
                new DerObjectIdentifier(Constants.szOID_RSA_signedData),
                signedData);

            return contentInfo.GetDerEncoded();
        }

        /// <summary>
        /// Формирование сигнатуры для серверной подписи
        /// </summary>
        /// <param name="data"></param>
        /// <param name="detached"></param>
        /// <returns></returns>
        public static byte[] ComputeSignature(byte[] data, bool detached = true)
		{
			using (var g = GostCryptoConfig.CreateGost3410AsymmetricAlgorithm())
			{
                return ComputeSignature(g, data, detached);
            }
		}

        /// <summary>
        ///  Формирование сигнатуры по хэшу для серверной подписи
        /// </summary>
        /// <param name="alg"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static byte[] ComputeSignatureDigest(Gost3410 alg, byte[] hash)
        {
            var certBytes = alg.ContainerCertificateRaw;

            var _x509CertificateParser = new BCX509.X509CertificateParser();
            var bcCert = _x509CertificateParser.ReadCertificate(certBytes);

            ICollection<BCX509.X509Certificate> certPath = new List<BCX509.X509Certificate>();
            certPath.Add(bcCert);

            IDigest digest;
            string hashOid;
            string signOid;
            if (GostCryptoConfig.ProviderType == ProviderTypes.CryptoPro256)
            {
                digest = new GOST3411_2012_256Digest();
                signOid = Constants.OID_GR3410_12_256;
                hashOid = Constants.OID_GR3411_12_256;
            }
            else if (GostCryptoConfig.ProviderType == ProviderTypes.CryptoPro512)
            {
                digest = new GOST3411_2012_512Digest();
                signOid = Constants.OID_GR3410_12_512;
                hashOid = Constants.OID_GR3411_12_512;
            }
            else
            {
                digest = new Gost3411Digest();
                signOid = Constants.OID_GR3410_2001;
                hashOid = Constants.OID_GR3411_2001;
            }

            // Construct SignerInfo.signedAttrs
            Asn1EncodableVector signedAttributesVector = new Asn1EncodableVector();

            // Add PKCS#9 contentType signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    new DerObjectIdentifier(Constants.szOID_RSA_contentType),
                    new DerSet(new DerObjectIdentifier(Constants.szOID_RSA_data))));

            // Add PKCS#9 messageDigest signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    new DerObjectIdentifier(Constants.szOID_RSA_messageDigest),
                    new DerSet(new DerOctetString(hash))));

            // Add PKCS#9 signingTime signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    new DerObjectIdentifier(Constants.szOID_RSA_signingTime),
                    new DerSet(new Org.BouncyCastle.Asn1.Cms.Time(new DerUtcTime(DateTime.UtcNow)))));

            DerSet signedAttributes = new DerSet(signedAttributesVector);
            byte[] pkcs1Digest = ComputeDigest(digest, signedAttributes.GetDerEncoded());
            //byte[] pkcs1DigestInfo = CreateDigestInfo(pkcs1Digest, hashOid);

            var formatter = new GostSignatureFormatter(alg);
            var signature = formatter.CreateSignature(pkcs1Digest);

            // Construct SignerInfo
            SignerInfo signerInfo = new SignerInfo(
                new SignerIdentifier(new IssuerAndSerialNumber(bcCert.IssuerDN, bcCert.SerialNumber)),
                new AlgorithmIdentifier(new DerObjectIdentifier(hashOid), null),
                signedAttributes,
                new AlgorithmIdentifier(new DerObjectIdentifier(signOid), null),
                new DerOctetString(signature),
                null);

            // Construct SignedData.digestAlgorithms
            Asn1EncodableVector digestAlgorithmsVector = new Asn1EncodableVector();
            digestAlgorithmsVector.Add(new AlgorithmIdentifier(new DerObjectIdentifier(hashOid), null));

            // Construct SignedData.encapContentInfo
            ContentInfo encapContentInfo = new ContentInfo(
                new DerObjectIdentifier(Constants.szOID_RSA_data), null);

            // Construct SignedData.certificates
            Asn1EncodableVector certificatesVector = new Asn1EncodableVector();
            foreach (BCX509.X509Certificate cert in certPath)
                certificatesVector.Add(X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(cert.GetEncoded())));

            // Construct SignedData.signerInfos
            Asn1EncodableVector signerInfosVector = new Asn1EncodableVector();
            signerInfosVector.Add(signerInfo.ToAsn1Object());

            // Construct SignedData
            SignedData signedData = new SignedData(
                new DerSet(digestAlgorithmsVector),
                encapContentInfo,
                new BerSet(certificatesVector),
                null,
                new DerSet(signerInfosVector));

            // Construct top level ContentInfo
            ContentInfo contentInfo = new ContentInfo(
                new DerObjectIdentifier(Constants.szOID_RSA_signedData),
                signedData);

            return contentInfo.GetDerEncoded();
        }

        /// <summary>
        /// Формирование сигнатуры по хэшу для серверной подписи
        /// </summary>
        /// <param name="hash"></param>
        /// <returns></returns>
		public static byte[] ComputeSignatureDigest(byte[] hash)
		{
			using (var g = GostCryptoConfig.CreateGost3410AsymmetricAlgorithm())
			{
                return ComputeSignatureDigest(g, hash);
            }
		}

        /// <summary>
        /// Вычисление хэша по заданным на сервере параметрам сертификата
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
		public static byte[] ComputeDigest(byte[] data)
		{
			IDigest digest;
            if (GostCryptoConfig.ProviderType == ProviderTypes.CryptoPro256)
                digest = new GOST3411_2012_256Digest();
            else if (GostCryptoConfig.ProviderType == ProviderTypes.CryptoPro512)
                digest = new GOST3411_2012_512Digest();
            else
                digest = new Gost3411Digest();

            return ComputeDigest(digest, data);
		}

        /// <summary>
        /// Вычисление хэша по сертификату
        /// </summary>
        /// <param name="data"></param>
        /// <param name="cert"></param>
        /// <returns></returns>
        public static byte[] ComputeDigest(byte[] data, byte[] cert)
        {
            var c = new X509Certificates.X509Certificate(cert);
            var oid = c.PublicKey.Oid.Value;

            IDigest digest;
            if (oid == Constants.OID_GR3410_12_256)
                digest = new GOST3411_2012_256Digest();
            else if (oid == Constants.OID_GR3410_12_512)
                digest = new GOST3411_2012_512Digest();
            else
                digest = new Gost3411Digest();

            return ComputeDigest(digest, data);
        }

        /// <summary>
        /// Computes hash of the data
        /// </summary>
        /// <param name="digest">Hash algorithm implementation</param>
        /// <param name="data">Data that should be processed</param>
        /// <returns>Hash of data</returns>
        private static byte[] ComputeDigest(IDigest digest, byte[] data)
		{
			if (digest == null)
				throw new ArgumentNullException("digest");

			if (data == null)
				throw new ArgumentNullException("data");

			byte[] hash = new byte[digest.GetDigestSize()];

			digest.Reset();
			digest.BlockUpdate(data, 0, data.Length);
			digest.DoFinal(hash, 0);

			return hash;
		}

        /// <summary>
        /// Creates PKCS#1 DigestInfo
        /// </summary>
        /// <param name="hash">Hash value</param>
        /// <param name="hashOid">Hash algorithm OID</param>
        /// <returns>DER encoded PKCS#1 DigestInfo</returns>
        /*private static byte[] CreateDigestInfo(byte[] hash, string hashOid)
		{
			DerObjectIdentifier derObjectIdentifier = new DerObjectIdentifier(hashOid);
			AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(derObjectIdentifier, null);
			DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, hash);
			return digestInfo.GetDerEncoded();
		}*/
    }
}