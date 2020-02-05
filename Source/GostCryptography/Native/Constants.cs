namespace GostCryptography.Native
{
	/// <summary>
	/// Константы для работы с криптографическим провайдером.
	/// </summary>
	public static class Constants
	{
		#region Common cryptographic constants
		public const uint LMEM_FIXED = 0x0000;
		public const uint LMEM_ZEROINIT = 0x0040;
		public const uint LPTR = (LMEM_FIXED | LMEM_ZEROINIT);

		public const int S_OK = 0;
		public const int S_FALSE = 1;

		public const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
		public const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;

		public const uint VER_PLATFORM_WIN32s = 0;
		public const uint VER_PLATFORM_WIN32_WINDOWS = 1;
		public const uint VER_PLATFORM_WIN32_NT = 2;
		public const uint VER_PLATFORM_WINCE = 3;

		// ASN.
		public const uint ASN_TAG_NULL = 0x05;
		public const uint ASN_TAG_OBJID = 0x06;

		// cert query object types.
		public const uint CERT_QUERY_OBJECT_FILE = 1;
		public const uint CERT_QUERY_OBJECT_BLOB = 2;

		// cert query content types.
		public const uint CERT_QUERY_CONTENT_CERT = 1;
		public const uint CERT_QUERY_CONTENT_CTL = 2;
		public const uint CERT_QUERY_CONTENT_CRL = 3;
		public const uint CERT_QUERY_CONTENT_SERIALIZED_STORE = 4;
		public const uint CERT_QUERY_CONTENT_SERIALIZED_CERT = 5;
		public const uint CERT_QUERY_CONTENT_SERIALIZED_CTL = 6;
		public const uint CERT_QUERY_CONTENT_SERIALIZED_CRL = 7;
		public const uint CERT_QUERY_CONTENT_PKCS7_SIGNED = 8;
		public const uint CERT_QUERY_CONTENT_PKCS7_UNSIGNED = 9;
		public const uint CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10;
		public const uint CERT_QUERY_CONTENT_PKCS10 = 11;
		public const uint CERT_QUERY_CONTENT_PFX = 12;
		public const uint CERT_QUERY_CONTENT_CERT_PAIR = 13;

		// cert query content flags.
		public const uint CERT_QUERY_CONTENT_FLAG_CERT = (1 << (int)CERT_QUERY_CONTENT_CERT);
		public const uint CERT_QUERY_CONTENT_FLAG_CTL = (1 << (int)CERT_QUERY_CONTENT_CTL);
		public const uint CERT_QUERY_CONTENT_FLAG_CRL = (1 << (int)CERT_QUERY_CONTENT_CRL);
		public const uint CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE = (1 << (int)CERT_QUERY_CONTENT_SERIALIZED_STORE);
		public const uint CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT = (1 << (int)CERT_QUERY_CONTENT_SERIALIZED_CERT);
		public const uint CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL = (1 << (int)CERT_QUERY_CONTENT_SERIALIZED_CTL);
		public const uint CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL = (1 << (int)CERT_QUERY_CONTENT_SERIALIZED_CRL);
		public const uint CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = (1 << (int)CERT_QUERY_CONTENT_PKCS7_SIGNED);
		public const uint CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED = (1 << (int)CERT_QUERY_CONTENT_PKCS7_UNSIGNED);
		public const uint CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = (1 << (int)CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED);
		public const uint CERT_QUERY_CONTENT_FLAG_PKCS10 = (1 << (int)CERT_QUERY_CONTENT_PKCS10);
		public const uint CERT_QUERY_CONTENT_FLAG_PFX = (1 << (int)CERT_QUERY_CONTENT_PFX);
		public const uint CERT_QUERY_CONTENT_FLAG_CERT_PAIR = (1 << (int)CERT_QUERY_CONTENT_CERT_PAIR);
		public const uint CERT_QUERY_CONTENT_FLAG_ALL =
									   (CERT_QUERY_CONTENT_FLAG_CERT |
										CERT_QUERY_CONTENT_FLAG_CTL |
										CERT_QUERY_CONTENT_FLAG_CRL |
										CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE |
										CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT |
										CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL |
										CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL |
										CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
										CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED |
										CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED |
										CERT_QUERY_CONTENT_FLAG_PKCS10 |
										CERT_QUERY_CONTENT_FLAG_PFX |
										CERT_QUERY_CONTENT_FLAG_CERT_PAIR);

		public const uint CERT_QUERY_FORMAT_BINARY = 1;
		public const uint CERT_QUERY_FORMAT_BASE64_ENCODED = 2;
		public const uint CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED = 3;

		public const uint CERT_QUERY_FORMAT_FLAG_BINARY = (1 << (int)CERT_QUERY_FORMAT_BINARY);
		public const uint CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED = (1 << (int)CERT_QUERY_FORMAT_BASE64_ENCODED);
		public const uint CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED = (1 << (int)CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED);
		public const uint CERT_QUERY_FORMAT_FLAG_ALL =
									   (CERT_QUERY_FORMAT_FLAG_BINARY |
										CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED |
										CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED);

		// OID key type.
		public const uint CRYPT_OID_INFO_OID_KEY = 1;
		public const uint CRYPT_OID_INFO_NAME_KEY = 2;
		public const uint CRYPT_OID_INFO_ALGID_KEY = 3;
		public const uint CRYPT_OID_INFO_SIGN_KEY = 4;

		// OID group Id's.
		public const uint CRYPT_HASH_ALG_OID_GROUP_ID = 1;
		public const uint CRYPT_ENCRYPT_ALG_OID_GROUP_ID = 2;
		public const uint CRYPT_PUBKEY_ALG_OID_GROUP_ID = 3;
		public const uint CRYPT_SIGN_ALG_OID_GROUP_ID = 4;
		public const uint CRYPT_RDN_ATTR_OID_GROUP_ID = 5;
		public const uint CRYPT_EXT_OR_ATTR_OID_GROUP_ID = 6;
		public const uint CRYPT_ENHKEY_USAGE_OID_GROUP_ID = 7;
		public const uint CRYPT_POLICY_OID_GROUP_ID = 8;
		public const uint CRYPT_TEMPLATE_OID_GROUP_ID = 9;
		public const uint CRYPT_LAST_OID_GROUP_ID = 9;

		public const uint CRYPT_FIRST_ALG_OID_GROUP_ID = CRYPT_HASH_ALG_OID_GROUP_ID;
		public const uint CRYPT_LAST_ALG_OID_GROUP_ID = CRYPT_SIGN_ALG_OID_GROUP_ID;

		// cert encoding flags.
		public const uint CRYPT_ASN_ENCODING = 0x00000001;
		public const uint CRYPT_NDR_ENCODING = 0x00000002;
		public const uint X509_ASN_ENCODING = 0x00000001;
		public const uint X509_NDR_ENCODING = 0x00000002;
		public const uint PKCS_7_ASN_ENCODING = 0x00010000;
		public const uint PKCS_7_NDR_ENCODING = 0x00020000;
		public const uint PKCS_7_OR_X509_ASN_ENCODING = (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING);

		// cert store provider
		public const uint CERT_STORE_PROV_MSG = 1;
		public const uint CERT_STORE_PROV_MEMORY = 2;
		public const uint CERT_STORE_PROV_FILE = 3;
		public const uint CERT_STORE_PROV_REG = 4;
		public const uint CERT_STORE_PROV_PKCS7 = 5;
		public const uint CERT_STORE_PROV_SERIALIZED = 6;
		public const uint CERT_STORE_PROV_FILENAME_A = 7;
		public const uint CERT_STORE_PROV_FILENAME_W = 8;
		public const uint CERT_STORE_PROV_FILENAME = CERT_STORE_PROV_FILENAME_W;
		public const uint CERT_STORE_PROV_SYSTEM_A = 9;
		public const uint CERT_STORE_PROV_SYSTEM_W = 10;
		public const uint CERT_STORE_PROV_SYSTEM = CERT_STORE_PROV_SYSTEM_W;
		public const uint CERT_STORE_PROV_COLLECTION = 11;
		public const uint CERT_STORE_PROV_SYSTEM_REGISTRY_A = 12;
		public const uint CERT_STORE_PROV_SYSTEM_REGISTRY_W = 13;
		public const uint CERT_STORE_PROV_SYSTEM_REGISTRY = CERT_STORE_PROV_SYSTEM_REGISTRY_W;
		public const uint CERT_STORE_PROV_PHYSICAL_W = 14;
		public const uint CERT_STORE_PROV_PHYSICAL = CERT_STORE_PROV_PHYSICAL_W;
		public const uint CERT_STORE_PROV_SMART_CARD_W = 15;
		public const uint CERT_STORE_PROV_SMART_CARD = CERT_STORE_PROV_SMART_CARD_W;
		public const uint CERT_STORE_PROV_LDAP_W = 16;
		public const uint CERT_STORE_PROV_LDAP = CERT_STORE_PROV_LDAP_W;

		// cert store flags
		public const uint CERT_STORE_NO_CRYPT_RELEASE_FLAG = 0x00000001;
		public const uint CERT_STORE_SET_LOCALIZED_NAME_FLAG = 0x00000002;
		public const uint CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG = 0x00000004;
		public const uint CERT_STORE_DELETE_FLAG = 0x00000010;
		public const uint CERT_STORE_SHARE_STORE_FLAG = 0x00000040;
		public const uint CERT_STORE_SHARE_CONTEXT_FLAG = 0x00000080;
		public const uint CERT_STORE_MANIFOLD_FLAG = 0x00000100;
		public const uint CERT_STORE_ENUM_ARCHIVED_FLAG = 0x00000200;
		public const uint CERT_STORE_UPDATE_KEYID_FLAG = 0x00000400;
		public const uint CERT_STORE_BACKUP_RESTORE_FLAG = 0x00000800;
		public const uint CERT_STORE_READONLY_FLAG = 0x00008000;
		public const uint CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;
		public const uint CERT_STORE_CREATE_NEW_FLAG = 0x00002000;
		public const uint CERT_STORE_MAXIMUM_ALLOWED_FLAG = 0x00001000;

		// cert store location
		public const uint CERT_SYSTEM_STORE_UNPROTECTED_FLAG = 0x40000000;
		public const uint CERT_SYSTEM_STORE_LOCATION_MASK = 0x00FF0000;
		public const uint CERT_SYSTEM_STORE_LOCATION_SHIFT = 16;

		public const uint CERT_SYSTEM_STORE_CURRENT_USER_ID = 1;
		public const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_ID = 2;
		public const uint CERT_SYSTEM_STORE_CURRENT_SERVICE_ID = 4;
		public const uint CERT_SYSTEM_STORE_SERVICES_ID = 5;
		public const uint CERT_SYSTEM_STORE_USERS_ID = 6;
		public const uint CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID = 7;
		public const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID = 8;
		public const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID = 9;

		public const uint CERT_SYSTEM_STORE_CURRENT_USER = ((int)CERT_SYSTEM_STORE_CURRENT_USER_ID << (int)CERT_SYSTEM_STORE_LOCATION_SHIFT);
		public const uint CERT_SYSTEM_STORE_LOCAL_MACHINE = ((int)CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << (int)CERT_SYSTEM_STORE_LOCATION_SHIFT);
		public const uint CERT_SYSTEM_STORE_CURRENT_SERVICE = ((int)CERT_SYSTEM_STORE_CURRENT_SERVICE_ID << (int)CERT_SYSTEM_STORE_LOCATION_SHIFT);
		public const uint CERT_SYSTEM_STORE_SERVICES = ((int)CERT_SYSTEM_STORE_SERVICES_ID << (int)CERT_SYSTEM_STORE_LOCATION_SHIFT);
		public const uint CERT_SYSTEM_STORE_USERS = ((int)CERT_SYSTEM_STORE_USERS_ID << (int)CERT_SYSTEM_STORE_LOCATION_SHIFT);
		public const uint CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY = ((int)CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID << (int)CERT_SYSTEM_STORE_LOCATION_SHIFT);
		public const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY = ((int)CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID << (int)CERT_SYSTEM_STORE_LOCATION_SHIFT);
		public const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE = ((int)CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID << (int)CERT_SYSTEM_STORE_LOCATION_SHIFT);

		// cert name types.
		public const uint CERT_NAME_EMAIL_TYPE = 1;
		public const uint CERT_NAME_RDN_TYPE = 2;
		public const uint CERT_NAME_ATTR_TYPE = 3;
		public const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;
		public const uint CERT_NAME_FRIENDLY_DISPLAY_TYPE = 5;
		public const uint CERT_NAME_DNS_TYPE = 6;
		public const uint CERT_NAME_URL_TYPE = 7;
		public const uint CERT_NAME_UPN_TYPE = 8;

		// cert name flags.
		public const uint CERT_SIMPLE_NAME_STR = 1;
		public const uint CERT_OID_NAME_STR = 2;
		public const uint CERT_X500_NAME_STR = 3;

		public const uint CERT_NAME_STR_SEMICOLON_FLAG = 0x40000000;
		public const uint CERT_NAME_STR_NO_PLUS_FLAG = 0x20000000;
		public const uint CERT_NAME_STR_NO_QUOTING_FLAG = 0x10000000;
		public const uint CERT_NAME_STR_CRLF_FLAG = 0x08000000;
		public const uint CERT_NAME_STR_COMMA_FLAG = 0x04000000;
		public const uint CERT_NAME_STR_REVERSE_FLAG = 0x02000000;

		public const uint CERT_NAME_ISSUER_FLAG = 0x1;
		public const uint CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG = 0x00010000;
		public const uint CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG = 0x00020000;
		public const uint CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG = 0x00040000;
		public const uint CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG = 0x00080000;

		// cert context property Id's.
		public const uint CERT_KEY_PROV_HANDLE_PROP_ID = 1;
		public const uint CERT_KEY_PROV_INFO_PROP_ID = 2;
		public const uint CERT_SHA1_HASH_PROP_ID = 3;
		public const uint CERT_MD5_HASH_PROP_ID = 4;
		public const uint CERT_HASH_PROP_ID = CERT_SHA1_HASH_PROP_ID;
		public const uint CERT_KEY_CONTEXT_PROP_ID = 5;
		public const uint CERT_KEY_SPEC_PROP_ID = 6;
		public const uint CERT_IE30_RESERVED_PROP_ID = 7;
		public const uint CERT_PUBKEY_HASH_RESERVED_PROP_ID = 8;
		public const uint CERT_ENHKEY_USAGE_PROP_ID = 9;
		public const uint CERT_CTL_USAGE_PROP_ID = CERT_ENHKEY_USAGE_PROP_ID;
		public const uint CERT_NEXT_UPDATE_LOCATION_PROP_ID = 10;
		public const uint CERT_FRIENDLY_NAME_PROP_ID = 11;
		public const uint CERT_PVK_FILE_PROP_ID = 12;
		public const uint CERT_DESCRIPTION_PROP_ID = 13;
		public const uint CERT_ACCESS_STATE_PROP_ID = 14;
		public const uint CERT_SIGNATURE_HASH_PROP_ID = 15;
		public const uint CERT_SMART_CARD_DATA_PROP_ID = 16;
		public const uint CERT_EFS_PROP_ID = 17;
		public const uint CERT_FORTEZZA_DATA_PROP_ID = 18;
		public const uint CERT_ARCHIVED_PROP_ID = 19;
		public const uint CERT_KEY_IDENTIFIER_PROP_ID = 20;
		public const uint CERT_AUTO_ENROLL_PROP_ID = 21;
		public const uint CERT_PUBKEY_ALG_PARA_PROP_ID = 22;
		public const uint CERT_CROSS_CERT_DIST_POINTS_PROP_ID = 23;
		public const uint CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID = 24;
		public const uint CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID = 25;
		public const uint CERT_ENROLLMENT_PROP_ID = 26;
		public const uint CERT_DATE_STAMP_PROP_ID = 27;
		public const uint CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID = 28;
		public const uint CERT_SUBJECT_NAME_MD5_HASH_PROP_ID = 29;
		public const uint CERT_EXTENDED_ERROR_INFO_PROP_ID = 30;
		public const uint CERT_RENEWAL_PROP_ID = 64;
		public const uint CERT_ARCHIVED_KEY_HASH_PROP_ID = 65;
		public const uint CERT_FIRST_RESERVED_PROP_ID = 66;

		// This value shall be defined in wincrypt.h so we avoid conflicts
		public const uint CERT_DELETE_KEYSET_PROP_ID = 101;

		// CertSetCertificateContextProperty flags.
		public const uint CERT_SET_PROPERTY_IGNORE_PERSIST_ERROR_FLAG = 0x80000000;
		public const uint CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG = 0x40000000;

		// cert info flags.
		public const uint CERT_INFO_VERSION_FLAG = 1;
		public const uint CERT_INFO_SERIAL_NUMBER_FLAG = 2;
		public const uint CERT_INFO_SIGNATURE_ALGORITHM_FLAG = 3;
		public const uint CERT_INFO_ISSUER_FLAG = 4;
		public const uint CERT_INFO_NOT_BEFORE_FLAG = 5;
		public const uint CERT_INFO_NOT_AFTER_FLAG = 6;
		public const uint CERT_INFO_SUBJECT_FLAG = 7;
		public const uint CERT_INFO_SUBJECT_PUBLIC_KEY_INFO_FLAG = 8;
		public const uint CERT_INFO_ISSUER_UNIQUE_ID_FLAG = 9;
		public const uint CERT_INFO_SUBJECT_UNIQUE_ID_FLAG = 10;
		public const uint CERT_INFO_EXTENSION_FLAG = 11;

		// cert compare flags.
		public const uint CERT_COMPARE_MASK = 0xFFFF;
		public const uint CERT_COMPARE_SHIFT = 16;
		public const uint CERT_COMPARE_ANY = 0;
		public const uint CERT_COMPARE_SHA1_HASH = 1;
		public const uint CERT_COMPARE_NAME = 2;
		public const uint CERT_COMPARE_ATTR = 3;
		public const uint CERT_COMPARE_MD5_HASH = 4;
		public const uint CERT_COMPARE_PROPERTY = 5;
		public const uint CERT_COMPARE_PUBLIC_KEY = 6;
		public const uint CERT_COMPARE_HASH = CERT_COMPARE_SHA1_HASH;
		public const uint CERT_COMPARE_NAME_STR_A = 7;
		public const uint CERT_COMPARE_NAME_STR_W = 8;
		public const uint CERT_COMPARE_KEY_SPEC = 9;
		public const uint CERT_COMPARE_ENHKEY_USAGE = 10;
		public const uint CERT_COMPARE_CTL_USAGE = CERT_COMPARE_ENHKEY_USAGE;
		public const uint CERT_COMPARE_SUBJECT_CERT = 11;
		public const uint CERT_COMPARE_ISSUER_OF = 12;
		public const uint CERT_COMPARE_EXISTING = 13;
		public const uint CERT_COMPARE_SIGNATURE_HASH = 14;
		public const uint CERT_COMPARE_KEY_IDENTIFIER = 15;
		public const uint CERT_COMPARE_CERT_ID = 16;
		public const uint CERT_COMPARE_CROSS_CERT_DIST_POINTS = 17;
		public const uint CERT_COMPARE_PUBKEY_MD5_HASH = 18;

		// cert find flags.
		public const uint CERT_FIND_ANY = ((int)CERT_COMPARE_ANY << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_SHA1_HASH = ((int)CERT_COMPARE_SHA1_HASH << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_MD5_HASH = ((int)CERT_COMPARE_MD5_HASH << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_SIGNATURE_HASH = ((int)CERT_COMPARE_SIGNATURE_HASH << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_KEY_IDENTIFIER = ((int)CERT_COMPARE_KEY_IDENTIFIER << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_HASH = CERT_FIND_SHA1_HASH;
		public const uint CERT_FIND_PROPERTY = ((int)CERT_COMPARE_PROPERTY << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_PUBLIC_KEY = ((int)CERT_COMPARE_PUBLIC_KEY << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_SUBJECT_NAME = ((int)CERT_COMPARE_NAME << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_SUBJECT_FLAG);
		public const uint CERT_FIND_SUBJECT_ATTR = ((int)CERT_COMPARE_ATTR << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_SUBJECT_FLAG);
		public const uint CERT_FIND_ISSUER_NAME = ((int)CERT_COMPARE_NAME << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_ISSUER_FLAG);
		public const uint CERT_FIND_ISSUER_ATTR = ((int)CERT_COMPARE_ATTR << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_ISSUER_FLAG);
		public const uint CERT_FIND_SUBJECT_STR_A = ((int)CERT_COMPARE_NAME_STR_A << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_SUBJECT_FLAG);
		public const uint CERT_FIND_SUBJECT_STR_W = ((int)CERT_COMPARE_NAME_STR_W << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_SUBJECT_FLAG);
		public const uint CERT_FIND_SUBJECT_STR = CERT_FIND_SUBJECT_STR_W;
		public const uint CERT_FIND_ISSUER_STR_A = ((int)CERT_COMPARE_NAME_STR_A << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_ISSUER_FLAG);
		public const uint CERT_FIND_ISSUER_STR_W = ((int)CERT_COMPARE_NAME_STR_W << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_ISSUER_FLAG);
		public const uint CERT_FIND_ISSUER_STR = CERT_FIND_ISSUER_STR_W;
		public const uint CERT_FIND_KEY_SPEC = ((int)CERT_COMPARE_KEY_SPEC << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_ENHKEY_USAGE = ((int)CERT_COMPARE_ENHKEY_USAGE << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_CTL_USAGE = CERT_FIND_ENHKEY_USAGE;
		public const uint CERT_FIND_SUBJECT_CERT = ((int)CERT_COMPARE_SUBJECT_CERT << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_ISSUER_OF = ((int)CERT_COMPARE_ISSUER_OF << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_EXISTING = ((int)CERT_COMPARE_EXISTING << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_CERT_ID = ((int)CERT_COMPARE_CERT_ID << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_CROSS_CERT_DIST_POINTS = ((int)CERT_COMPARE_CROSS_CERT_DIST_POINTS << (int)CERT_COMPARE_SHIFT);
		public const uint CERT_FIND_PUBKEY_MD5_HASH = ((int)CERT_COMPARE_PUBKEY_MD5_HASH << (int)CERT_COMPARE_SHIFT);

		// cert key usage flags.
		public const uint CERT_ENCIPHER_ONLY_KEY_USAGE = 0x0001;
		public const uint CERT_CRL_SIGN_KEY_USAGE = 0x0002;
		public const uint CERT_KEY_CERT_SIGN_KEY_USAGE = 0x0004;
		public const uint CERT_KEY_AGREEMENT_KEY_USAGE = 0x0008;
		public const uint CERT_DATA_ENCIPHERMENT_KEY_USAGE = 0x0010;
		public const uint CERT_KEY_ENCIPHERMENT_KEY_USAGE = 0x0020;
		public const uint CERT_NON_REPUDIATION_KEY_USAGE = 0x0040;
		public const uint CERT_DIGITAL_SIGNATURE_KEY_USAGE = 0x0080;
		public const uint CERT_DECIPHER_ONLY_KEY_USAGE = 0x8000;

		// Add certificate/CRL, encoded, context or element disposition values.
		public const uint CERT_STORE_ADD_NEW = 1;
		public const uint CERT_STORE_ADD_USE_EXISTING = 2;
		public const uint CERT_STORE_ADD_REPLACE_EXISTING = 3;
		public const uint CERT_STORE_ADD_ALWAYS = 4;
		public const uint CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5;
		public const uint CERT_STORE_ADD_NEWER = 6;
		public const uint CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES = 7;

		// constants for dwFormatStrType of function CryptFormatObject
		public const uint CRYPT_FORMAT_STR_MULTI_LINE = 0x0001;
		public const uint CRYPT_FORMAT_STR_NO_HEX = 0x0010;

		// store save as type.
		public const uint CERT_STORE_SAVE_AS_STORE = 1;
		public const uint CERT_STORE_SAVE_AS_PKCS7 = 2;

		// store save to type.
		public const uint CERT_STORE_SAVE_TO_FILE = 1;
		public const uint CERT_STORE_SAVE_TO_MEMORY = 2;
		public const uint CERT_STORE_SAVE_TO_FILENAME_A = 3;
		public const uint CERT_STORE_SAVE_TO_FILENAME_W = 4;
		public const uint CERT_STORE_SAVE_TO_FILENAME = CERT_STORE_SAVE_TO_FILENAME_W;

		// flags for CERT_BASIC_CONSTRAINTS_INFO.SubjectType
		public const uint CERT_CA_SUBJECT_FLAG = 0x80;
		public const uint CERT_END_ENTITY_SUBJECT_FLAG = 0x40;

		// dwFlags definitions for PFXExportCertStoreEx.
		public const uint REPORT_NO_PRIVATE_KEY = 0x0001;
		public const uint REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY = 0x0002;
		public const uint EXPORT_PRIVATE_KEYS = 0x0004;
		public const uint PKCS12_EXPORT_RESERVED_MASK = 0xffff0000;

		// Predefined primitive data structures that can be encoded / decoded.
		public const uint RSA_CSP_PUBLICKEYBLOB = 19;
		public const uint X509_MULTI_BYTE_UINT = 38;
		public const uint X509_DSS_PUBLICKEY = X509_MULTI_BYTE_UINT;
		public const uint X509_DSS_PARAMETERS = 39;
		public const uint X509_DSS_SIGNATURE = 40;

		// Object Identifiers short hand.
		public const uint X509_EXTENSIONS = 5;
		public const uint X509_NAME_VALUE = 6;
		public const uint X509_NAME = 7;
		public const uint X509_AUTHORITY_KEY_ID = 9;
		public const uint X509_KEY_USAGE_RESTRICTION = 11;
		public const uint X509_BASIC_CONSTRAINTS = 13;
		public const uint X509_KEY_USAGE = 14;
		public const uint X509_BASIC_CONSTRAINTS2 = 15;
		public const uint X509_CERT_POLICIES = 16;
		public const uint PKCS_UTC_TIME = 17;
		public const uint PKCS_ATTRIBUTE = 22;
		public const uint X509_UNICODE_NAME_VALUE = 24;
		public const uint X509_OCTET_STRING = 25;
		public const uint X509_BITS = 26;
		public const uint X509_ANY_STRING = X509_NAME_VALUE;
		public const uint X509_UNICODE_ANY_STRING = X509_UNICODE_NAME_VALUE;
		public const uint X509_ENHANCED_KEY_USAGE = 36;
		public const uint PKCS_RC2_CBC_PARAMETERS = 41;
		public const uint X509_CERTIFICATE_TEMPLATE = 64;
		public const uint PKCS7_SIGNER_INFO = 500;
		public const uint CMS_SIGNER_INFO = 501;

		public const string szOID_COMMON_NAME = "2.5.4.3";
		public const string szOID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.1";
		public const string szOID_KEY_USAGE_RESTRICTION = "2.5.29.4";
		public const string szOID_SUBJECT_ALT_NAME = "2.5.29.7";
		public const string szOID_ISSUER_ALT_NAME = "2.5.29.8";
		public const string szOID_BASIC_CONSTRAINTS = "2.5.29.10";
		public const string szOID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
		public const string szOID_KEY_USAGE = "2.5.29.15";
		public const string szOID_SUBJECT_ALT_NAME2 = "2.5.29.17";
		public const string szOID_ISSUER_ALT_NAME2 = "2.5.29.18";
		public const string szOID_BASIC_CONSTRAINTS2 = "2.5.29.19";
		public const string szOID_CRL_DIST_POINTS = "2.5.29.31";
		public const string szOID_CERT_POLICIES = "2.5.29.32";
		public const string szOID_ENHANCED_KEY_USAGE = "2.5.29.37";
		public const string szOID_KEYID_RDN = "1.3.6.1.4.1.311.10.7.1";
		public const string szOID_ENROLL_CERTTYPE_EXTENSION = "1.3.6.1.4.1.311.20.2";
		public const string szOID_NT_PRINCIPAL_NAME = "1.3.6.1.4.1.311.20.2.3";
		public const string szOID_CERTIFICATE_TEMPLATE = "1.3.6.1.4.1.311.21.7";
		public const string szOID_RDN_DUMMY_SIGNER = "1.3.6.1.4.1.311.21.9";
		public const string szOID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";

		// Predefined verify chain policies
		public const uint CERT_CHAIN_POLICY_BASE = 1;
		public const uint CERT_CHAIN_POLICY_AUTHENTICODE = 2;
		public const uint CERT_CHAIN_POLICY_AUTHENTICODE_TS = 3;
		public const uint CERT_CHAIN_POLICY_SSL = 4;
		public const uint CERT_CHAIN_POLICY_BASIC_CONSTRAINTS = 5;
		public const uint CERT_CHAIN_POLICY_NT_AUTH = 6;
		public const uint CERT_CHAIN_POLICY_MICROSOFT_ROOT = 7;

		// Default usage match type is AND with value zero
		public const uint USAGE_MATCH_TYPE_AND = 0x00000000;
		public const uint USAGE_MATCH_TYPE_OR = 0x00000001;

		// Common chain policy flags.
		public const uint CERT_CHAIN_REVOCATION_CHECK_END_CERT = 0x10000000;
		public const uint CERT_CHAIN_REVOCATION_CHECK_CHAIN = 0x20000000;
		public const uint CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x40000000;
		public const uint CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY = 0x80000000;
		public const uint CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT = 0x08000000;

		// These can be applied to certificates and chains
		public const uint CERT_TRUST_NO_ERROR = 0x00000000;
		public const uint CERT_TRUST_IS_NOT_TIME_VALID = 0x00000001;
		public const uint CERT_TRUST_IS_NOT_TIME_NESTED = 0x00000002;
		public const uint CERT_TRUST_IS_REVOKED = 0x00000004;
		public const uint CERT_TRUST_IS_NOT_SIGNATURE_VALID = 0x00000008;
		public const uint CERT_TRUST_IS_NOT_VALID_FOR_USAGE = 0x00000010;
		public const uint CERT_TRUST_IS_UNTRUSTED_ROOT = 0x00000020;
		public const uint CERT_TRUST_REVOCATION_STATUS_UNKNOWN = 0x00000040;
		public const uint CERT_TRUST_IS_CYCLIC = 0x00000080;

		public const uint CERT_TRUST_INVALID_EXTENSION = 0x00000100;
		public const uint CERT_TRUST_INVALID_POLICY_CONSTRAINTS = 0x00000200;
		public const uint CERT_TRUST_INVALID_BASIC_CONSTRAINTS = 0x00000400;
		public const uint CERT_TRUST_INVALID_NAME_CONSTRAINTS = 0x00000800;
		public const uint CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT = 0x00001000;
		public const uint CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT = 0x00002000;
		public const uint CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT = 0x00004000;
		public const uint CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT = 0x00008000;

		public const uint CERT_TRUST_IS_OFFLINE_REVOCATION = 0x01000000;
		public const uint CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY = 0x02000000;

		// These can be applied to chains only
		public const uint CERT_TRUST_IS_PARTIAL_CHAIN = 0x00010000;
		public const uint CERT_TRUST_CTL_IS_NOT_TIME_VALID = 0x00020000;
		public const uint CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID = 0x00040000;
		public const uint CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE = 0x00080000;

		// Common chain policy flags
		public const uint CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG = 0x00000001;
		public const uint CERT_CHAIN_POLICY_IGNORE_CTL_NOT_TIME_VALID_FLAG = 0x00000002;
		public const uint CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG = 0x00000004;
		public const uint CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG = 0x00000008;

		public const uint CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG = 0x00000010;
		public const uint CERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG = 0x00000020;
		public const uint CERT_CHAIN_POLICY_IGNORE_INVALID_NAME_FLAG = 0x00000040;
		public const uint CERT_CHAIN_POLICY_IGNORE_INVALID_POLICY_FLAG = 0x00000080;

		public const uint CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG = 0x00000100;
		public const uint CERT_CHAIN_POLICY_IGNORE_CTL_SIGNER_REV_UNKNOWN_FLAG = 0x00000200;
		public const uint CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN_FLAG = 0x00000400;
		public const uint CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN_FLAG = 0x00000800;

		public const uint CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS = (
												CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG |
												CERT_CHAIN_POLICY_IGNORE_CTL_SIGNER_REV_UNKNOWN_FLAG |
												CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN_FLAG |
												CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN_FLAG);

		// The following are info status bits

		// These can be applied to certificates only
		public const uint CERT_TRUST_HAS_EXACT_MATCH_ISSUER = 0x00000001;
		public const uint CERT_TRUST_HAS_KEY_MATCH_ISSUER = 0x00000002;
		public const uint CERT_TRUST_HAS_NAME_MATCH_ISSUER = 0x00000004;
		public const uint CERT_TRUST_IS_SELF_SIGNED = 0x00000008;

		// These can be applied to certificates and chains
		public const uint CERT_TRUST_HAS_PREFERRED_ISSUER = 0x00000100;
		public const uint CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY = 0x00000200;
		public const uint CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS = 0x00000400;

		// These can be applied to chains only
		public const uint CERT_TRUST_IS_COMPLEX_CHAIN = 0x00010000;

		// Signature value that only contains the hash octets. The parameters for
		// this algorithm must be present and must be encoded as NULL.
		public const string szOID_PKIX_NO_SIGNATURE = "1.3.6.1.5.5.7.6.2";

		// Consistent key usage bits: DIGITAL_SIGNATURE, KEY_ENCIPHERMENT or KEY_AGREEMENT
		public const string szOID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
		// Consistent key usage bits: DIGITAL_SIGNATURE
		public const string szOID_PKIX_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
		// Consistent key usage bits: DIGITAL_SIGNATURE
		public const string szOID_PKIX_KP_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
		// Consistent key usage bits: DIGITAL_SIGNATURE, NON_REPUDIATION and/or (KEY_ENCIPHERMENT or KEY_AGREEMENT)
		public const string szOID_PKIX_KP_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";

		public const string SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID = "1.3.6.1.4.1.311.2.1.21";
		public const string SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID = "1.3.6.1.4.1.311.2.1.22";

		// CertGetCertificateChain chain engine handles.
		public const uint HCCE_CURRENT_USER = 0x0;
		public const uint HCCE_LOCAL_MACHINE = 0x1;

		// PKCS.
		public const string szOID_PKCS_1 = "1.2.840.113549.1.1";
		public const string szOID_PKCS_2 = "1.2.840.113549.1.2";
		public const string szOID_PKCS_3 = "1.2.840.113549.1.3";
		public const string szOID_PKCS_4 = "1.2.840.113549.1.4";
		public const string szOID_PKCS_5 = "1.2.840.113549.1.5";
		public const string szOID_PKCS_6 = "1.2.840.113549.1.6";
		public const string szOID_PKCS_7 = "1.2.840.113549.1.7";
		public const string szOID_PKCS_8 = "1.2.840.113549.1.8";
		public const string szOID_PKCS_9 = "1.2.840.113549.1.9";
		public const string szOID_PKCS_10 = "1.2.840.113549.1.10";
		public const string szOID_PKCS_12 = "1.2.840.113549.1.12";

		// PKCS7 Content Types.
		public const string szOID_RSA_data = "1.2.840.113549.1.7.1";
		public const string szOID_RSA_signedData = "1.2.840.113549.1.7.2";
		public const string szOID_RSA_envelopedData = "1.2.840.113549.1.7.3";
		public const string szOID_RSA_signEnvData = "1.2.840.113549.1.7.4";
		public const string szOID_RSA_digestedData = "1.2.840.113549.1.7.5";
		public const string szOID_RSA_hashedData = "1.2.840.113549.1.7.5";
		public const string szOID_RSA_encryptedData = "1.2.840.113549.1.7.6";

		// PKCS9 Attributes.
		public const string szOID_RSA_emailAddr = "1.2.840.113549.1.9.1";
		public const string szOID_RSA_unstructName = "1.2.840.113549.1.9.2";
		public const string szOID_RSA_contentType = "1.2.840.113549.1.9.3";
		public const string szOID_RSA_messageDigest = "1.2.840.113549.1.9.4";
		public const string szOID_RSA_signingTime = "1.2.840.113549.1.9.5";
		public const string szOID_RSA_counterSign = "1.2.840.113549.1.9.6";
		public const string szOID_RSA_challengePwd = "1.2.840.113549.1.9.7";
		public const string szOID_RSA_unstructAddr = "1.2.840.113549.1.9.8";
		public const string szOID_RSA_extCertAttrs = "1.2.840.113549.1.9.9";
		public const string szOID_RSA_SMIMECapabilities = "1.2.840.113549.1.9.15";

		public const string szOID_CAPICOM = "1.3.6.1.4.1.311.88";     // Reserved for CAPICOM.
		public const string szOID_CAPICOM_version = "1.3.6.1.4.1.311.88.1";   // CAPICOM version
		public const string szOID_CAPICOM_attribute = "1.3.6.1.4.1.311.88.2";   // CAPICOM attribute
		public const string szOID_CAPICOM_documentName = "1.3.6.1.4.1.311.88.2.1"; // Document type attribute
		public const string szOID_CAPICOM_documentDescription = "1.3.6.1.4.1.311.88.2.2"; // Document description attribute
		public const string szOID_CAPICOM_encryptedData = "1.3.6.1.4.1.311.88.3";   // CAPICOM encrypted data message.
		public const string szOID_CAPICOM_encryptedContent = "1.3.6.1.4.1.311.88.3.1"; // CAPICOM content of encrypted data.

		// Digest Algorithms
		public const string szOID_OIWSEC_sha1 = "1.3.14.3.2.26";
		public const string szOID_RSA_MD5 = "1.2.840.113549.2.5";
		public const string szOID_OIWSEC_SHA256 = "2.16.840.1.101.3.4.1";
		public const string szOID_OIWSEC_SHA384 = "2.16.840.1.101.3.4.2";
		public const string szOID_OIWSEC_SHA512 = "2.16.840.1.101.3.4.3";

		// Encryption Algorithms
		public const string szOID_RSA_RC2CBC = "1.2.840.113549.3.2";
		public const string szOID_RSA_RC4 = "1.2.840.113549.3.4";
		public const string szOID_RSA_DES_EDE3_CBC = "1.2.840.113549.3.7";
		public const string szOID_OIWSEC_desCBC = "1.3.14.3.2.7";

		// Key encryption algorithms
		public const string szOID_RSA_SMIMEalg = "1.2.840.113549.1.9.16.3";
		public const string szOID_RSA_SMIMEalgESDH = "1.2.840.113549.1.9.16.3.5";
		public const string szOID_RSA_SMIMEalgCMS3DESwrap = "1.2.840.113549.1.9.16.3.6";
		public const string szOID_RSA_SMIMEalgCMSRC2wrap = "1.2.840.113549.1.9.16.3.7";

		// DSA signing algorithms
		public const string szOID_X957_DSA = "1.2.840.10040.4.1";
		public const string szOID_X957_sha1DSA = "1.2.840.10040.4.3";

		// RSA signing algorithms
		public const string szOID_OIWSEC_sha1RSASign = "1.3.14.3.2.29";
		public const string szOID_RSA = "1.2.840.113549.1.1.1";

		// Alt Name Types.
		public const uint CERT_ALT_NAME_OTHER_NAME = 1;
		public const uint CERT_ALT_NAME_RFC822_NAME = 2;
		public const uint CERT_ALT_NAME_DNS_NAME = 3;
		public const uint CERT_ALT_NAME_X400_ADDRESS = 4;
		public const uint CERT_ALT_NAME_DIRECTORY_NAME = 5;
		public const uint CERT_ALT_NAME_EDI_PARTY_NAME = 6;
		public const uint CERT_ALT_NAME_URL = 7;
		public const uint CERT_ALT_NAME_IP_ADDRESS = 8;
		public const uint CERT_ALT_NAME_REGISTERED_ID = 9;

		// CERT_RDN Attribute Value Types
		public const uint CERT_RDN_ANY_TYPE = 0;
		public const uint CERT_RDN_ENCODED_BLOB = 1;
		public const uint CERT_RDN_OCTET_STRING = 2;
		public const uint CERT_RDN_NUMERIC_STRING = 3;
		public const uint CERT_RDN_PRINTABLE_STRING = 4;
		public const uint CERT_RDN_TELETEX_STRING = 5;
		public const uint CERT_RDN_T61_STRING = 5;
		public const uint CERT_RDN_VIDEOTEX_STRING = 6;
		public const uint CERT_RDN_IA5_STRING = 7;
		public const uint CERT_RDN_GRAPHIC_STRING = 8;
		public const uint CERT_RDN_VISIBLE_STRING = 9;
		public const uint CERT_RDN_ISO646_STRING = 9;
		public const uint CERT_RDN_GENERAL_STRING = 10;
		public const uint CERT_RDN_UNIVERSAL_STRING = 11;
		public const uint CERT_RDN_INT4_STRING = 11;
		public const uint CERT_RDN_BMP_STRING = 12;
		public const uint CERT_RDN_UNICODE_STRING = 12;
		public const uint CERT_RDN_UTF8_STRING = 13;
		public const uint CERT_RDN_TYPE_MASK = 0x000000FF;
		public const uint CERT_RDN_FLAGS_MASK = 0xFF000000;

		// Certificate Store control types
		public const uint CERT_STORE_CTRL_RESYNC = 1;
		public const uint CERT_STORE_CTRL_NOTIFY_CHANGE = 2;
		public const uint CERT_STORE_CTRL_COMMIT = 3;
		public const uint CERT_STORE_CTRL_AUTO_RESYNC = 4;
		public const uint CERT_STORE_CTRL_CANCEL_NOTIFY = 5;

		// Certificate Identifier
		public const uint CERT_ID_ISSUER_SERIAL_NUMBER = 1;
		public const uint CERT_ID_KEY_IDENTIFIER = 2;
		public const uint CERT_ID_SHA1_HASH = 3;

		// MS provider names.
		public const string MS_ENHANCED_PROV = "Microsoft Enhanced Cryptographic Provider v1.0";
		public const string MS_STRONG_PROV = "Microsoft Strong Cryptographic Provider";
		public const string MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0";
		public const string MS_DEF_DSS_DH_PROV = "Microsoft Base DSS and Diffie-Hellman Cryptographic Provider";
		public const string MS_ENH_DSS_DH_PROV = "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider";

		// HashOnly Signature
		public const string DummySignerCommonName = "CN=Dummy Signer";

		// CSP types.
		public const uint PROV_RSA_FULL = 1;
		public const uint PROV_DSS_DH = 13;

		// Algorithm types
		public const uint ALG_TYPE_ANY = (0);
		public const uint ALG_TYPE_DSS = (1 << 9);
		public const uint ALG_TYPE_RSA = (2 << 9);
		public const uint ALG_TYPE_BLOCK = (3 << 9);
		public const uint ALG_TYPE_STREAM = (4 << 9);
		public const uint ALG_TYPE_DH = (5 << 9);
		public const uint ALG_TYPE_SECURECHANNEL = (6 << 9);

		// Algorithm classes
		public const uint ALG_CLASS_ANY = (0);
		public const uint ALG_CLASS_SIGNATURE = (1 << 13);
		public const uint ALG_CLASS_MSG_ENCRYPT = (2 << 13);
		public const uint ALG_CLASS_DATA_ENCRYPT = (3 << 13);
		public const uint ALG_CLASS_HASH = (4 << 13);
		public const uint ALG_CLASS_KEY_EXCHANGE = (5 << 13);
		public const uint ALG_CLASS_ALL = (7 << 13);

		public const uint ALG_SID_ANY = (0);
		// Some RSA sub-ids
		public const uint ALG_SID_RSA_ANY = 0;
		public const uint ALG_SID_RSA_PKCS = 1;
		public const uint ALG_SID_RSA_MSATWORK = 2;
		public const uint ALG_SID_RSA_ENTRUST = 3;
		public const uint ALG_SID_RSA_PGP = 4;

		// Some DSS sub-ids
		public const uint ALG_SID_DSS_ANY = 0;
		public const uint ALG_SID_DSS_PKCS = 1;
		public const uint ALG_SID_DSS_DMS = 2;

		// Block cipher sub ids
		// DES sub_ids
		public const uint ALG_SID_DES = 1;
		public const uint ALG_SID_3DES = 3;
		public const uint ALG_SID_DESX = 4;
		public const uint ALG_SID_IDEA = 5;
		public const uint ALG_SID_CAST = 6;
		public const uint ALG_SID_SAFERSK64 = 7;
		public const uint ALG_SID_SAFERSK128 = 8;
		public const uint ALG_SID_3DES_112 = 9;
		public const uint ALG_SID_CYLINK_MEK = 12;
		public const uint ALG_SID_RC5 = 13;
		public const uint ALG_SID_AES_128 = 14;
		public const uint ALG_SID_AES_192 = 15;
		public const uint ALG_SID_AES_256 = 16;
		public const uint ALG_SID_AES = 17;

		// Fortezza sub-ids
		public const uint ALG_SID_SKIPJACK = 10;
		public const uint ALG_SID_TEK = 11;

		// RC2 sub-ids
		public const uint ALG_SID_RC2 = 2;

		// Stream cipher sub-ids
		public const uint ALG_SID_RC4 = 1;
		public const uint ALG_SID_SEAL = 2;

		// Diffie-Hellman sub-ids
		public const uint ALG_SID_DH_SANDF = 1;
		public const uint ALG_SID_DH_EPHEM = 2;
		public const uint ALG_SID_AGREED_KEY_ANY = 3;
		public const uint ALG_SID_KEA = 4;

		// Hash sub ids
		public const uint ALG_SID_MD2 = 1;
		public const uint ALG_SID_MD4 = 2;
		public const uint ALG_SID_MD5 = 3;
		public const uint ALG_SID_SHA = 4;
		public const uint ALG_SID_SHA1 = 4;
		public const uint ALG_SID_MAC = 5;
		public const uint ALG_SID_RIPEMD = 6;
		public const uint ALG_SID_RIPEMD160 = 7;
		public const uint ALG_SID_SSL3SHAMD5 = 8;
		public const uint ALG_SID_HMAC = 9;
		public const uint ALG_SID_TLS1PRF = 10;
		public const uint ALG_SID_HASH_REPLACE_OWF = 11;

		// secure channel sub ids
		public const uint ALG_SID_SSL3_MASTER = 1;
		public const uint ALG_SID_SCHANNEL_MASTER_HASH = 2;
		public const uint ALG_SID_SCHANNEL_MAC_KEY = 3;
		public const uint ALG_SID_PCT1_MASTER = 4;
		public const uint ALG_SID_SSL2_MASTER = 5;
		public const uint ALG_SID_TLS1_MASTER = 6;
		public const uint ALG_SID_SCHANNEL_ENC_KEY = 7;

		// algorithm identifier definitions
		public const uint CALG_MD2 = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD2);
		public const uint CALG_MD4 = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD4);
		public const uint CALG_MD5 = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5);
		public const uint CALG_SHA = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA);
		public const uint CALG_SHA1 = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1);
		public const uint CALG_MAC = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MAC);
		public const uint CALG_RSA_SIGN = (ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | ALG_SID_RSA_ANY);
		public const uint CALG_DSS_SIGN = (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_DSS_ANY);
		public const uint CALG_NO_SIGN = (ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_ANY);
		public const uint CALG_RSA_KEYX = (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | ALG_SID_RSA_ANY);
		public const uint CALG_DES = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_DES);
		public const uint CALG_3DES_112 = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES_112);
		public const uint CALG_3DES = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES);
		public const uint CALG_DESX = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_DESX);
		public const uint CALG_RC2 = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RC2);
		public const uint CALG_RC4 = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | ALG_SID_RC4);
		public const uint CALG_SEAL = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | ALG_SID_SEAL);
		public const uint CALG_DH_SF = (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_SANDF);
		public const uint CALG_DH_EPHEM = (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EPHEM);
		public const uint CALG_AGREEDKEY_ANY = (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_AGREED_KEY_ANY);
		public const uint CALG_KEA_KEYX = (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_KEA);
		public const uint CALG_HUGHES_MD5 = (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | ALG_SID_MD5);
		public const uint CALG_SKIPJACK = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SKIPJACK);
		public const uint CALG_TEK = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_TEK);
		public const uint CALG_CYLINK_MEK = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_CYLINK_MEK);
		public const uint CALG_SSL3_SHAMD5 = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SSL3SHAMD5);
		public const uint CALG_SSL3_MASTER = (ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SSL3_MASTER);
		public const uint CALG_SCHANNEL_MASTER_HASH = (ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MASTER_HASH);
		public const uint CALG_SCHANNEL_MAC_KEY = (ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MAC_KEY);
		public const uint CALG_SCHANNEL_ENC_KEY = (ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_ENC_KEY);
		public const uint CALG_PCT1_MASTER = (ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_PCT1_MASTER);
		public const uint CALG_SSL2_MASTER = (ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SSL2_MASTER);
		public const uint CALG_TLS1_MASTER = (ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_TLS1_MASTER);
		public const uint CALG_RC5 = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RC5);
		public const uint CALG_HMAC = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HMAC);
		public const uint CALG_TLS1PRF = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1PRF);
		public const uint CALG_HASH_REPLACE_OWF = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_REPLACE_OWF);
		public const uint CALG_AES_128 = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_128);
		public const uint CALG_AES_192 = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_192);
		public const uint CALG_AES_256 = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256);
		public const uint CALG_AES = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES);

		// CryptGetProvParam flags
		public const uint CRYPT_FIRST = 1;
		public const uint CRYPT_NEXT = 2;
		public const uint PP_ENUMALGS_EX = 22;
		public const uint PP_CONTAINER = 6;

		// dwFlags definitions for CryptAcquireContext
		public const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
		public const uint CRYPT_NEWKEYSET = 0x00000008;
		public const uint CRYPT_DELETEKEYSET = 0x00000010;
		public const uint CRYPT_MACHINE_KEYSET = 0x00000020;
		public const uint CRYPT_SILENT = 0x00000040;
		public const uint CRYPT_USER_KEYSET = 0x00001000;

		// dwFlag definitions for CryptGenKey
		public const uint CRYPT_EXPORTABLE = 0x00000001;
		public const uint CRYPT_USER_PROTECTED = 0x00000002;
		public const uint CRYPT_CREATE_SALT = 0x00000004;
		public const uint CRYPT_UPDATE_KEY = 0x00000008;
		public const uint CRYPT_NO_SALT = 0x00000010;
		public const uint CRYPT_PREGEN = 0x00000040;
		public const uint CRYPT_RECIPIENT = 0x00000010;
		public const uint CRYPT_INITIATOR = 0x00000040;
		public const uint CRYPT_ONLINE = 0x00000080;
		public const uint CRYPT_SF = 0x00000100;
		public const uint CRYPT_CREATE_IV = 0x00000200;
		public const uint CRYPT_KEK = 0x00000400;
		public const uint CRYPT_DATA_KEY = 0x00000800;
		public const uint CRYPT_VOLATILE = 0x00001000;
		public const uint CRYPT_SGCKEY = 0x00002000;
		public const uint CRYPT_ARCHIVABLE = 0x00004000;

		public const byte CUR_BLOB_VERSION = 2;

		// Exported key blob definitions
		public const byte SIMPLEBLOB = 0x1;
		public const byte PUBLICKEYBLOB = 0x6;
		public const byte PRIVATEKEYBLOB = 0x7;
		public const byte PLAINTEXTKEYBLOB = 0x8;
		public const byte OPAQUEKEYBLOB = 0x9;
		public const byte PUBLICKEYBLOBEX = 0xA;
		public const byte SYMMETRICWRAPKEYBLOB = 0xB;

		// Magic constants
		public const uint DSS_MAGIC = 0x31535344;
		public const uint DSS_PRIVATE_MAGIC = 0x32535344;
		public const uint DSS_PUB_MAGIC_VER3 = 0x33535344;
		public const uint DSS_PRIV_MAGIC_VER3 = 0x34535344;
		public const uint RSA_PUB_MAGIC = 0x31415352;
		public const uint RSA_PRIV_MAGIC = 0x32415352;

		// CryptAcquireCertificatePrivateKey dwFlags
		public const uint CRYPT_ACQUIRE_CACHE_FLAG = 0x00000001;
		public const uint CRYPT_ACQUIRE_USE_PROV_INFO_FLAG = 0x00000002;
		public const uint CRYPT_ACQUIRE_COMPARE_KEY_FLAG = 0x00000004;
		public const uint CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040;

		// CryptMsgOpenToDecode dwFlags
		public const uint CMSG_BARE_CONTENT_FLAG = 0x00000001;
		public const uint CMSG_LENGTH_ONLY_FLAG = 0x00000002;
		public const uint CMSG_DETACHED_FLAG = 0x00000004;
		public const uint CMSG_AUTHENTICATED_ATTRIBUTES_FLAG = 0x00000008;
		public const uint CMSG_CONTENTS_OCTETS_FLAG = 0x00000010;
		public const uint CMSG_MAX_LENGTH_FLAG = 0x00000020;

		// Get parameter types and their corresponding data structure definitions.
		public const uint CMSG_TYPE_PARAM = 1;
		public const uint CMSG_CONTENT_PARAM = 2;
		public const uint CMSG_BARE_CONTENT_PARAM = 3;
		public const uint CMSG_INNER_CONTENT_TYPE_PARAM = 4;
		public const uint CMSG_SIGNER_COUNT_PARAM = 5;
		public const uint CMSG_SIGNER_INFO_PARAM = 6;
		public const uint CMSG_SIGNER_CERT_INFO_PARAM = 7;
		public const uint CMSG_SIGNER_HASH_ALGORITHM_PARAM = 8;
		public const uint CMSG_SIGNER_AUTH_ATTR_PARAM = 9;
		public const uint CMSG_SIGNER_UNAUTH_ATTR_PARAM = 10;
		public const uint CMSG_CERT_COUNT_PARAM = 11;
		public const uint CMSG_CERT_PARAM = 12;
		public const uint CMSG_CRL_COUNT_PARAM = 13;
		public const uint CMSG_CRL_PARAM = 14;
		public const uint CMSG_ENVELOPE_ALGORITHM_PARAM = 15;
		public const uint CMSG_RECIPIENT_COUNT_PARAM = 17;
		public const uint CMSG_RECIPIENT_INDEX_PARAM = 18;
		public const uint CMSG_RECIPIENT_INFO_PARAM = 19;
		public const uint CMSG_HASH_ALGORITHM_PARAM = 20;
		public const uint CMSG_HASH_DATA_PARAM = 21;
		public const uint CMSG_COMPUTED_HASH_PARAM = 22;
		public const uint CMSG_ENCRYPT_PARAM = 26;
		public const uint CMSG_ENCRYPTED_DIGEST = 27;
		public const uint CMSG_ENCODED_SIGNER = 28;
		public const uint CMSG_ENCODED_MESSAGE = 29;
		public const uint CMSG_VERSION_PARAM = 30;
		public const uint CMSG_ATTR_CERT_COUNT_PARAM = 31;
		public const uint CMSG_ATTR_CERT_PARAM = 32;
		public const uint CMSG_CMS_RECIPIENT_COUNT_PARAM = 33;
		public const uint CMSG_CMS_RECIPIENT_INDEX_PARAM = 34;
		public const uint CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM = 35;
		public const uint CMSG_CMS_RECIPIENT_INFO_PARAM = 36;
		public const uint CMSG_UNPROTECTED_ATTR_PARAM = 37;
		public const uint CMSG_SIGNER_CERT_ID_PARAM = 38;
		public const uint CMSG_CMS_SIGNER_INFO_PARAM = 39;

		// Message control types.
		public const uint CMSG_CTRL_VERIFY_SIGNATURE = 1;
		public const uint CMSG_CTRL_DECRYPT = 2;
		public const uint CMSG_CTRL_VERIFY_HASH = 5;
		public const uint CMSG_CTRL_ADD_SIGNER = 6;
		public const uint CMSG_CTRL_DEL_SIGNER = 7;
		public const uint CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR = 8;
		public const uint CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR = 9;
		public const uint CMSG_CTRL_ADD_CERT = 10;
		public const uint CMSG_CTRL_DEL_CERT = 11;
		public const uint CMSG_CTRL_ADD_CRL = 12;
		public const uint CMSG_CTRL_DEL_CRL = 13;
		public const uint CMSG_CTRL_ADD_ATTR_CERT = 14;
		public const uint CMSG_CTRL_DEL_ATTR_CERT = 15;
		public const uint CMSG_CTRL_KEY_TRANS_DECRYPT = 16;
		public const uint CMSG_CTRL_KEY_AGREE_DECRYPT = 17;
		public const uint CMSG_CTRL_MAIL_LIST_DECRYPT = 18;
		public const uint CMSG_CTRL_VERIFY_SIGNATURE_EX = 19;
		public const uint CMSG_CTRL_ADD_CMS_SIGNER_INFO = 20;

		// Signer Types
		public const uint CMSG_VERIFY_SIGNER_PUBKEY = 1; // pvSigner: PCERT_PUBLIC_KEY_INFO
		public const uint CMSG_VERIFY_SIGNER_CERT = 2; // pvSigner: PCCERT_CONTEXT
		public const uint CMSG_VERIFY_SIGNER_CHAIN = 3; // pvSigner: PCCERT_CHAIN_CONTEXT
		public const uint CMSG_VERIFY_SIGNER_NULL = 4; // pvSigner: NULL

		// Message types.
		public const uint CMSG_DATA = 1;
		public const uint CMSG_SIGNED = 2;
		public const uint CMSG_ENVELOPED = 3;
		public const uint CMSG_SIGNED_AND_ENVELOPED = 4;
		public const uint CMSG_HASHED = 5;
		public const uint CMSG_ENCRYPTED = 6;

		// Recipient types
		public const uint CMSG_KEY_TRANS_RECIPIENT = 1;
		public const uint CMSG_KEY_AGREE_RECIPIENT = 2;
		public const uint CMSG_MAIL_LIST_RECIPIENT = 3;

		// Key agree type
		public const uint CMSG_KEY_AGREE_ORIGINATOR_CERT = 1;
		public const uint CMSG_KEY_AGREE_ORIGINATOR_PUBLIC_KEY = 2;

		// Key agree choices
		public const uint CMSG_KEY_AGREE_EPHEMERAL_KEY_CHOICE = 1;
		public const uint CMSG_KEY_AGREE_STATIC_KEY_CHOICE = 2;

		// dwVersion numbers for the KeyTrans, KeyAgree and MailList recipients
		public const uint CMSG_ENVELOPED_RECIPIENT_V0 = 0;
		public const uint CMSG_ENVELOPED_RECIPIENT_V2 = 2;
		public const uint CMSG_ENVELOPED_RECIPIENT_V3 = 3;
		public const uint CMSG_ENVELOPED_RECIPIENT_V4 = 4;
		public const uint CMSG_KEY_TRANS_PKCS_1_5_VERSION = CMSG_ENVELOPED_RECIPIENT_V0;
		public const uint CMSG_KEY_TRANS_CMS_VERSION = CMSG_ENVELOPED_RECIPIENT_V2;
		public const uint CMSG_KEY_AGREE_VERSION = CMSG_ENVELOPED_RECIPIENT_V3;
		public const uint CMSG_MAIL_LIST_VERSION = CMSG_ENVELOPED_RECIPIENT_V4;

		// RC2 encryption algorithm version (key length).
		public const uint CRYPT_RC2_40BIT_VERSION = 160;
		public const uint CRYPT_RC2_56BIT_VERSION = 52;
		public const uint CRYPT_RC2_64BIT_VERSION = 120;
		public const uint CRYPT_RC2_128BIT_VERSION = 58;

		// Error codes.
		public const int E_NOTIMPL = unchecked((int)0x80000001); // Not implemented.
		public const int E_OUTOFMEMORY = unchecked((int)0x8007000E); // Ran out of memory.
		public const int NTE_NO_KEY = unchecked((int)0x8009000D); // Key does not exist.
		public const int NTE_BAD_PUBLIC_KEY = unchecked((int)0x80090015); // Provider's public key is invalid.
		public const int NTE_BAD_KEYSET = unchecked((int)0x80090016); // Keyset does not exist
		public const int CRYPT_E_MSG_ERROR = unchecked((int)0x80091001); // An error occurred while performing an operation on a cryptographic message.
		public const int CRYPT_E_UNKNOWN_ALGO = unchecked((int)0x80091002); // Unknown cryptographic algorithm.
		public const int CRYPT_E_INVALID_MSG_TYPE = unchecked((int)0x80091004); // Invalid cryptographic message type.
		public const int CRYPT_E_RECIPIENT_NOT_FOUND = unchecked((int)0x8009100B); // The enveloped-data message does not contain the specified recipient.
		public const int CRYPT_E_ISSUER_SERIALNUMBER = unchecked((int)0x8009100D); // Invalid issuer and/or serial number.
		public const int CRYPT_E_SIGNER_NOT_FOUND = unchecked((int)0x8009100E); // Cannot find the original signer.
		public const int CRYPT_E_ATTRIBUTES_MISSING = unchecked((int)0x8009100F); // The cryptographic message does not contain all of the requested attributes.
		public const int CRYPT_E_BAD_ENCODE = unchecked((int)0x80092002); // An error occurred during encode or decode operation.
		public const int CRYPT_E_NOT_FOUND = unchecked((int)0x80092004); // Cannot find object or property.
		public const int CRYPT_E_NO_MATCH = unchecked((int)0x80092009); // Cannot find the requested object.
		public const int CRYPT_E_NO_SIGNER = unchecked((int)0x8009200E); // The signed cryptographic message does not have a signer for the specified signer index.
		public const int CRYPT_E_REVOKED = unchecked((int)0x80092010); // The certificate is revoked.
		public const int CRYPT_E_NO_REVOCATION_CHECK = unchecked((int)0x80092012); // The revocation function was unable to check revocation for the certificate.        
		public const int CRYPT_E_REVOCATION_OFFLINE = unchecked((int)0x80092013); // The revocation function was unable to check revocation 
																					// because the revocation server was offline.        
		public const int CRYPT_E_ASN1_BADTAG = unchecked((int)0x8009310B); // ASN1 bad tag value met.

		public const int TRUST_E_CERT_SIGNATURE = unchecked((int)0x80096004); // The signature of the certificate can not be verified.
		public const int TRUST_E_BASIC_CONSTRAINTS = unchecked((int)0x80096019); // A certificate's basic constraint extension has not been observed.        
		public const int CERT_E_EXPIRED = unchecked((int)0x800B0101); // A required certificate is not within its validity period when verifying against 
																		// the current system clock or the timestamp in the signed file.        
		public const int CERT_E_VALIDITYPERIODNESTING = unchecked((int)0x800B0102); // The validity periods of the certification chain do not nest correctly.        
		public const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109); // A certificate chain processed, but terminated in a root 
																			  // certificate which is not trusted by the trust provider.
		public const int CERT_E_CHAINING = unchecked((int)0x800B010A); // An public certificate chaining error has occurred.        
		public const int TRUST_E_FAIL = unchecked((int)0x800B010B); // Generic trust failure.        
		public const int CERT_E_REVOKED = unchecked((int)0x800B010C); // A certificate was explicitly revoked by its issuer.        
		public const int CERT_E_UNTRUSTEDTESTROOT = unchecked((int)0x800B010D); // The certification path terminates with the test root which 
																				  // is not trusted with the current policy settings.        
		public const int CERT_E_REVOCATION_FAILURE = unchecked((int)0x800B010E); // The revocation process could not continue - the certificate(s) could not be checked.        
		public const int CERT_E_WRONG_USAGE = unchecked((int)0x800B0110); // The certificate is not valid for the requested usage.        
		public const int CERT_E_INVALID_POLICY = unchecked((int)0x800B0113); // The certificate has invalid policy.        
		public const int CERT_E_INVALID_NAME = unchecked((int)0x800B0114); // The certificate has an invalid name. The name is not included 
																			 // in the permitted list or is explicitly excluded.

		public const int ERROR_SUCCESS = 0;                           // The operation completed successfully.
		public const int ERROR_CALL_NOT_IMPLEMENTED = 120;                         // This function is not supported on this system.
		public const int ERROR_CANCELLED = 1223;                        // The operation was canceled by the user.
		#endregion


		#region Идентификаторы криптографических алгоритмов ГОСТ

        /// <summary>
        /// Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 2001.
        /// </summary>
        public const int CALG_DH_EL_SF = 0xaa24;

        /// <summary>
        /// Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 2012 (256 бит).
        /// </summary>
        public const int CALG_DH_GR3410_2012_256_SF = 0xaa46;

        /// <summary>
        /// Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 2012 (512 бит).
        /// </summary>
        public const int CALG_DH_GR3410_2012_512_SF = 0xaa42;

        /// <summary>
        /// Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 2001.
        /// </summary>
        public const int CALG_DH_EL_EPHEM = 0xaa25;

        /// <summary>
        /// Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 2012 (256 бит).
        /// </summary>
        public const int CALG_DH_GR3410_12_256_EPHEM = 0xaa47;

        /// <summary>
        /// Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 2012 (512 бит).
        /// </summary>
        public const int CALG_DH_GR3410_12_512_EPHEM = 0xaa43;

        /// <summary>
        /// Идентификатор алгоритма вычисления имитовставки по ГОСТ 28147-89.
        /// </summary>
        public const int CALG_G28147_IMIT = 0x801f;

		/// <summary>
		/// Идентификатор алгоритма ГОСТ Р 34.10-2001.
		/// </summary>
		public const int CALG_GR3410EL = 0x2e23;

        /// <summary>
        /// Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2012 (256 бит).
        /// </summary>
        public const int CALG_GR3410_2012_256 = 0x2e49;

        /// <summary>
        /// Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2012 (512 бит).
        /// </summary>
        public const int CALG_GR3410_2012_512 = 0x2e3d;

        /// <summary>
        /// Идентификатор алгоритма хэширования по ГОСТ Р 34.11-94.
        /// </summary>
        public const int CALG_GR3411 = 0x801e;

        /// <summary>
        /// Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 256 бит.
        /// </summary>
        public const int CALG_GR3411_2012_256 = 0x8021;

        /// <summary>
        /// Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 512 бит.
        /// </summary>
        public const int CALG_GR3411_2012_512 = 0x8022;

        /// <summary>
        /// Идентификатор алгоритма вычисления HMAC (Hash-based Message Authentication Code) на базе алгоритма хэширования по ГОСТ Р 34.11.
        /// </summary>
        public const int CALG_GR3411_HMAC = 0x8027;

        /// <summary>
        /// Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма ГОСТ Р 34.11-2012 и сессионного ключа <see cref="CALG_G28147"/>, длина выхода 256 бит.
        /// </summary>
        public const int CALG_GR3411_2012_256_HMAC = 0x8034;

        /// <summary>
        /// Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма ГОСТ Р 34.11-2012 и сессионного ключа <see cref="CALG_G28147"/>, длина выхода 512 бит.
        /// </summary>
        public const int CALG_GR3411_2012_512_HMAC = 0x8035;

        /// <summary>
        /// Идентификатор алгоритма вычисления HMAC (Hash-based Message Authentication Code) на базе алгоритма хэширования по ГОСТ Р 34.11.
        /// </summary>
        public const int CALG_GR3411_HMAC34 = 0x8028;

		/// <summary>
		/// Идентификатор алгоритма симметричного шифрования по ГОСТ 28147-89.
		/// </summary>
		public const int CALG_G28147 = 0x661e;

		/// <summary>
		/// Идентификатор алгоритма экспорта ключа КриптоПро.
		/// </summary>
		public const int CALG_PRO_EXPORT = 0x661f;

		/// <summary>
		/// Идентификатор алгоритма экспорта ключа по ГОСТ 28147-89.
		/// </summary>
		public const int CALG_SIMPLE_EXPORT = 0x6620;

        /// <summary>
        /// OID алгоритма шифрования ГОСТ 28147-89
        /// </summary>
        public const string OID_GR28147_89 = "1.2.643.2.2.21";

		/// <summary>
		/// OID алгоритма ГОСТ Р 34.10-2001.
		/// </summary>
		public const string OID_GR3410_2001 = "1.2.643.2.2.19";

        public const string OID_GR3410_12_256 = "1.2.643.7.1.1.1.1";

        public const string OID_GR3410_12_512 = "1.2.643.7.1.1.1.2";

        public const string OID_GR3411_2001 = "1.2.643.2.2.9";

        public const string OID_GR3411_12_256 = "1.2.643.7.1.1.2.2";

        public const string OID_GR3411_12_512 = "1.2.643.7.1.1.2.3";

        #endregion


        #region Настройки контекста криптографического провайдера

        /// <summary>
        /// Создать новый ключевой контейнер.
        /// </summary>
        //public const uint CRYPT_NEWKEYSET = 8;

        /// <summary>
        /// Использовать ключи локальной машины.
        /// </summary>
        //public const uint CRYPT_MACHINE_KEYSET = 0x20;

        /// <summary>
        /// Получить доступ к провайдеру без необходимости доступа к приватным ключам.
        /// </summary>
        //public const uint CRYPT_VERIFYCONTEXT = 0xf0000000;


        #endregion


        #region Параметры криптографического провайдера

        public const int PP_CLIENT_HWND = 1;

		/// <summary>
		/// Удаляет текущий контейнер с носителя.
		/// </summary>
		public const int PP_DELETE_KEYSET = 0x7d;

		/// <summary>
		/// Задаёт пароль (PIN) для доступа к ключу AT_KEYEXCHANGE.
		/// </summary>
		public const int PP_KEYEXCHANGE_PIN = 0x20;

		/// <summary>
		/// Задаёт пароль (PIN) для доступа к ключу AT_SIGNATURE.
		/// </summary>
		public const int PP_SIGNATURE_PIN = 0x21;

		#endregion


		#region Параметры функции хэширования криптографического провайдера

		/// <summary>
		/// Стартовый вектор функции хэширования, устанавливаемый приложением.
		/// </summary>
		public const int HP_HASHSTARTVECT = 8;

		/// <summary>
		/// Значение функции хэширования в little-endian порядке байт в соотвествии с типом GostR3411-94-Digest CPCMS [RFC 4490].
		/// </summary>
		public const int HP_HASHVAL = 2;

		#endregion


		#region Параметры функций шифрования криптографического провайдера

		/// <summary>
		/// Размер элемента.
		/// </summary>
		public const int EL_SIZE = 512;

		/// <summary>
		/// Признак ключей ГОСТ 28147-89 и мастер ключей TLS.
		/// </summary>
		public const int G28147_MAGIC = 0x374A51FD;

		/// <summary>
		/// Признак ключей ГОСТ Р 34.10-94 и ГОСТ Р 34.10-2001.
		/// </summary>
		public const int GR3410_1_MAGIC = 0x3147414D;

		#endregion


		#region Параметры ключей криптографического провайдера

		/// <summary>
		/// Вектор инициализации (IV, синхропосылки) алгоритма шифрования.
		/// </summary>
		public const int KP_IV = 1;

		/// <summary>
		/// Метод дополнения шифра ключа.
		/// </summary>
		public const int KP_PADDING = 3;

		/// <summary>
		/// Режим шифра ключа.
		/// </summary>
		public const int KP_MODE = 4;

		/// <summary>
		/// Идентификатор алгоритма ключа.
		/// </summary>
		public const int KP_ALGID = 7;

		/// <summary>
		/// Строковый идентификатор узла замены.
		/// </summary>
		public const int KP_CIPHEROID = 0x68;

		/// <summary>
		/// Строковый идентификатор параметров ключа ГОСТ Р 34.10-2001, применяемых в алгоритме Диффи-Хеллмана.
		/// </summary>
		public const int KP_DHOID = 0x6a;

		/// <summary>
		/// Строковый идентификатор функции хэширования.
		/// </summary>
		public const int KP_HASHOID = 0x67;

		/// <summary>
		/// Закрытый ключ в ключевой паре.
		/// </summary>
		public const int KP_X = 14;

		/// <summary>
		/// Произведенный ключ может быть передан из криптопровайдера в ключевой блоб при экспорте ключа независимо сессии криптопровайдера (исключает CRYPT_ARCHIVABLE).
		/// </summary>
		//public const int CRYPT_EXPORTABLE = 1;

		/// <summary>
		/// Произведенный ключ может быть передан из криптопровайдера в ключевой блоб при экспорте ключа в раках одной сессии криптопровайдера (исключает CRYPT_EXPORTABLE).
		/// </summary>
		//public const int CRYPT_ARCHIVABLE = 0x4000;

		/// <summary>
		/// При любом запросе на доступ к носителю закрытого ключа пользователя выводится окно диалога, запрашивающего право доступа к ключу.
		/// </summary>
		//public const int CRYPT_USER_PROTECTED = 2;

		/// <summary>
		/// Генерация пустой ключевой пары обмена.
		/// </summary>
		//public const int CRYPT_PREGEN = 0x40;

		/// <summary>
		/// Пара ключей для обмена ключами.
		/// </summary>
		public const int AT_KEYEXCHANGE = 1;

		/// <summary>
		/// Пара ключей для формирования цифровой подписи
		/// </summary>
		public const int AT_SIGNATURE = 2;

		#endregion


		#region Методы дополнения шифра ключа (KP_PADDING)

		/// <summary>
		/// PKCS#5.
		/// </summary>
		public const int PKCS5_PADDING = 1;

		/// <summary>
		/// Дополнение случайными байтами.
		/// </summary>
		public const int RANDOM_PADDING = 2;

		/// <summary>
		/// Дополнение нулевыми байтами.
		/// </summary>
		public const int ZERO_PADDING = 3;

		#endregion


		#region Режимы шифра ключа (KP_MODE)

		/// <summary>
		/// Cipher Block Chaining (CBC).
		/// </summary>
		public const int CRYPT_MODE_CBC = 1;

		/// <summary>
		/// Electronic codebook (ECB).
		/// </summary>
		public const int CRYPT_MODE_ECB = 2;

		/// <summary>
		/// Output Feedback (OFB).
		/// </summary>
		public const int CRYPT_MODE_OFB = 3;

		/// <summary>
		/// Cipher Feedback (CFB).
		/// </summary>
		public const int CRYPT_MODE_CFB = 4;

		/// <summary>
		/// Ciphertext stealing (CTS).
		/// </summary>
		public const int CRYPT_MODE_CTS = 5;

		#endregion


		#region Коды ошибок

		/// <summary>
		/// Aлгоритм, который данный криптопровайдер не поддерживает.
		/// </summary>
		public const int NTE_BAD_ALGID = -2146893816;

		/// <summary>
		/// Данные некорректного размера.
		/// </summary>
		public const int NTE_BAD_DATA = -2146893819;

		/// <summary>
		/// Дескриптор хэша ошибочен.
		/// </summary>
		public const int NTE_BAD_HASH = -2146893822;

		/// <summary>
		/// Ключевой контейнер не был открыт или не существует.
		/// </summary>
		//public const int NTE_BAD_KEYSET = -2146893802;

		/// <summary>
		/// Ключевой контейнер с заданным именем не существует.
		/// </summary>
		public const int NTE_KEYSET_NOT_DEF = -2146893799;

		/// <summary>
		/// Ключ с заданным параметром (AT_KEYEXCHANGE, AT_SIGNATURE или AT_UECSYMMETRICKEY) не существует.
		/// </summary>
		//public const int NTE_NO_KEY = -2146893811;

		/// <summary>
		/// Пользователь прервал операцию.
		/// </summary>
		public const int SCARD_W_CANCELLED_BY_USER = -2146434962;

		#endregion


		// ReSharper restore InconsistentNaming
	}
}