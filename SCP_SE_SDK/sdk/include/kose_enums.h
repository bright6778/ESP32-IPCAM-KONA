/*
*
* Copyright 2019,2020 NXP
* SPDX-License-Identifier: Apache-2.0
*/

/** @file */

#ifndef KOSE_ENUMS_H
#define KOSE_ENUMS_H

/** Values for INS in ISO7816 APDU */
typedef enum
{
    /** Invalid */
    kKOSE_INS_NA = 0,
    /** INS Select */
    kKOSE_INS_SELECT = 0xA4,
    /** INS Get Data */
    kKOSE_GET_DATA = 0xCA,
    /** INS SIGN CDATA */
    kKOSE_INS_SIGN_CDATA = 0x2A,
    /** INS Get Random */
    kKOSE_GET_RANDOM = 0x84,
    
    /** INS Read Binary */
    kKOSE_INS_READ_BINARY = 0xB0,
    /** INS Update Binary */
    kKOSE_INS_UPDATE_BINARY = 0xD6,
    /** INS Configure access control */
    kKOSE_INS_CONFIGURE_ACCESS_CTRL = 0x41,
    /** INS Manage read counter */
    kKOSE_INS_MANAGE_READ_CTR = 0x42,




    // 여기 아래는 삭제할지 고민중 - uc.nam
    /** 3 MSBit for instruction characteristics. */
    kKOSE_INS_MASK_INS_CHAR = 0xE0,
    /** 5 LSBit for instruction */
    kKOSE_INS_MASK_INSTRUCTION = 0x1F,

    /** Mask for transient object creation, can only be combined with INS_WRITE. */
    kKOSE_INS_TRANSIENT = 0x80,
    /** Mask for authentication object creation, can only be combined with INS_WRITE */
    kKOSE_INS_AUTH_OBJECT = 0x40,
    /** Mask for getting attestation data. */
    kKOSE_INS_ATTEST = 0x20,

    /** Write or create a persistent object. */
    kKOSE_INS_WRITE = 0x01,
    /** Read the object */
    kKOSE_INS_READ = 0x02,
    /** Perform Security Operation */
    kKOSE_INS_CRYPTO = 0x03,
    /** General operation */
    kKOSE_INS_MGMT = 0x04,
    /** Process session command */
    kKOSE_INS_PROCESS = 0x05,
} KOSE_INS_t;

/** Values for P1 in ISO7816 APDU */
typedef enum
{
    /** Invalid */
    kKOSE_P1_NA = 0,
    /** Highest bit not used */
    kKOSE_P1_UNUSED = 0x80,
    /** 2 MSBit for key type */
    kKOSE_P1_MASK_KEY_TYPE = 0x60,
    /** 5 LSBit for credential type */
    kKOSE_P1_MASK_CRED_TYPE = 0x1F,

    /** Select P1 */
    kKOSE_P1_SELECT_NAME = 0x04,

    /** Key & Signature P1 */
    kKOSE_P1_ECC_PRIVATE = 0x01,
    kKOSE_P1_ECC_PUBLIC  = 0x11,
    kKOSE_P1_RSA_PRIVATE = 0x02,
    kKOSE_P1_RSA_PUBLIC  = 0x21,
    kKOSE_P1_AES         = 0x03,
    kKOSE_P1_3DES        = 0x04,
    kKOSE_P1_HMAC        = 0x06,
    kKOSE_P1_CMAC        = 0x07,




    /** Key pair (private key + public key) */
    kKOSE_P1_KEY_PAIR = 0x60,
    /** Private key */
    kKOSE_P1_PRIVATE = 0x40,
    /** Public key */
    kKOSE_P1_PUBLIC = 0x20,

    kKOSE_P1_DEFAULT = 0x00,
    kKOSE_P1_EC = 0x01,
    kKOSE_P1_RSA = 0x02,
    //kKOSE_P1_AES = 0x03,
    kKOSE_P1_DES = 0x04,
    //kKOSE_P1_HMAC = 0x05,
    kKOSE_P1_BINARY = 0x06,
    kKOSE_P1_UserID = 0x07,
    kKOSE_P1_COUNTER = 0x08,
    kKOSE_P1_PCR = 0x09,
    kKOSE_P1_CURVE = 0x0B,
    kKOSE_P1_SIGNATURE = 0x0C,
    kKOSE_P1_MAC = 0x0D,
    kKOSE_P1_CIPHER = 0x0E,
    kKOSE_P1_TLS = 0x0F,
    kKOSE_P1_CRYPTO_OBJ = 0x10,
#if KSS_HAVE_KOSE_VER_GTE_07_02
    /** Applet >= 4.4 */
    kKOSE_P1_AEAD = 0x11,
    /** Applet >= 4.4 */
    kKOSE_P1_AEAD_SP800_38D = 0x12,
#endif /* KSS_HAVE_KOSE_VER_GTE_07_02 */
    kKOSE_P1_PAKE = 0x12,
} KOSE_P1_t;

/** Values for P2 in ISO7816 APDU */
typedef enum
{
    /** Invalid */
    kKOSE_P2_DEFAULT = 0x00,
    kKOSE_P2_GENERATE = 0x03,
    kKOSE_P2_CREATE = 0x04,
    kKOSE_P2_SIZE = 0x07,
    kKOSE_P2_SIGN = 0x09,
    kKOSE_P2_VERIFY = 0x0A,
    kKOSE_P2_INIT = 0x0B,
    kKOSE_P2_UPDATE = 0x0C,
    kKOSE_P2_FINAL = 0x0D,
    kKOSE_P2_ONESHOT = 0x0E,
    kKOSE_P2_DH = 0x0F,
    kKOSE_P2_DIVERSIFY = 0x10,
    // kKOSE_P2_AUTH_PART1 = 0x11,
    kKOSE_P2_AUTH_FIRST_PART2 = 0x12,
    kKOSE_P2_AUTH_NONFIRST_PART2 = 0x13,
    kKOSE_P2_DUMP_KEY = 0x14,
    kKOSE_P2_CHANGE_KEY_PART1 = 0x15,
    kKOSE_P2_CHANGE_KEY_PART2 = 0x16,
    kKOSE_P2_KILL_AUTH = 0x17,
    kKOSE_P2_IMPORT = 0x18,
    kKOSE_P2_EXPORT = 0x19,
    kKOSE_P2_SESSION_CREATE = 0x1B,
    kKOSE_P2_SESSION_CLOSE = 0x1C,
    kKOSE_P2_SESSION_REFRESH = 0x1E,
    kKOSE_P2_SESSION_POLICY = 0x1F,
    kKOSE_P2_VERSION = 0x20,
    kKOSE_P2_VERSION_EXT = 0x21,
    kKOSE_P2_MEMORY = 0x22,
    kKOSE_P2_LIST = 0x25,
    kKOSE_P2_TYPE = 0x26,
    kKOSE_P2_EXIST = 0x27,
    kKOSE_P2_DELETE_OBJECT = 0x28,
    kKOSE_P2_DELETE_ALL = 0x2A,
    kKOSE_P2_SESSION_UserID = 0x2C,
    kKOSE_P2_HKDF = 0x2D,
    kKOSE_P2_PBKDF = 0x2E,
    /* Applet >= 4.4 */
    kKOSE_P2_HKDF_EXPAND_ONLY = 0x2F,
    kKOSE_P2_I2CM = 0x30,
    kKOSE_P2_I2CM_ATTESTED = 0x31,
    kKOSE_P2_MAC = 0x32,
    kKOSE_P2_UNLOCK_CHALLENGE = 0x33,
    kKOSE_P2_CURVE_LIST = 0x34,
    kKOSE_P2_ID = 0x36,
    kKOSE_P2_ENCRYPT_ONESHOT = 0x37,
    kKOSE_P2_DECRYPT_ONESHOT = 0x38,
    kKOSE_P2_ATTEST = 0x3A,
    kKOSE_P2_ATTRIBUTES = 0x3B,
    kKOSE_P2_CPLC = 0x3C,
    kKOSE_P2_TIME = 0x3D,
    kKOSE_P2_TRANSPORT = 0x3E,
    kKOSE_P2_VARIANT = 0x3F,
    kKOSE_P2_PARAM = 0x40,
    kKOSE_P2_DELETE_CURVE = 0x41,
    kKOSE_P2_ENCRYPT = 0x42,
    kKOSE_P2_DECRYPT = 0x43,
    kKOSE_P2_VALIDATE = 0x44,
    kKOSE_P2_GENERATE_ONESHOT = 0x45,
    kKOSE_P2_VALIDATE_ONESHOT = 0x46,
    kKOSE_P2_CRYPTO_LIST = 0x47,
    kKOSE_P2_RANDOM = 0x49,
    kKOSE_P2_TLS_PMS = 0x4A,
    kKOSE_P2_TLS_PRF_CLI_HELLO = 0x4B,
    kKOSE_P2_TLS_PRF_SRV_HELLO = 0x4C,
    kKOSE_P2_TLS_PRF_CLI_RND = 0x4D,
    kKOSE_P2_TLS_PRF_SRV_RND = 0x4E,
    kKOSE_P2_TLS_PRF_BOTH = 0x5A,
    kKOSE_P2_RAW = 0x4F,
    kKOSE_P2_IMPORT_EXT = 0x51,
    kKOSE_P2_SCP = 0x52,
    kKOSE_P2_AUTH_FIRST_PART1 = 0x53,
    kKOSE_P2_AUTH_NONFIRST_PART1 = 0x54,
#if KSS_HAVE_KOSE_VER_GTE_07_02
    kKOSE_P2_CM_COMMAND = 0x55,
    kKOSE_P2_MODE_OF_OPERATION = 0x56,
    kKOSE_P2_RESTRICT = 0x57,
    kKOSE_P2_SANITY = 0x58,
    kKOSE_P2_DH_REVERSE = 0x59,
    kKOSE_P2_READ_STATE = 0x5B,
#endif
#if KSS_HAVE_KOSE_VER_GTE_07_02
    kKOSE_P2_ECPM = 0x62
#endif
} KOSE_P2_t;

#if 1
//#include <Applet_SE050_Ver.h>


/* + more or less machine Generated */

/** @addtogroup se05x_types
 *
 * @{ */

/** Reserved idendntifiers of the Applet */
typedef enum
{
    /** Invalid */
    kKOSE_AppletResID_NA = 0,
    /** An authentication object which allows the user to switch
     * LockState of the applet. The LockState defines whether the
     * applet is transport locked or not. */
    kKOSE_AppletResID_TRANSPORT = 0x7FFF0200,
    /** A device unique NIST P-256 key pair which contains SK.SE.ECKA
     * and PK.SE.ECKA in ECKey session context. */
    kKOSE_AppletResID_KP_ECKEY_USER = 0x7FFF0201,
    /** A device unique NIST P-256 key pair which contains SK.SE.ECKA
     * and PK.SE.ECKA in ECKey session context; A constant card
     * challenge (all zeroes) is applicable. */
    kKOSE_AppletResID_KP_ECKEY_IMPORT = 0x7FFF0202,
    /* Reserved Key @ location 0x7FFF0203 */
    /** An authentication object which allows the user to change the
    applet variant. */
    kKOSE_AppletResID_FEATURE = 0x7FFF0204,
    /** An authentication object which allows the user to delete all
    objects, except trust provisioned by NXP objects. */
    kKOSE_AppletResID_FACTORY_RESET = 0x7FFF0205,
    /** A BinaryFile Secure Object which holds the device unique
     *  ID. This file cannot be overwritten or deleted. */
    kKOSE_AppletResID_UNIQUE_ID = 0x7FFF0206,
    /** An authentication object which allows the user to change the
    * platform SCP requirements, i.e. make platform SCP mandatory or
    * not, using SetPlatformSCPRequest. Mandatory means full security,
    * i.e. command & response MAC and encryption. Only SCP03 will be
    * sufficient. */
    kKOSE_AppletResID_PLATFORM_SCP = 0x7FFF0207,
    /** An authentication object which grants access to the I2C master
     * feature. If the credential is not present, access to I2C master
     * is allowed in general. Otherwise, a session using this
     * credential shall be established and I2CM commands shall be sent
     * within this session. */
    kKOSE_AppletResID_I2CM_ACCESS = 0x7FFF0208,
    /** An authentication object which grants access to the
    * SetLockState command */
    kKOSE_AppletResID_RESTRICT = 0x7FFF020A,
    /** SPAKE2P_M_P256_UNCOMPRESSED KEY*/
    kKOSE_AppletResID_SPAKE2P_M_P256_UNCOMPRESSED = 0x7FFF0210,
    /** SPAKE2P_N_P256_UNCOMPRESSED KEY*/
    kKOSE_AppletResID_SPAKE2P_N_P256_UNCOMPRESSED = 0x7FFF0211,
    /** SPAKE2P_M_P384_UNCOMPRESSED KEY*/
    kKOSE_AppletResID_SPAKE2P_M_P384_UNCOMPRESSED = 0x7FFF0212,
    /** SPAKE2P_N_P384_UNCOMPRESSED KEY*/
    kKOSE_AppletResID_SPAKE2P_N_P384_UNCOMPRESSED = 0x7FFF0213,
    /** SPAKE2P_M_P521_UNCOMPRESSED KEY*/
    kKOSE_AppletResID_SPAKE2P_M_P521_UNCOMPRESSED = 0x7FFF0214,
    /** SPAKE2P_N_P521_UNCOMPRESSED KEY*/
    kKOSE_AppletResID_SPAKE2P_N_P521_UNCOMPRESSED = 0x7FFF0215,

} KOSE_AppletResID_t;

/** Mapping of 2 byte return code */
typedef enum
{
    /** Invalid */
    kKOSE_SW12_NA = 0,
    /** No Error */
    kKOSE_SW12_NO_ERROR = 0x9000,
    /** Conditions not satisfied */
    kKOSE_SW12_CONDITIONS_NOT_SATISFIED = 0x6985,
    /** Security status not satisfied. */
    kKOSE_SW12_SECURITY_STATUS = 0x6982,
    /** Wrong data provided. */
    kKOSE_SW12_WRONG_DATA = 0x6A80,
    /** Data invalid - policy set invalid for the given object */
    kKOSE_SW12_DATA_INVALID = 0x6984,
    /** Command not allowed - access denied based on object policy */
    kKOSE_SW12_COMMAND_NOT_ALLOWED = 0x6986,
} KOSE_SW12_t;

#if 0
/** Values for INS in ISO7816 APDU */
typedef enum
{
    /** Invalid */
    kKOSE_INS_NA = 0,
    /** 3 MSBit for instruction characteristics. */
    kKOSE_INS_MASK_INS_CHAR = 0xE0,
    /** 5 LSBit for instruction */
    kKOSE_INS_MASK_INSTRUCTION = 0x1F,

    /** Mask for transient object creation, can only be combined with INS_WRITE. */
    kKOSE_INS_TRANSIENT = 0x80,
    /** Mask for authentication object creation, can only be combined with INS_WRITE */
    kKOSE_INS_AUTH_OBJECT = 0x40,
    /** Mask for getting attestation data. */
    kKOSE_INS_ATTEST = 0x20,

    /** Write or create a persistent object. */
    kKOSE_INS_WRITE = 0x01,
    /** Read the object */
    kKOSE_INS_READ = 0x02,
    /** Perform Security Operation */
    kKOSE_INS_CRYPTO = 0x03,
    /** General operation */
    kKOSE_INS_MGMT = 0x04,
    /** Process session command */
    kKOSE_INS_PROCESS = 0x05,
} KOSE_INS_t;
#endif



/** Data for available memory */
typedef enum
{
    /** Invalid */
    kKOSE_MemoryType_NA = 0,
    /** Persistent memory */
    kKOSE_MemoryType_PERSISTENT = 0x01,
    /** Transient memory, clear on reset */
    kKOSE_MemoryType_TRANSIENT_RESET = 0x02,
    /** Transient memory, clear on deselect */
    kKOSE_MemoryType_TRANSIENT_DESELECT = 0x03,
} KOSE_MemoryType_t;

/** Where was this object originated */
typedef enum
{
    /** Invalid */
    kKOSE_Origin_NA = 0,
    /** Generated outside the module. */
    kKOSE_Origin_EXTERNAL = 0x01,
    /** Generated inside the module. */
    kKOSE_Origin_INTERNAL = 0x02,
    /** Trust provisioned by NXP */
    kKOSE_Origin_PROVISIONED = 0x03,
} KOSE_Origin_t;

/** Different TAG Values to talk to KOSE IoT Applet */
typedef enum
{
    /** Invalid */
    kKOSE_TAG_NA = 0,
    kKOSE_TAG_SESSION_ID = 0x10,
    kKOSE_TAG_POLICY = 0x11,
    kKOSE_TAG_MAX_ATTEMPTS = 0x12,
    kKOSE_TAG_IMPORT_AUTH_DATA = 0x13,
    kKOSE_TAG_IMPORT_AUTH_KEY_ID = 0x14,
    kKOSE_TAG_POLICY_CHECK = 0x15,

    kKOSE_TAG_SELECT = 0x31,
    kKOSE_TAG_RANDOM = 0x41,

    //kKOSE_TAG_1 = 0x41,
    kKOSE_TAG_2 = 0x42,
    kKOSE_TAG_3 = 0x43,
    kKOSE_TAG_4 = 0x44,
    kKOSE_TAG_5 = 0x45,
    kKOSE_TAG_6 = 0x46,
    kKOSE_TAG_7 = 0x47,
    kKOSE_TAG_8 = 0x48,
    kKOSE_TAG_9 = 0x49,
    kKOSE_TAG_10 = 0x4A,
    kKOSE_TAG_11 = 0x4B,
#if KSS_HAVE_KOSE_VER_GTE_07_02
    kKOSE_TAG_TIMESTAMP = 0x4F,
    kKOSE_TAG_SIGNATURE = 0x52,
#endif
    kKOSE_GP_TAG_CONTRL_REF_PARM = 0xA6,
    kKOSE_GP_TAG_AID = 0x4F,
    kKOSE_GP_TAG_KEY_TYPE = 0x80,
    kKOSE_GP_TAG_KEY_LEN = 0x81,
    kKOSE_GP_TAG_GET_DATA = 0x83,
    kKOSE_GP_TAG_DR_SE = 0x85,
    kKOSE_GP_TAG_RECEIPT = 0x86,
    kKOSE_GP_TAG_SCP_PARMS = 0x90,

#if KSS_HAVE_APPLET_SE051_UWB
    /** FiRaLite applet specific Tags */
    kKOSE_FIRALITE_OID_TAG = 0x06,
    kKOSE_FIRALITE_OPTSA_TAG = 0x80,
    kKOSE_FIRALITE_SESSION_ID_TAG = 0x80,
    kKOSE_FIRALITE_DISPATCH_TAG = 0x81,
    kKOSE_FIRALITE_TUNNEL_TAG = 0x81,
    kKOSE_FIRALITE_PROPRIETARY_CMD_TAG = 0x70,
    kKOSE_FIRALITE_TAG_FCI_TEMPLATE = 0x6F,
    kKOSE_FIRALITE_TAG_PROP_RSP_TEMPLATE = 0x71,
    kKOSE_FIRALITE_TAG_STATUS = 0x80,
    kKOSE_FIRALITE_TAG_NOTIFICATION_FORMAT = 0x80,
    kKOSE_FIRALITE_TAG_COMMAND_OR_RESPONSE = 0x81,
    kKOSE_FIRALITE_TAG_EVENT_ID = 0x81,
    kKOSE_FIRALITE_TAG_EVENT_DATA = 0x82,
    kKOSE_FIRALITE_TAG_AID = 0x84,
    kKOSE_FIRALITE_TAG_PROPRIETARY = 0x85,
    kKOSE_FIRALITE_TAG_NOTIFICATION = 0xE1,

    /* Wrapp Data specific Tags*/
    kKOSE_SUS_TAG_RANGING_SESSION_KEY = 0xC0,
    kKOSE_SUS_TAG_RESPONDER_RANGING_KEY,
    kKOSE_SUS_TAG_PROXIMITY_DISTANCE,
    kKOSE_SUS_TAG_ANGLE_OF_ARRIVAL,
    kKOSE_SUS_TAG_CLIENT_DATA,
    kKOSE_SUS_TAG_TRANSACTION_IDENTIFIER,
    kKOSE_SUS_TAG_KEY_IDENTIFIER,
    kKOSE_SUS_TAG_ARIBTARY_DATA,
    kKOSE_SUS_TAG_FINALIZATION_APPLET_AID = 0XCE,
    kKOSE_SUS_TAG_SESSION_ID,
    kKOSE_SUS_TAG_RANDOM_NUM = 0xD0,
    kKOSE_SUS_TAG_WRDS,
#endif
} KOSE_TAG_t;

#ifndef __DOXYGEN__
#define kKOSE_TAG_GP_CONTRL_REF_PARM kKOSE_GP_TAG_CONTRL_REF_PARM
#endif

/** Different signature algorithms for EC */
typedef enum
{
    /** Invalid */
    kKOSE_ECSignatureAlgo_NA = 0,
    /** NOT SUPPORTED */
    kKOSE_ECSignatureAlgo_PLAIN = 0x09,
    kKOSE_ECSignatureAlgo_SHA = 0x11,
    kKOSE_ECSignatureAlgo_SHA_224 = 0x25,
    kKOSE_ECSignatureAlgo_SHA_256 = 0x21,
    kKOSE_ECSignatureAlgo_SHA_384 = 0x22,
    kKOSE_ECSignatureAlgo_SHA_512 = 0x26,
} KOSE_ECSignatureAlgo_t;

/** Different signature algorithms for ED */
typedef enum
{
    /** Invalid */
    kKOSE_EDSignatureAlgo_NA = 0,
    /** Message input must be plain Data. Pure EDDSA algorithm */
    kKOSE_EDSignatureAlgo_ED25519PURE_SHA_512 = 0xA3,
} KOSE_EDSignatureAlgo_t;

/** Different ECDH algorithms */
typedef enum
{
    /** Invalid */
    kKOSE_ECDHAlgo_NA = 0,
    /** Generates the SHA1 of the X coordinate. */
    kKOSE_ECDHAlgo_EC_SVDP_DH = 0x01,
    /** Generates the X coordinate. */
    kKOSE_ECDHAlgo_EC_SVDP_DH_PLAIN = 0x03,
} KOSE_ECDHAlgo_t;

/** Different signature algorithms for RSA */
typedef enum
{
    /** Invalid */
    kKOSE_RSASignatureAlgo_NA = 0,
    /** RFC8017: RSASSA-PSS */
    kKOSE_RSASignatureAlgo_SHA1_PKCS1_PSS = 0x15,
    /** RFC8017: RSASSA-PSS */
    kKOSE_RSASignatureAlgo_SHA224_PKCS1_PSS = 0x2B,
    /** RFC8017: RSASSA-PSS */
    kKOSE_RSASignatureAlgo_SHA256_PKCS1_PSS = 0x2C,
    /** RFC8017: RSASSA-PSS */
    kKOSE_RSASignatureAlgo_SHA384_PKCS1_PSS = 0x2D,
    /** RFC8017: RSASSA-PSS */
    kKOSE_RSASignatureAlgo_SHA512_PKCS1_PSS = 0x2E,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    kKOSE_RSASignatureAlgo_SHA1_PKCS1 = 0x0A,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    kKOSE_RSASignatureAlgo_SHA_224_PKCS1 = 0x27,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    kKOSE_RSASignatureAlgo_SHA_256_PKCS1 = 0x28,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    kKOSE_RSASignatureAlgo_SHA_384_PKCS1 = 0x29,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    kKOSE_RSASignatureAlgo_SHA_512_PKCS1 = 0x2A,
} KOSE_RSASignatureAlgo_t;

/** Different encryption/decryption algorithms for RSA */
typedef enum
{
    /** Invalid */
    kKOSE_RSAEncryptionAlgo_NA = 0,
    /** Plain RSA, padding required on host. */
    kKOSE_RSAEncryptionAlgo_NO_PAD = 0x0C,
    /** RFC8017: RSAES-PKCS1-v1_5 */
    kKOSE_RSAEncryptionAlgo_PKCS1 = 0x0A,
    /** RFC8017: RSAES-OAEP */
    kKOSE_RSAEncryptionAlgo_PKCS1_OAEP = 0x0F,
} KOSE_RSAEncryptionAlgo_t;

/** Size of RSA Key Objects  */
typedef enum
{
    /** Invalid */
    kKOSE_RSABitLength_NA = 0,
    kKOSE_RSABitLength_512 = 512,
    kKOSE_RSABitLength_1024 = 1024,
    kKOSE_RSABitLength_1152 = 1152,
    kKOSE_RSABitLength_2048 = 2048,
    kKOSE_RSABitLength_3072 = 3072,
    kKOSE_RSABitLength_4096 = 4096,
} KOSE_RSABitLength_t;

/** Part of the RSA Key Objects  */
typedef enum
{
    /** Invalid */
    kKOSE_RSAKeyComponent_NA = 0xFF,
    /** Modulus */
    kKOSE_RSAKeyComponent_MOD = 0x00,
    /** Public key exponent */
    kKOSE_RSAKeyComponent_PUB_EXP = 0x01,
    /** Private key exponent */
    kKOSE_RSAKeyComponent_PRIV_EXP = 0x02,
    /** CRT component p */
    kKOSE_RSAKeyComponent_P = 0x03,
    /** CRT component q */
    kKOSE_RSAKeyComponent_Q = 0x04,
    /** CRT component dp */
    kKOSE_RSAKeyComponent_DP = 0x05,
    /** CRT component dq */
    kKOSE_RSAKeyComponent_DQ = 0x06,
    /** CRT component q_inv */
    kKOSE_RSAKeyComponent_INVQ = 0x07,
} KOSE_RSAKeyComponent_t;

/** Hashing/Digest algorithms */
typedef enum
{
    /** Invalid */
    kKOSE_DigestMode_NA = 0,
    kKOSE_DigestMode_NO_HASH = 0x00,
    kKOSE_DigestMode_SHA = 0x01,
    /** Not supported */
    kKOSE_DigestMode_SHA224 = 0x07,
    kKOSE_DigestMode_SHA256 = 0x04,
    kKOSE_DigestMode_SHA384 = 0x05,
    kKOSE_DigestMode_SHA512 = 0x06,
} KOSE_DigestMode_t;

/** HMAC/CMAC Algorithms  */
typedef enum
{
    /** Invalid */
    kKOSE_MACAlgo_NA = 0,
    kKOSE_MACAlgo_HMAC_SHA1 = 0x18,
    kKOSE_MACAlgo_HMAC_SHA256 = 0x19,
    kKOSE_MACAlgo_HMAC_SHA384 = 0x1A,
    kKOSE_MACAlgo_HMAC_SHA512 = 0x1B,
    kKOSE_MACAlgo_CMAC_128 = 0x31,
    kKOSE_MACAlgo_DES_CMAC8 = 0x7A,
} KOSE_MACAlgo_t;

/** AEAD Algorithms */
typedef enum
{
    /** Invalid */
    kKOSE_AeadAlgo_NA = 0,
    kKOSE_AeadGCMAlgo = 0xB0,
    kKOSE_AeadGCM_IVAlgo = 0xF3,
    kKOSE_AeadCCMAlgo = 0xF4,
} KOSE_AeadAlgo_t;

/** PAKE Mode */
typedef enum
{
    /** Invalid */
    kKOSE_SPAKE2PLUS_NA = 0,
    kKOSE_SPAKE2PLUS_P256_SHA256_HKDF_HMAC = 0x01,
    kKOSE_SPAKE2PLUS_P256_SHA512_HKDF_HMAC = 0x02,
    kKOSE_SPAKE2PLUS_P384_SHA256_HKDF_HMAC = 0x03,
    kKOSE_SPAKE2PLUS_P384_SHA512_HKDF_HMAC = 0x04,
    kKOSE_SPAKE2PLUS_P521_SHA512_HKDF_HMAC = 0x05,
    //kKOSE_SPAKE2PLUS_ED25519_SHA256_HKDF_HMAC = 0x06, //Not supported
    //kKOSE_SPAKE2PLUS_ED448_SHA512_HKDF_HMAC = 0x07, //Not supported
    kKOSE_SPAKE2PLUS_P256_SHA256_HKDF_CMAC = 0x08,
    kKOSE_SPAKE2PLUS_P256_SHA512_HKDF_CMAC = 0x09,
} KOSE_PAKEMode_t;

/** PAKE State */
typedef enum
{
    kKOSE_PAKE_STATE_SETUP = 0,
    kKOSE_PAKE_STATE_KEY_SHARE_GENERATED = 0xA5,
    kKOSE_PAKE_STATE_SESSION_KEYS_GENERATED = 0x5A,
} KOSE_PAKEState_t;

/** HKDF Mode */
typedef enum
{
    /** Invalid */
    kKOSE_HkdfMode_NA = 0x00,
    kKOSE_HkdfMode_ExtractExpand = 0x01,
    kKOSE_HkdfMode_ExpandOnly = 0x02,
} KOSE_HkdfMode_t;


/** ECC Curve Identifiers */
typedef enum
{
    /** Invalid */
    kKOSE_ECCurve_NA = 0x00,
    kKOSE_ECCurve_NIST_P192 = 0x01,
    kKOSE_ECCurve_NIST_P224 = 0x02,
    kKOSE_ECCurve_NIST_P256 = 0x03,
    kKOSE_ECCurve_NIST_P384 = 0x04,
    kKOSE_ECCurve_NIST_P521 = 0x05,
    kKOSE_ECCurve_Brainpool160 = 0x06,
    kKOSE_ECCurve_Brainpool192 = 0x07,
    kKOSE_ECCurve_Brainpool224 = 0x08,
    kKOSE_ECCurve_Brainpool256 = 0x09,
    kKOSE_ECCurve_Brainpool320 = 0x0A,
    kKOSE_ECCurve_Brainpool384 = 0x0B,
    kKOSE_ECCurve_Brainpool512 = 0x0C,
    kKOSE_ECCurve_Secp160k1 = 0x0D,
    kKOSE_ECCurve_Secp192k1 = 0x0E,
    kKOSE_ECCurve_Secp224k1 = 0x0F,
    kKOSE_ECCurve_Secp256k1 = 0x10,
    kKOSE_ECCurve_TPM_ECC_BN_P256 = 0x11,
    /** Not Weierstrass */
    kKOSE_ECCurve_ECC_ED_25519 = 0x40,
    kKOSE_ECCurve_ECC_MONT_DH_25519 = 0x41,
    /** Not Weierstrass */
    kKOSE_ECCurve_ECC_MONT_DH_448 = 0x43,
} KOSE_ECCurve_t;

#ifndef __DOXYGEN__

/** Same as kKOSE_ECCurve_TPM_ECC_BN_P256 */
#define kKOSE_ECCurve_RESERVED_ID_ECC_ED_25519 kKOSE_ECCurve_ECC_ED_25519
#define kKOSE_ECCurve_RESERVED_ID_ECC_MONT_DH_25519 kKOSE_ECCurve_ECC_MONT_DH_25519
#if KSS_HAVE_KOSE_VER_GTE_07_02
#define kKOSE_ECCurve_RESERVED_ID_ECC_MONT_DH_448 kKOSE_ECCurve_ECC_MONT_DH_448
#endif
#define kKOSE_ECCurve_Total_Weierstrass_Curves kKOSE_ECCurve_TPM_ECC_BN_P256
#endif

/** Parameters while setting the curve */
typedef enum
{   /** Invalid */
    kKOSE_ECCurveParam_NA = 0,
    kKOSE_ECCurveParam_PARAM_A = 0x01,
    kKOSE_ECCurveParam_PARAM_B = 0x02,
    kKOSE_ECCurveParam_PARAM_G = 0x04,
    kKOSE_ECCurveParam_PARAM_N = 0x08,
    kKOSE_ECCurveParam_PARAM_PRIME = 0x10,
} KOSE_ECCurveParam_t;

/** Symmetric cipher modes */
typedef enum
{
    /** Invalid */
    kKOSE_CipherMode_NA = 0,
    /** Typically using DESKey identifiers */
    kKOSE_CipherMode_DES_CBC_NOPAD = 0x01,
    /** Typically using DESKey identifiers */
    kKOSE_CipherMode_DES_CBC_ISO9797_M1 = 0x02,
    /** Typically using DESKey identifiers */
    kKOSE_CipherMode_DES_CBC_ISO9797_M2 = 0x03,
    /** NOT SUPPORTED */
    kKOSE_CipherMode_DES_CBC_PKCS5 = 0x04,
    /** Typically using DESKey identifiers */
    kKOSE_CipherMode_DES_ECB_NOPAD = 0x05,
    /** NOT SUPPORTED */
    kKOSE_CipherMode_DES_ECB_ISO9797_M1 = 0x06,
    /** NOT SUPPORTED */
    kKOSE_CipherMode_DES_ECB_ISO9797_M2 = 0x07,
    /** NOT SUPPORTED */
    kKOSE_CipherMode_DES_ECB_PKCS5 = 0x08,
    /** Typically using AESKey identifiers */
    kKOSE_CipherMode_AES_ECB_NOPAD = 0x0E,
    /** Typically using AESKey identifiers */
    kKOSE_CipherMode_AES_CBC_NOPAD = 0x0D,
    /** Typically using AESKey identifiers */
    kKOSE_CipherMode_AES_CBC_ISO9797_M1 = 0x16,
    /** Typically using AESKey identifiers */
    kKOSE_CipherMode_AES_CBC_ISO9797_M2 = 0x17,
    /** NOT SUPPORTED */
    kKOSE_CipherMode_AES_CBC_PKCS5 = 0x18,
    /** Typically using AEAD GCM mode */
    kKOSE_CipherMode_AES_GCM = 0xB0,
    /** Typically using AESKey identifiers */
    kKOSE_CipherMode_AES_CTR = 0xF0,
    /** Typically using AESKey CTR mode with internal IV Gen */
    /** Only used by MW. Change to kKOSE_CipherMode_AES_CTR when sending to SE */
    kKOSE_CipherMode_AES_CTR_INT_IV = 0xF1,
    /** Typically using AEAD GCM with internal IV Gen */
    kKOSE_CipherMode_AES_GCM_INT_IV = 0xF3,
    /** Typically using AEAD CCM mode */
    kKOSE_CipherMode_AES_CCM = 0xF4,
    /** Typically using AEAD CCM with internal IV Gen */
    kKOSE_CipherMode_AES_CCM_INT_IV = 0xF5,
} KOSE_CipherMode_t;

/** Features which are available / enabled in the Applet */
typedef enum {
    /** Invalid */
    kKOSE_AppletConfig_NA = 0,
    /** EC DSA and DH support */
    kKOSE_AppletConfig_ECDSA_ECDH_ECDHE = 0x0002,
    /** Use of curve RESERVED_ID_ECC_ED_25519 */
    kKOSE_AppletConfig_EDDSA = 0x0004,
    /** Use of curve RESERVED_ID_ECC_MONT_DH_25519 */
    kKOSE_AppletConfig_DH_MONT = 0x0008,
    /** Writing HMACKey objects */
    kKOSE_AppletConfig_HMAC = 0x0010,
    /** Writing RSAKey objects */
    kKOSE_AppletConfig_RSA_PLAIN = 0x0020,
    /** Writing RSAKey objects */
    kKOSE_AppletConfig_RSA_CRT = 0x0040,
    /** Writing AESKey objects */
    kKOSE_AppletConfig_AES = 0x0080,
    /** Writing DESKey objects */
    kKOSE_AppletConfig_DES = 0x0100,
    /** PBKDF2 */
    kKOSE_AppletConfig_PBKDF = 0x0200,
    /** TLS Handshake support commands (see 4.16) in APDU Spec*/
    kKOSE_AppletConfig_TLS = 0x0400,
    /** Mifare DESFire support (see 4.15)  in APDU Spec*/
    kKOSE_AppletConfig_MIFARE = 0x0800,
    /** RFU1 */
    kKOSE_AppletConfig_RFU1 = 0x1000,
    /** I2C Master support (see 4.17)  in APDU Spec*/
    kKOSE_AppletConfig_I2CM = 0x2000,
    /** RFU2 */
    kKOSE_AppletConfig_RFU2 = 0x4000,
} KOSE_AppletConfig_t;

/** Transient / Persistent lock */
typedef enum
{
    /** Invalid */
    kKOSE_LockIndicator_NA = 0,
    kKOSE_LockIndicator_TRANSIENT_LOCK = 0x01,
    kKOSE_LockIndicator_PERSISTENT_LOCK = 0x02,
} KOSE_LockIndicator_t;

/**
 * Applet >= 4.4
 *
 * See @ref Se05x_API_DisableObjCreation */
typedef enum
{
    kKOSE_RestrictMode_NA = 0,
    kKOSE_RestrictMode_RESTRICT_NEW = 0x01,
    kKOSE_RestrictMode_RESTRICT_ALL = 0x02,
} KOSE_RestrictMode_t;

/**
 * Lock the sample (until unlocked )
 */
typedef enum
{
    /** Invalid */
    kKOSE_LockState_NA = 0,
    kKOSE_LockState_LOCKED = 0x01,
    //    kKOSE_LockState_UNLOCKED = Any except 0x01,
} KOSE_LockState_t;

/** Cryptographic context for operation */
typedef enum
{
    /** Invalid */
    kKOSE_CryptoContext_NA = 0,
    /** For DigestInit/DigestUpdate/DigestFinal */
    kKOSE_CryptoContext_DIGEST = 0x01,
    /** For CipherInit/CipherUpdate/CipherFinal */
    kKOSE_CryptoContext_CIPHER = 0x02,
    /** For MACInit/MACUpdate/MACFinal */
    kKOSE_CryptoContext_SIGNATURE = 0x03,
    /** For AEADInit/AEADUpdate/AEADFinal */
    kKOSE_CryptoContext_AEAD = 0x04,
    /** For PAKE */
    kKOSE_CryptoContext_PAKE = 0x05,
} KOSE_CryptoContext_t;

/** Result of operations */
typedef enum
{
    /** Invalid */
    kKOSE_Result_NA = 0,
    kKOSE_Result_SUCCESS = 0x01,
    kKOSE_Result_FAILURE = 0x02,
} KOSE_Result_t;

/** Whether object is transient or persistent */
typedef enum
{
    /** Invalid */
    kKOSE_TransientIndicator_NA = 0,
    kKOSE_TransientIndicator_PERSISTENT = 0x01,
    kKOSE_TransientIndicator_TRANSIENT = 0x02,
} KOSE_TransientIndicator_t;

/** Whether object attribute is set */
typedef enum
{
    /** Invalid */
    kKOSE_SetIndicator_NA = 0,
    kKOSE_SetIndicator_NOT_SET = 0x01,
    kKOSE_SetIndicator_SET = 0x02,
} KOSE_SetIndicator_t;

/** When there are more entries yet to be fetched from few of the APIs */
typedef enum
{
    /** Invalid */
    kKOSE_MoreIndicator_NA = 0,
    /** No more data available */
    kKOSE_MoreIndicator_NO_MORE = 0x01,
    /** More data available */
    kKOSE_MoreIndicator_MORE = 0x02,
} KOSE_MoreIndicator_t;

#if KSS_HAVE_KOSE_VER_GTE_07_02
/** Health check */
typedef enum
{
    /** Invalid */
    kKOSE_HealthCheckMode_NA = 0,
    /** Performs all on-demand self-tests. Can only be done when
     * the module is in FIPS mode. When the test fails, the chip
     * goes into TERMINATED state. */
    kKOSE_HealthCheckMode_FIPS = 0xF906,
    /** Performs ROM integrity checks. When the test fails, the chip
     * triggers the attack counter and the chip will reset. */
    kKOSE_HealthCheckMode_CODE_SIGNATURE = 0xFE01,
    /** Performs flash integrity tests. When the test fails, the chip
     * triggers the attack counter and the chip will reset. */
    kKOSE_HealthCheckMode_DYNAMIC_FLASH_INTEGRITY = 0xFD02,
    /** Performs tests on the active shield protection of the
     * hardware. When the test fails, the chip triggers the attack
     * counter and the chip will reset. */
    kKOSE_HealthCheckMode_SHIELDING = 0xFC03,
    /** Performs self-tests on hardware sensors and reports the
     * status. */
    kKOSE_HealthCheckMode_SENSOR = 0xFB04,
    /** Performs self-tests on the hardware registers. When the test
     * fails, the chip triggers the attack counter and the chip will
     * reset. */
    kKOSE_HealthCheckMode_SFR_CHECK = 0xFA05,
} KOSE_HealthCheckMode_t;
#endif

/** Mandate platform SCP or not */
typedef enum
{
    /** Invalid */
    kKOSE_PlatformSCPRequest_NA = 0,
    /** Platform SCP is required (full enc & MAC) */
    kKOSE_PlatformSCPRequest_REQUIRED = 0x01,
    /** No platform SCP required. */
    kKOSE_PlatformSCPRequest_NOT_REQUIRED = 0x02,
} KOSE_PlatformSCPRequest_t;

/** Crypto object identifiers */
typedef enum
{
    /** Invalid */
    kKOSE_CryptoObject_NA = 0,
    kKOSE_CryptoObject_DIGEST_SHA,
    kKOSE_CryptoObject_DIGEST_SHA224,
    kKOSE_CryptoObject_DIGEST_SHA256,
    kKOSE_CryptoObject_DIGEST_SHA384,
    kKOSE_CryptoObject_DIGEST_SHA512,
    kKOSE_CryptoObject_DES_CBC_NOPAD,
    kKOSE_CryptoObject_DES_CBC_ISO9797_M1,
    kKOSE_CryptoObject_DES_CBC_ISO9797_M2,
    kKOSE_CryptoObject_DES_CBC_PKCS5,
    kKOSE_CryptoObject_DES_ECB_NOPAD,
    kKOSE_CryptoObject_DES_ECB_ISO9797_M1,
    kKOSE_CryptoObject_DES_ECB_ISO9797_M2,
    kKOSE_CryptoObject_DES_ECB_PKCS5,
    kKOSE_CryptoObject_AES_ECB_NOPAD,
    kKOSE_CryptoObject_AES_CBC_NOPAD,
    kKOSE_CryptoObject_AES_CBC_ISO9797_M1,
    kKOSE_CryptoObject_AES_CBC_ISO9797_M2,
    kKOSE_CryptoObject_AES_CBC_PKCS5,
    kKOSE_CryptoObject_AES_CTR,
    kKOSE_CryptoObject_AES_CTR_INT_IV,
    kKOSE_CryptoObject_HMAC_SHA1,
    kKOSE_CryptoObject_HMAC_SHA256,
    kKOSE_CryptoObject_HMAC_SHA384,
    kKOSE_CryptoObject_HMAC_SHA512,
    kKOSE_CryptoObject_CMAC_128,
    kKOSE_CryptoObject_AES_GCM,
    kKOSE_CryptoObject_AES_GCM_INT_IV,
    kKOSE_CryptoObject_AES_CCM,
    kKOSE_CryptoObject_AES_CCM_INT_IV,
	kKOSE_CryptoObject_PAKE_TYPE_A,
    kKOSE_CryptoObject_PAKE_TYPE_B,
	kKOSE_CryptoObject_End,
} KOSE_CryptoObject_t;

/** @copydoc KOSE_CryptoObject_t */
#define KOSE_CryptoObjectID_t KOSE_CryptoObject_t

/** SPAKE device type */
typedef enum
{
    /** Invalid */
    kKOSE_SPAKE2PLUS_DEVICE_TYPE_UNKNOWN = 0,
    /** Spake device commionsioner */
    KOSE_SPAKE2PLUS_DEVICE_TYPE_A = 1,
    /** Spake device Node/accessory */
    KOSE_SPAKE2PLUS_DEVICE_TYPE_B = 2,
}KOSE_SPAKE2PlusDeviceType_t;


/** Maximum number of session supported by SE050 */
#define SE050_MAX_NUMBER_OF_SESSIONS 2
/** Maximum number of session supported by SE050 */
#define SE050_OBJECT_IDENTIFIER_SIZE 4
/** How many bytes can be used for buffer for I2C Master interface */
#define SE050_MAX_I2CM_COMMAND_LENGTH 255
/**
 * the maximum APDU payload length will be smaller, depending on which protocol applies, etc.
 */
#define SE050_MAX_APDU_PAYLOAD_LENGTH 892
//#define SE050_DEFAULT_MAX_ATTEMPTS 10

/** 3 MSBit for instruction characteristics. */
#define SE050_INS_MASK_INS_CHAR 0xE0
/** 5 LSBit for instruction */
#define SE050_INS_MASK_INSTRUCTION 0x1F

/** Type of Object */
typedef enum
{
    /**  */
    kKOSE_SecObjTyp_NA = 0x00,
    /**  */
    kKOSE_SecObjTyp_EC_KEY_PAIR = 0x01,
    /**  */
    kKOSE_SecObjTyp_EC_PRIV_KEY = 0x02,
    /**  */
    kKOSE_SecObjTyp_EC_PUB_KEY = 0x03,
    /**  */
    kKOSE_SecObjTyp_RSA_KEY_PAIR = 0x04,
    /**  */
    kKOSE_SecObjTyp_RSA_KEY_PAIR_CRT = 0x05,
    /**  */
    kKOSE_SecObjTyp_RSA_PRIV_KEY = 0x06,
    /**  */
    kKOSE_SecObjTyp_RSA_PRIV_KEY_CRT = 0x07,
    /**  */
    kKOSE_SecObjTyp_RSA_PUB_KEY = 0x08,
    /**  */
    kKOSE_SecObjTyp_AES_KEY = 0x09,
    /**  */
    kKOSE_SecObjTyp_DES_KEY = 0x0A,
    /**  */
    kKOSE_SecObjTyp_BINARY_FILE = 0x0B,
    /**  */
    kKOSE_SecObjTyp_UserID = 0x0C,
    /**  */
    kKOSE_SecObjTyp_COUNTER = 0x0D,
    /**  */
    kKOSE_SecObjTyp_PCR = 0x0F,
    /**  */
    kKOSE_SecObjTyp_CURVE = 0x10,
    /**  */
    kKOSE_SecObjTyp_HMAC_KEY = 0x11,
#if KSS_HAVE_KOSE_VER_GTE_07_02
    kKOSE_SecObjTyp_EC_KEY_PAIR_NIST_P192 = 0x21,
    kKOSE_SecObjTyp_EC_PRIV_KEY_NIST_P192 = 0x22,
    kKOSE_SecObjTyp_EC_PUB_KEY_NIST_P192 = 0x23,
    kKOSE_SecObjTyp_EC_KEY_PAIR_NIST_P224 = 0x25,
    kKOSE_SecObjTyp_EC_PRIV_KEY_NIST_P224 = 0x26,
    kKOSE_SecObjTyp_EC_PUB_KEY_NIST_P224 = 0x27,
    kKOSE_SecObjTyp_EC_KEY_PAIR_NIST_P256 = 0x29,
    kKOSE_SecObjTyp_EC_PRIV_KEY_NIST_P256 = 0x2A,
    kKOSE_SecObjTyp_EC_PUB_KEY_NIST_P256 = 0x2B,
    kKOSE_SecObjTyp_EC_KEY_PAIR_NIST_P384 = 0x2D,
    kKOSE_SecObjTyp_EC_PRIV_KEY_NIST_P384 = 0x2E,
    kKOSE_SecObjTyp_EC_PUB_KEY_NIST_P384 = 0x2F,
    kKOSE_SecObjTyp_EC_KEY_PAIR_NIST_P521 = 0x31,
    kKOSE_SecObjTyp_EC_PRIV_KEY_NIST_P521 = 0x32,
    kKOSE_SecObjTyp_EC_PUB_KEY_NIST_P521 = 0x33,
    kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool160 = 0x35,
    kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool160 = 0x36,
    kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool160 = 0x37,
    kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool192 = 0x39,
    kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool192 = 0x3A,
    kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool192 = 0x3B,
    kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool224 = 0x3D,
    kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool224 = 0x3E,
    kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool224 = 0x3F,
    kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool256 = 0x41,
    kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool256 = 0x42,
    kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool256 = 0x43,
    kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool320 = 0x45,
    kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool320 = 0x46,
    kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool320 = 0x47,
    kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool384 = 0x49,
    kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool384 = 0x4A,
    kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool384 = 0x4B,
    kKOSE_SecObjTyp_EC_KEY_PAIR_Brainpool512 = 0x4D,
    kKOSE_SecObjTyp_EC_PRIV_KEY_Brainpool512 = 0x4E,
    kKOSE_SecObjTyp_EC_PUB_KEY_Brainpool512 = 0x4F,
    kKOSE_SecObjTyp_EC_KEY_PAIR_Secp160k1 = 0x51,
    kKOSE_SecObjTyp_EC_PRIV_KEY_Secp160k1 = 0x52,
    kKOSE_SecObjTyp_EC_PUB_KEY_Secp160k1 = 0x53,
    kKOSE_SecObjTyp_EC_KEY_PAIR_Secp192k1 = 0x55,
    kKOSE_SecObjTyp_EC_PRIV_KEY_Secp192k1 = 0x56,
    kKOSE_SecObjTyp_EC_PUB_KEY_Secp192k1 = 0x57,
    kKOSE_SecObjTyp_EC_KEY_PAIR_Secp224k1 = 0x59,
    kKOSE_SecObjTyp_EC_PRIV_KEY_Secp224k1 = 0x5A,
    kKOSE_SecObjTyp_EC_PUB_KEY_Secp224k1 = 0x5B,
    kKOSE_SecObjTyp_EC_KEY_PAIR_Secp256k1 = 0x5D,
    kKOSE_SecObjTyp_EC_PRIV_KEY_Secp256k1 = 0x5E,
    kKOSE_SecObjTyp_EC_PUB_KEY_Secp256k1 = 0x5F,
    kKOSE_SecObjTyp_EC_KEY_PAIR_BN_P256 = 0x61,
    kKOSE_SecObjTyp_EC_PRIV_KEY_BN_P256 = 0x62,
    kKOSE_SecObjTyp_EC_PUB_KEY_BN_P256 = 0x63,
    kKOSE_SecObjTyp_EC_KEY_PAIR_ED25519 = 0x65,
    kKOSE_SecObjTyp_EC_PRIV_KEY_ED25519 = 0x66,
    kKOSE_SecObjTyp_EC_PUB_KEY_ED25519 = 0x67,
    kKOSE_SecObjTyp_EC_KEY_PAIR_MONT_DH_25519 = 0x69,
    kKOSE_SecObjTyp_EC_PRIV_KEY_MONT_DH_25519 = 0x6A,
    kKOSE_SecObjTyp_EC_PUB_KEY_MONT_DH_25519 = 0x6B,
    kKOSE_SecObjTyp_EC_KEY_PAIR_MONT_DH_448 = 0x71,
    kKOSE_SecObjTyp_EC_PRIV_KEY_MONT_DH_448 = 0x72,
    kKOSE_SecObjTyp_EC_PUB_KEY_MONT_DH_448 = 0x73,
#endif
} KOSE_SecObjTyp_t;

/** @copydoc KOSE_SecObjTyp_t */
typedef KOSE_SecObjTyp_t KOSE_SecureObjectType_t;


/** Algorithms for RSA Signature */
typedef enum
{
    /** Invalid */
    kKOSE_RSASignAlgo_NA = 0,
    /** RFC8017: RSASSA-PSS */
    kKOSE_RSASignAlgo_SHA1_PKCS1_PSS = 0x15,
    /** RFC8017: RSASSA-PSS */
    kKOSE_RSASignAlgo_SHA224_PKCS1_PSS = 0x2B,
    /** RFC8017: RSASSA-PSS */
    kKOSE_RSASignAlgo_SHA256_PKCS1_PSS = 0x2C,
    /** RFC8017: RSASSA-PSS */
    kKOSE_RSASignAlgo_SHA384_PKCS1_PSS = 0x2D,
    /** RFC8017: RSASSA-PSS */
    kKOSE_RSASignAlgo_SHA512_PKCS1_PSS = 0x2E,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    kKOSE_RSASignAlgo_SHA_224_PKCS1 = 0x27,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    kKOSE_RSASignAlgo_SHA_256_PKCS1 = 0x28,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    kKOSE_RSASignAlgo_SHA_384_PKCS1 = 0x29,
    /** RFC8017: RSASSA-PKCS1-v1_5 */
    kKOSE_RSASignAlgo_SHA_512_PKCS1 = 0x2A,
} KOSE_RSASignAlgo_t;

// typedef enum
// {
//     /** Plain RSA, padding required on host. */
//     kKOSE_RSAEncrAlgo_NO_PAD = 0x0C,
//     * RFC8017: RSAES-PKCS1-v1_5
//     kKOSE_RSAEncrAlgo_PKCS1 = 0x0A,
//     /** RFC8017: RSAES-OAEP */
//     kKOSE_RSAEncrAlgo_PKCS1_OAEP = 0x0F,
// } KOSE_RSAEncrAlgo_t;

/** Public part of RSA Keys */
typedef enum
{
    kKOSE_RSAPubKeyComp_NA = 0,
    kKOSE_RSAPubKeyComp_MOD = kKOSE_RSAKeyComponent_MOD,
    kKOSE_RSAPubKeyComp_PUB_EXP = kKOSE_RSAKeyComponent_PUB_EXP,
} KOSE_RSAPubKeyComp_t;

/** Cyrpto module subtype */
typedef union {
    /** In case it's digest */
    KOSE_DigestMode_t digest;
    /** In case it's cipher */
    KOSE_CipherMode_t cipher;
    /** In case it's mac */
    KOSE_MACAlgo_t mac;
    /** In case it's aead */
    KOSE_AeadAlgo_t aead;
    /** In case it's pake */
    KOSE_PAKEMode_t pakeMode;
    /** Accessing 8 bit value for APDUs */
    uint8_t union_8bit;
} KOSE_CryptoModeSubType_t;

/** @} */

/** @addtogroup se050_i2cm
 *
 * @{
 */
/** @brief I2C Master micro operation */
typedef enum
{
    kKOSE_TAG_I2CM_Config = 0x01,
    kKOSE_TAG_I2CM_Write = 0x03,
    kKOSE_TAG_I2CM_Read = 0x04,
} KOSE_I2CM_TAG_t;

/*!
*@}
*/ /* end of se050_i2cm */

/** @addtogroup se05x_types
 *
 * @{ */

/** Whether key is transient of persistent */
typedef enum
{
    kKOSE_TransientType_Persistent = 0,
    kKOSE_TransientType_Transient = kKOSE_INS_TRANSIENT,
} KOSE_TransientType_t;

/** Part of the asymmetric key */
typedef enum
{
    kKOSE_KeyPart_NA = kKOSE_P1_DEFAULT,
    /** Key pair (private key + public key) */
    kKOSE_KeyPart_Pair = kKOSE_P1_KEY_PAIR,
    /** Private key */
    kKOSE_KeyPart_Private = kKOSE_P1_PRIVATE,
    /** Public key */
    kKOSE_KeyPart_Public = kKOSE_P1_PUBLIC,
} KOSE_KeyPart_t;

/** Cipher Operation.
 *
 * Encrypt or decrypt */
typedef enum
{
    kKOSE_Cipher_Oper_NA = 0,
    kKOSE_Cipher_Oper_Encrypt = kKOSE_P2_ENCRYPT,
    kKOSE_Cipher_Oper_Decrypt = kKOSE_P2_DECRYPT,
} KOSE_Cipher_Oper_t;

/** One Shot operations helper */
typedef enum
{
    kKOSE_Cipher_Oper_OneShot_NA = 0,
    kKOSE_Cipher_Oper_OneShot_Encrypt = kKOSE_P2_ENCRYPT_ONESHOT,
    kKOSE_Cipher_Oper_OneShot_Decrypt = kKOSE_P2_DECRYPT_ONESHOT,
} KOSE_Cipher_Oper_OneShot_t;

/** MAC operations */
typedef enum
{
    kKOSE_Mac_Oper_NA = 0,
    kKOSE_Mac_Oper_Generate = kKOSE_P2_GENERATE,
    kKOSE_Mac_Oper_Validate = kKOSE_P2_VALIDATE,
} KOSE_Mac_Oper_t;

/** In case the read is attested */
typedef enum
{
    kKOSE_AttestationType_None = 0,
    //kKOSE_AttestationType_AUTH = kKOSE_INS_AUTH_OBJECT,
} KOSE_AttestationType_t;

/** Symmetric keys */
typedef enum
{
    kKOSE_SymmKeyType_NA = 0,
    kKOSE_SymmKeyType_AES = kKOSE_P1_AES,
    kKOSE_SymmKeyType_DES = kKOSE_P1_DES,
    kKOSE_SymmKeyType_HMAC = kKOSE_P1_HMAC,
    kKOSE_SymmKeyType_CMAC = kKOSE_P1_AES,
} KOSE_SymmKeyType_t;

/** @copydoc KOSE_AppletConfig_t */
typedef KOSE_AppletConfig_t KOSE_Variant_t;

/** TLS Perform PRF */
typedef enum
{
    kKOSE_TLS_PRF_NA = 0,
    kKOSE_TLS_PRF_CLI_HELLO = kKOSE_P2_TLS_PRF_CLI_HELLO,
    kKOSE_TLS_PRF_SRV_HELLO = kKOSE_P2_TLS_PRF_SRV_HELLO,
    kKOSE_TLS_PRF_CLI_RND = kKOSE_P2_TLS_PRF_CLI_RND,
    kKOSE_TLS_PRF_SRV_RND = kKOSE_P2_TLS_PRF_SRV_RND,
    kKOSE_TLS_PRF_BOTH = kKOSE_P2_TLS_PRF_BOTH,
} KOSE_TLSPerformPRFType_t;

/** Attestation */
typedef enum
{
    kKOSE_AttestationAlgo_NA = 0,
    kKOSE_AttestationAlgo_EC_PLAIN = kKOSE_ECSignatureAlgo_PLAIN,
    kKOSE_AttestationAlgo_EC_SHA = kKOSE_ECSignatureAlgo_SHA,
    kKOSE_AttestationAlgo_EC_SHA_224 = kKOSE_ECSignatureAlgo_SHA_224,
    kKOSE_AttestationAlgo_EC_SHA_256 = kKOSE_ECSignatureAlgo_SHA_256,
    kKOSE_AttestationAlgo_EC_SHA_384 = kKOSE_ECSignatureAlgo_SHA_384,
    kKOSE_AttestationAlgo_EC_SHA_512 = kKOSE_ECSignatureAlgo_SHA_512,
    kKOSE_AttestationAlgo_ED25519PURE_SHA_512 = kKOSE_EDSignatureAlgo_ED25519PURE_SHA_512,
    kKOSE_AttestationAlgo_RSA_SHA1_PKCS1_PSS = kKOSE_RSASignatureAlgo_SHA1_PKCS1_PSS,
    kKOSE_AttestationAlgo_RSA_SHA224_PKCS1_PSS = kKOSE_RSASignatureAlgo_SHA224_PKCS1_PSS,
    kKOSE_AttestationAlgo_RSA_SHA256_PKCS1_PSS = kKOSE_RSASignatureAlgo_SHA256_PKCS1_PSS,
    kKOSE_AttestationAlgo_RSA_SHA384_PKCS1_PSS = kKOSE_RSASignatureAlgo_SHA384_PKCS1_PSS,
    kKOSE_AttestationAlgo_RSA_SHA512_PKCS1_PSS = kKOSE_RSASignatureAlgo_SHA512_PKCS1_PSS,
    kKOSE_AttestationAlgo_RSA_SHA_224_PKCS1 = kKOSE_RSASignatureAlgo_SHA_224_PKCS1,
    kKOSE_AttestationAlgo_RSA_SHA_256_PKCS1 = kKOSE_RSASignatureAlgo_SHA_256_PKCS1,
    kKOSE_AttestationAlgo_RSA_SHA_384_PKCS1 = kKOSE_RSASignatureAlgo_SHA_384_PKCS1,
    kKOSE_AttestationAlgo_RSA_SHA_512_PKCS1 = kKOSE_RSASignatureAlgo_SHA_512_PKCS1,

} KOSE_AttestationAlgo_t;




/** T4T Access Control constants */
typedef enum
{
    /** Access_Control_Granted */
    kKOSE_AccessCtrl_Granted = 0x00,
    /** Access_Control_Denied */
    kKOSE_AccessCtrl_Denied = 0xFF,
    /** Access_Control_Locked */
    kKOSE_AccessCtrl_Locked = 0x80,
} KOSE_T4T_Access_Ctrl_t;

/** T4T Interface constants */
typedef enum
{
    /** Interface contact */
    kKOSE_Interface_Contact = 0x00,
    /** Interface contactless */
    kKOSE_Interface_Contactless = 0xFF,
} KOSE_T4T_Interface_Const_t;

/** T4T Operation constants */
typedef enum
{
    /** Operation read */
    kKOSE_Operation_Read = 0x00,
    /** Operation Wrire */
    kKOSE_Operation_Write = 0xFF,
} KOSE_T4T_Operation_Const_t;

/** T4T Read counter operation */
typedef enum
{
    /** Read Counter Reset */
    kKOSE_Read_Counter_Reset = 0x01,
    /** Read Counter Enable */
    kKOSE_Read_Counter_Enable = 0x02,
    /** Read Counter Disable */
    kKOSE_Read_Counter_Disable = 0x03,
} KOSE_T4T_Read_Ctr_Operation_t;


/** RSA Key format */
typedef enum
{
    kKOSE_RSAKeyFormat_CRT = kKOSE_P2_DEFAULT,
    kKOSE_RSAKeyFormat_RAW = kKOSE_P2_RAW,
} KOSE_RSAKeyFormat_t;

/** ECPMAlgo */
typedef enum
{
    kKOSE_ECPMAlgo_PACE_GM = 0x05,
    kKOSE_ECPMAlgo_SVDP_DH_PLAIN_XY = 0x06,
} KOSE_ECPMAlgo_t;

/** @copydoc KOSE_MACAlgo_t */
typedef KOSE_MACAlgo_t KOSE_MacOperation_t;

/** KOSE's key IDs */
typedef uint32_t KOSE_KeyID_t;
/** Case when there is no KEK */
#define KOSE_KeyID_KEK_NONE 0

/** [Optional: if the authentication key is the same as the key to be replaced, this TAG should not be present]. */
#define KOSE_KeyID_MFDF_NONE 0

/** KOSE key's max attempts */
typedef uint16_t KOSE_MaxAttemps_t;
/** Fall back to applet default */
#define KOSE_MaxAttemps_UNLIMITED 0
/** Identify in code that this is not an AUTH object and hence not applicable */
#define KOSE_MaxAttemps_NA 0

/** When we want to read with attestation */
#define kKOSE_INS_READ_With_Attestation (kKOSE_INS_READ | kKOSE_INS_ATTEST)

/** When we want to read I2CM Data with attestation */
#define kKOSE_INS_I2CM_Attestation (kKOSE_INS_CRYPTO | kKOSE_INS_ATTEST)

#ifndef __DOXYGEN__
/* RSA Helper Macros to make code little more readable */
#define KOSE_RSA_NO_p /* Skip */ NULL, 0
#define KOSE_RSA_NO_q /* Skip */ NULL, 0
#define KOSE_RSA_NO_dp /* Skip */ NULL, 0
#define KOSE_RSA_NO_dq /* Skip */ NULL, 0
#define KOSE_RSA_NO_qInv /* Skip */ NULL, 0
#define KOSE_RSA_NO_pubExp /* Skip */ NULL, 0
#define KOSE_RSA_NO_priv /* Skip */ NULL, 0
#define KOSE_RSA_NO_pubMod /* Skip */ NULL, 0
#endif // __DOXYGEN__


/*!
*@}
*/ /* end of se05x_types */
#endif

#endif /* KOSE_ENUMS_H */
