/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */
/** @file */
#ifndef _KONA_KSS_API_H_
#define _KONA_KSS_API_H_

#if !defined(KSS_CONFIG_FILE)
#include "kona_kss_kose_config.h"
#else
#include KSS_CONFIG_FILE
#endif

#include <stdio.h>

/** Version of the SSS API */
#define KSS_API_VERSION (0x00000001u)

/** Size of an AES Block, in bytes */
#define KSS_AES_BLOCK_SIZE (16u)
/** Size of a DES Block, in bytes */
#define KSS_DES_BLOCK_SIZE (8u)
/** Size of a DES Key, in bytes */
#define KSS_DES_KEY_SIZE (8u)
/** Size of a DES IV, in bytes */
#define KSS_DES_IV_SIZE (8u)
/**
 * @addtogroup kss_types
 * @{
 */

/** Status of the KSS APIs */
typedef enum
{
    /** Operation was successful */
    kStatus_KSS_Success = 0x5a5a5a5au,
    /** Operation failed */
    kStatus_KSS_Fail = 0x3c3c0000u,
    /** Operation not performed because some of the passed parameters
     * were found inappropriate */
    kStatus_KSS_InvalidArgument = 0x3c3c0001u,
    // LCOV_EXCL_START
    /** Where the underlying sub-system *supports* multi-threading,
     * Internal status to handle simultaneous access.
     *
     * This status is not expected to be returned to higher layers.
     * */
    kStatus_KSS_ResourceBusy = 0x3c3c0002u,
    // LCOV_EXCL_STOP
    /** APDU Throughput error */
    kStatus_KSS_ApduThroughputError = 0x3c3c0003u,
} kss_status_t;

/** Helper macro to set enum value */

#define KSS_ENUM(GROUP, INDEX) ((GROUP) | (INDEX))

/** Cryptographic sub system */
typedef enum
{
    kType_KSS_SubSystem_NONE,
    /** Software based */
    kType_KSS_Software = KSS_ENUM(0x01 << 8, 0x00),
    kType_KSS_mbedTLS  = KSS_ENUM(kType_KSS_Software, 0x01),
    kType_KSS_OpenSSL  = KSS_ENUM(kType_KSS_Software, 0x02),
    // LCOV_EXCL_START
    /** HOST HW Based */
    kType_KSS_HW   = KSS_ENUM(0x02 << 8, 0x00),
    kType_KSS_SECO = KSS_ENUM(kType_KSS_HW, 0x01),
    /** Isolated HW */
    kType_KSS_Isolated_HW = KSS_ENUM(0x04 << 8, 0x00),
    kType_KSS_Sentinel    = KSS_ENUM(kType_KSS_Isolated_HW, 0x01),
    kType_KSS_Sentinel200 = KSS_ENUM(kType_KSS_Isolated_HW, 0x02),
    kType_KSS_Sentinel300 = KSS_ENUM(kType_KSS_Isolated_HW, 0x03),
    kType_KSS_Sentinel400 = KSS_ENUM(kType_KSS_Isolated_HW, 0x04),
    kType_KSS_Sentinel500 = KSS_ENUM(kType_KSS_Isolated_HW, 0x05),
    // LCOV_EXCL_STOP
    /** Secure Element */
    kType_KSS_SecureElement = KSS_ENUM(0x08 << 8, 0x00),
    kType_KSS_SubSystem_LAST
} kss_type_t;

/** Destintion connection type */
typedef enum
{
    /* Plain => Lowest level of security requested.
     *       => Probably a system with no mechanism to *identify* who
     *          has opened the session from host
     *       => Probably a system with Easy for man in the middle attack.
     *
     */
    kKSS_ConnectionType_Plain,
    /* Password:
     *       => Some level of user authentication/identification requested
     *       => Probably a system with "static" authentication/identification.
     *       => Probably same Password us always.
     *       => "Password" mostly gets sent in plain over the communication layer
     *       => Probably a system with replay attack possible
     */
    kKSS_ConnectionType_Password,
    /* Encrypted:
     *    Communication is guaranteed to be Encrypted.
     *    For SE => This would mean highest level of authentication
     *    For other system => channel would be encrypted
     *
     *    In general, almost a level of security that is definitely higher than
     *    Plain/Password/PIN.
     *
     *    Using *Dynamic* Sessions Keys for authenticated communication.
     */
    kKSS_ConnectionType_Encrypted
} kss_connection_type_t;

#ifndef __DOXYGEN__

#define KSS_ALGORITHM_START_AES (0x00)
#define KSS_ALGORITHM_START_CHACHA (0x01)
#define KSS_ALGORITHM_START_DES (0x02)
#define KSS_ALGORITHM_START_SHA (0x03)
#define KSS_ALGORITHM_START_MAC (0x04)
#define KSS_ALGORITHM_START_DH (0x05)
#define KSS_ALGORITHM_START_DSA (0x06)
#define KSS_ALGORITHM_START_RSASSA_PKCS1_V1_5 (0x07)
#define KSS_ALGORITHM_START_RSASSA_PKCS1_PSS_MGF1 (0x08)
#define KSS_ALGORITHM_START_RSAES_PKCS1_OAEP (0x09)
#define KSS_ALGORITHM_START_RSAES_PKCS1_V1_5 (0x0A)
#define KSS_ALGORITHM_START_RSASSA_NO_PADDING (0x0B)
#define KSS_ALGORITHM_START_ECDSA (0x0C)

/* Not available outside this file */
#define KSS_ENUM_ALGORITHM(GROUP, INDEX) (((KSS_ALGORITHM_START_##GROUP) << 8) | (INDEX))

#endif

/** Cryptographic algorithm to be applied */
typedef enum /* _kss_algorithm */
{
    kAlgorithm_None,
    /* AES */
    kAlgorithm_KSS_AES_ECB        = KSS_ENUM_ALGORITHM(AES, 0x01),
    kAlgorithm_KSS_AES_CBC        = KSS_ENUM_ALGORITHM(AES, 0x02),
    kAlgorithm_KSS_AES_CTR        = KSS_ENUM_ALGORITHM(AES, 0x03),
    kAlgorithm_KSS_AES_GCM        = KSS_ENUM_ALGORITHM(AES, 0x04),
    kAlgorithm_KSS_AES_CCM        = KSS_ENUM_ALGORITHM(AES, 0x05),
    kAlgorithm_KSS_AES_GCM_INT_IV = KSS_ENUM_ALGORITHM(AES, 0x06),
    kAlgorithm_KSS_AES_CTR_INT_IV = KSS_ENUM_ALGORITHM(AES, 0x07),
    kAlgorithm_KSS_AES_CCM_INT_IV = KSS_ENUM_ALGORITHM(AES, 0x08),
    /* CHACHA_POLY */
    kAlgorithm_KSS_CHACHA_POLY = KSS_ENUM_ALGORITHM(CHACHA, 0x01),
    /* DES */
    kAlgorithm_KSS_DES_ECB            = KSS_ENUM_ALGORITHM(DES, 0x01),
    kAlgorithm_KSS_DES_CBC            = KSS_ENUM_ALGORITHM(DES, 0x02),
    kAlgorithm_KSS_DES_CBC_ISO9797_M1 = KSS_ENUM_ALGORITHM(DES, 0x05),
    kAlgorithm_KSS_DES_CBC_ISO9797_M2 = KSS_ENUM_ALGORITHM(DES, 0x06),
    /* DES3 */
    kAlgorithm_KSS_DES3_ECB            = KSS_ENUM_ALGORITHM(DES, 0x03),
    kAlgorithm_KSS_DES3_CBC            = KSS_ENUM_ALGORITHM(DES, 0x04),
    kAlgorithm_KSS_DES3_CBC_ISO9797_M1 = KSS_ENUM_ALGORITHM(DES, 0x07),
    kAlgorithm_KSS_DES3_CBC_ISO9797_M2 = KSS_ENUM_ALGORITHM(DES, 0x08),
    /* digest */
    /* doc:start hash_algo */
    kAlgorithm_KSS_SHA1   = KSS_ENUM_ALGORITHM(SHA, 0x01),
    kAlgorithm_KSS_SHA224 = KSS_ENUM_ALGORITHM(SHA, 0x02),
    kAlgorithm_KSS_SHA256 = KSS_ENUM_ALGORITHM(SHA, 0x03),
    kAlgorithm_KSS_SHA384 = KSS_ENUM_ALGORITHM(SHA, 0x04),
    kAlgorithm_KSS_SHA512 = KSS_ENUM_ALGORITHM(SHA, 0x05),
    /* doc:end hash_algo */

    /* MAC */
    kAlgorithm_KSS_CMAC_AES    = KSS_ENUM_ALGORITHM(MAC, 0x01), /* CMAC-128 */
    kAlgorithm_KSS_HMAC_SHA1   = KSS_ENUM_ALGORITHM(MAC, 0x02),
    kAlgorithm_KSS_HMAC_SHA224 = KSS_ENUM_ALGORITHM(MAC, 0x03),
    kAlgorithm_KSS_HMAC_SHA256 = KSS_ENUM_ALGORITHM(MAC, 0x04),
    kAlgorithm_KSS_HMAC_SHA384 = KSS_ENUM_ALGORITHM(MAC, 0x05),
    kAlgorithm_KSS_HMAC_SHA512 = KSS_ENUM_ALGORITHM(MAC, 0x06),
    kAlgorithm_KSS_DES_CMAC8   = KSS_ENUM_ALGORITHM(MAC, 0x07), /* Only with OneShot mode */

    /* Diffie-Helmann */
    kAlgorithm_KSS_DH   = KSS_ENUM_ALGORITHM(DH, 0x01),
    kAlgorithm_KSS_ECDH = KSS_ENUM_ALGORITHM(DH, 0x02),
    /* DSA */
    kAlgorithm_KSS_DSA_SHA1   = KSS_ENUM_ALGORITHM(DSA, 0x01),
    kAlgorithm_KSS_DSA_SHA224 = KSS_ENUM_ALGORITHM(DSA, 0x02),
    kAlgorithm_KSS_DSA_SHA256 = KSS_ENUM_ALGORITHM(DSA, 0x03),

    /* RSA */
    /* doc:start rsa_sign_algo */
    kAlgorithm_KSS_RSASSA_PKCS1_V1_5_NO_HASH    = KSS_ENUM_ALGORITHM(RSASSA_PKCS1_V1_5, 0x01),
    kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA1       = KSS_ENUM_ALGORITHM(RSASSA_PKCS1_V1_5, 0x02),
    kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA224     = KSS_ENUM_ALGORITHM(RSASSA_PKCS1_V1_5, 0x03),
    kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA256     = KSS_ENUM_ALGORITHM(RSASSA_PKCS1_V1_5, 0x04),
    kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA384     = KSS_ENUM_ALGORITHM(RSASSA_PKCS1_V1_5, 0x05),
    kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512     = KSS_ENUM_ALGORITHM(RSASSA_PKCS1_V1_5, 0x06),
    kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA1   = KSS_ENUM_ALGORITHM(RSASSA_PKCS1_PSS_MGF1, 0x01),
    kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA224 = KSS_ENUM_ALGORITHM(RSASSA_PKCS1_PSS_MGF1, 0x02),
    kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA256 = KSS_ENUM_ALGORITHM(RSASSA_PKCS1_PSS_MGF1, 0x03),
    kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA384 = KSS_ENUM_ALGORITHM(RSASSA_PKCS1_PSS_MGF1, 0x04),
    kAlgorithm_KSS_RSASSA_PKCS1_PSS_MGF1_SHA512 = KSS_ENUM_ALGORITHM(RSASSA_PKCS1_PSS_MGF1, 0x05),
    /* doc:end rsa_sign_algo */

    /* doc:start rsa_enc_algo */
    kAlgorithm_KSS_RSAES_PKCS1_OAEP_SHA1   = KSS_ENUM_ALGORITHM(RSAES_PKCS1_OAEP, 0x01),
    kAlgorithm_KSS_RSAES_PKCS1_OAEP_SHA224 = KSS_ENUM_ALGORITHM(RSAES_PKCS1_OAEP, 0x02),
    kAlgorithm_KSS_RSAES_PKCS1_OAEP_SHA256 = KSS_ENUM_ALGORITHM(RSAES_PKCS1_OAEP, 0x03),
    kAlgorithm_KSS_RSAES_PKCS1_OAEP_SHA384 = KSS_ENUM_ALGORITHM(RSAES_PKCS1_OAEP, 0x04),
    kAlgorithm_KSS_RSAES_PKCS1_OAEP_SHA512 = KSS_ENUM_ALGORITHM(RSAES_PKCS1_OAEP, 0x05),
    kAlgorithm_KSS_RSAES_PKCS1_V1_5        = KSS_ENUM_ALGORITHM(RSAES_PKCS1_V1_5, 0x01),
    /* doc:end rsa_enc_algo */

    /* doc:start rsa_sign_algo_no_padding */
    kAlgorithm_KSS_RSASSA_NO_PADDING = KSS_ENUM_ALGORITHM(RSASSA_NO_PADDING, 0x01),
    /* doc:end rsa_sign_algo_no_padding */

    /* ECDSA */
    /* doc:start ecc_sign_algo */
    kAlgorithm_KSS_ECDSA_SHA1   = KSS_ENUM_ALGORITHM(ECDSA, 0x01),
    kAlgorithm_KSS_ECDSA_SHA224 = KSS_ENUM_ALGORITHM(ECDSA, 0x02),
    kAlgorithm_KSS_ECDSA_SHA256 = KSS_ENUM_ALGORITHM(ECDSA, 0x03),
    kAlgorithm_KSS_ECDSA_SHA384 = KSS_ENUM_ALGORITHM(ECDSA, 0x04),
    kAlgorithm_KSS_ECDSA_SHA512 = KSS_ENUM_ALGORITHM(ECDSA, 0x05),
    /* doc:end ecc_sign_algo */
} kss_algorithm_t;

#undef KSS_ENUM_ALGORITHM

#ifndef __DOXYGEN__

// Deprecated names for RSAES_PKCS1_OAEP algorithms
#define kAlgorithm_KSS_RSASSA_PKCS1_OEAP_SHA1 kAlgorithm_KSS_RSAES_PKCS1_OAEP_SHA1
#define kAlgorithm_KSS_RSASSA_PKCS1_OEAP_SHA224 kAlgorithm_KSS_RSAES_PKCS1_OAEP_SHA224
#define kAlgorithm_KSS_RSASSA_PKCS1_OEAP_SHA256 kAlgorithm_KSS_RSAES_PKCS1_OAEP_SHA256
#define kAlgorithm_KSS_RSASSA_PKCS1_OEAP_SHA384 kAlgorithm_KSS_RSAES_PKCS1_OAEP_SHA384
#define kAlgorithm_KSS_RSASSA_PKCS1_OEAP_SHA512 kAlgorithm_KSS_RSAES_PKCS1_OAEP_SHA512

// Deprecated names for RSAES_PKCS1_V1_5 algorithms
#define kAlgorithm_KSS_RSAES_PKCS1_V1_5_SHA1 kAlgorithm_KSS_RSAES_PKCS1_V1_5
#define kAlgorithm_KSS_RSAES_PKCS1_V1_5_SHA224 kAlgorithm_KSS_RSAES_PKCS1_V1_5
#define kAlgorithm_KSS_RSAES_PKCS1_V1_5_SHA256 kAlgorithm_KSS_RSAES_PKCS1_V1_5
#define kAlgorithm_KSS_RSAES_PKCS1_V1_5_SHA384 kAlgorithm_KSS_RSAES_PKCS1_V1_5
#define kAlgorithm_KSS_RSAES_PKCS1_V1_5_SHA512 kAlgorithm_KSS_RSAES_PKCS1_V1_5

#endif /* __DOXYGEN__ */

/** High level algorihtmic operations.
 *
 * Augmented by @ref kss_algorithm_t
 */
typedef enum
{
    kMode_KSS_Encrypt = 1, //!< Encrypt
    kMode_KSS_Decrypt = 2, //!< Decrypt
    kMode_KSS_Sign    = 3, //!< Sign
    kMode_KSS_Verify  = 4, //!< Verify
    /* Compute Shared Secret. e.g. Diffie-Hellman */
    kMode_KSS_ComputeSharedSecret = 5,
    kMode_KSS_Digest              = 6, //!< Message Digest
    kMode_KSS_Mac                 = 7, //!< Message Authentication Code

    // kMode_KSS_HKDF = 8,   //!< HKDF Extract and Expand (RFC 5869)
    kMode_KSS_HKDF_ExpandOnly    = 9,  //!< HKDF Expand Only (RFC 5869)
    kMode_KSS_HKDF_ExtractExpand = 10, //!< HKDF Extract and Expand (RFC 5869)

    kMode_KSS_Mac_Validate = 11, //!< MAC Validate
} kss_mode_t;

/**
 * Permissions of an object
 */
typedef enum
{
    /** Can read (applicable) contents of the key.
     *
     *  @note This is not same as @ref kAccessPermission_KSS_Use.
     *
     *  Without reading, the object, the key can be used.
     */
    kAccessPermission_KSS_Read = (1u << 0),
    /** Can change the value of an object */
    kAccessPermission_KSS_Write = (1u << 1),
    /** Can use an object */
    kAccessPermission_KSS_Use = (1u << 2),
    /** Can delete an object */
    kAccessPermission_KSS_Delete = (1u << 3),
    /** Can change permissions applicable to an object */
    kAccessPermission_KSS_ChangeAttributes = (1u << 4),
    /** Bitwise OR of all kss_access_permission. */
    kAccessPermission_KSS_All_Permission = 0x1F,
} kss_access_permission_t;

/**
 * Persistent / Non persistent mode of a key
 */
typedef enum
{
    kKeyObject_Mode_None = 0, //!< kKeyObject_Mode_None
    /** Key object will be persisted in memory
     * and will retain it's value after a closed session
     */
    kKeyObject_Mode_Persistent = 1,
    /** Key Object will be stored in RAM.
     * It will lose it's contents after a session is closed
     */
    kKeyObject_Mode_Transient = 2,
} kss_key_object_mode_t;

/** Part of a key */
typedef enum
{
    kKSS_KeyPart_NONE,
    /** Applicable where we have UserID, Binary Files,
     * Certificates, Symmetric Keys, PCR, HMAC-key, counter */
    kKSS_KeyPart_Default = 1,
    /** Public part of asymmetric key */
    kKSS_KeyPart_Public = 2,
    /** Private only part of asymmetric key */
    kKSS_KeyPart_Private = 3,
    /** Both, public and private part of asymmetric key */
    kKSS_KeyPart_Pair = 4,
} kss_key_part_t;

/** For all cipher types, key bit length is provides at the time key is inserted/generated */
typedef enum
{
    kKSS_CipherType_NONE,
    kKSS_CipherType_AES = 10,
    kKSS_CipherType_DES = 12,

    kKSS_CipherType_CMAC = 20,
    kKSS_CipherType_HMAC = 21,

    kKSS_CipherType_MAC     = 30,
    kKSS_CipherType_RSA     = 31, /*! RSA RAW format      */
    kKSS_CipherType_RSA_CRT = 32, /*! RSA CRT format      */

    /* The following keys can be identified
     * solely by the *Family* and bit length
     */
    kKSS_CipherType_EC_NIST_P = 40, /*! Keys Part of NIST-P Family */
    kKSS_CipherType_EC_NIST_K = 41, /*! Keys Part of NIST-K Family */

    /* The following keys need their full curve parameters (p,a,b,x,y,n,h)
     */
    /** Montgomery Key,   */
    kKSS_CipherType_EC_MONTGOMERY = 50,
    /** twisted Edwards form elliptic curve public key */
    kKSS_CipherType_EC_TWISTED_ED = 51,
    /** Brainpool form elliptic curve public key */
    kKSS_CipherType_EC_BRAINPOOL = 52,

    kKSS_CipherType_UserID = 70,

    /** Use kKSS_CipherType_Binary to store Certificate */
    kKSS_CipherType_Certificate = 71,
    kKSS_CipherType_Binary      = 72,

    kKSS_CipherType_Count       = 73,
    kKSS_CipherType_PCR         = 74,
    kKSS_CipherType_ReservedPin = 75,
} kss_cipher_type_t;

/** XY Co-ordinates for ECC Curves */
typedef struct
{
    /** X Point */
    uint8_t *X;
    /** Y Point */
    uint8_t *Y;
} kss_ecc_point_t;

/** ECC Curve Parameter */
typedef struct
{
    uint8_t *p;         /**< ECC parameter P */
    uint8_t *a;         /**< ECC parameter a */
    uint8_t *b;         /**< ECC parameter b */
    kss_ecc_point_t *G; /**< ECC parameter G */
    uint8_t *n;         /**< ECC parameter n */
    uint8_t *h;         /**< ECC parameter h */
} kss_eccgfp_group_t;

/** @} */

/**
 * @addtogroup kss_session
 * @{
 */

/** Properties of session that are U32
 *
 * From 0 to kKSS_SessionProp_Optional_Prop_Start,
 * around 2^24 = 16777215 Properties are
 * possible.
 *
 * From 0 to kKSS_SessionProp_Optional_Prop_Start,
 * around 2^24 = 16777215 Properties are
 * possible.
 *
 */
typedef enum
{
    /** Invalid */
    kKSS_SessionProp_u32_NA = 0,
    /** Major version */
    kKSS_SessionProp_VerMaj,
    /** Minor Version */
    kKSS_SessionProp_VerMin,
    /** Development Version */
    kKSS_SessionProp_VerDev,

    /* Lenght of UID */
    kKSS_SessionProp_UIDLen,

    /** Optional Properties Start */
    kKSS_SessionProp_u32_Optional_Start = 0x00FFFFFFu,

    /** How much persistent memory is free */
    kKSS_KeyStoreProp_FreeMem_Persistant,

    /** How much transient memory is free */
    kKSS_KeyStoreProp_FreeMem_Transient,

    /** Proprietary Properties Start */
    kKSS_SessionProp_u32_Proprietary_Start = 0x01FFFFFFu,

} kss_session_prop_u32_t;

/** Properties of session that are S32
 *
 * From 0 to kKSS_SessionProp_Optional_Prop_Start,
 * around 2^24 = 16777215 Properties are
 * possible.
 *
 * From 0 to kKSS_SessionProp_Optional_Prop_Start,
 * around 2^24 = 16777215 Properties are
 * possible.
 *
 */
typedef enum
{
    /** Invalid */
    kKSS_SessionProp_au8_NA = 0,
    /** Name of the product, string */
    kKSS_SessionProp_szName,
    /** Unique Identifier */
    kKSS_SessionProp_UID,

    /** Optional Properties Start */
    kKSS_SessionProp_au8_Optional_Start = 0x00FFFFFFu,

    /** Proprietary Properties Start */
    kKSS_SessionProp_au8_Proprietary_Start = 0x01FFFFFFu,

} kss_session_prop_au8_t;

/** @brief Root session
 *
 * This is a *singleton* for each connection (physical/logical)
 * to individual cryptographic system.
 */
typedef struct
{
    /** Indicates which security subsystem is selected.
     *
     *  This is set when @ref kss_session_open is successful */
    kss_type_t subsystem;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_SESSION_MAX_CONTEXT_SIZE];
    } extension;
} kss_session_t;
/** @} */

/**
 * @addtogroup kss_key_store
 * @{
 */

/** @brief Store for secure and non secure key objects within a cryptographic system.
 *
 * - A cryptographic system may have more than partitions to store such keys.
 *
 */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    kss_session_t *session;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_KEY_STORE_MAX_CONTEXT_SIZE];
    } extension;
} kss_key_store_t;

/** properties of a Key Store that return array */
typedef enum
{
    /** Optional Properties Start */
    kKSS_KeyStoreProp_au8_Optional_Start = 0x00FFFFFFu,

} kss_key_store_prop_au8_t;

/** Entity on the other side of the tunnel */
typedef enum
{
    /** Default value */
    kKSS_TunnelDest_None = 0,

    /** SE05X IoT Applet */
    kKSS_TunnelType_Se05x_Iot_applet,
} kss_tunnel_dest_t;

/** @} */

/**
 * @addtogroup kss_key_object
 * @{
 */

/** @brief An object (secure / non-secure) within a Key Store.
 *
 */
typedef struct
{
    /** key store holding the data and other properties */
    kss_key_store_t *keyStore;
    /** The type/part of object is referneced from @ref kss_key_part_t */
    uint32_t objectType;
    /** cipherType type from @ref kss_cipher_type_t */
    uint32_t cipherType;
    /** Application specific key identifier. The keyId is kept in the key  store
     * along with the key data and other properties. */
    uint32_t keyId;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_KEY_OBJECT_MAX_CONTEXT_SIZE];
    } extension;
} kss_object_t;

/** @} */

/**
 * @addtogroup kss_crypto_symmetric
 * @{
 */

/** @brief Typedef for the symmetric crypto context */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    kss_session_t *session;
    /** Key to be used for the symmetric operation */
    kss_object_t *keyObject;
    /** Algorithm to be applied, e.g AES_ECB / CBC */
    kss_algorithm_t algorithm;
    /** Mode of operation, e.g Encryption/Decryption */
    kss_mode_t mode;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_SYMMETRIC_MAX_CONTEXT_SIZE];
    } extension;
} kss_symmetric_t;
/** @} */

/**
 * @addtogroup kss_crypto_aead
 * @{
 */

/** @brief Authenticated Encryption with Additional Data
 *
 */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    kss_session_t *session;
    /** Key to be used for asymmetric */
    kss_object_t *keyObject;
    /** Algorithm to be used */
    kss_algorithm_t algorithm;
    /** High level operation (encrypt/decrypt) */
    kss_mode_t mode;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_AEAD_MAX_CONTEXT_SIZE];
    } extension;
} kss_aead_t;

/** @} */

/**
 * @addtogroup kss_crypto_digest
 * @{
 */

/** Message Digest operations */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    kss_session_t *session;
    /** Algorithm to be applied, e.g SHA1, SHA256 */
    kss_algorithm_t algorithm;
    /** Mode of operation, e.g Sign/Verify */
    kss_mode_t mode;
    /** Full digest length per algorithm definition. This field is initialized along with algorithm. */
    size_t digestFullLen;
    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_DIGEST_MAX_CONTEXT_SIZE];
    } extension;
} kss_digest_t;

/** @} */

/**
 * @addtogroup kss_crypto_mac
 * @{
 */

/** @brief Message Authentication Code
 *
 */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    kss_session_t *session;
    /** Key to be used for ... */
    kss_object_t *keyObject;
    /** Algorithm to be applied, e.g. MAC/CMAC */
    kss_algorithm_t algorithm;
    /** Mode of operation for MAC (kMode_KSS_Mac) */
    kss_mode_t mode;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_MAC_MAX_CONTEXT_SIZE];
    } extension;
} kss_mac_t;

/** @} */

/**
 * @addtogroup kss_crypto_asymmetric
 * @{
 */
/** @} */

/** @brief Asymmetric Cryptographic operations
 *
 * e.g. RSA/ECC.
 */

typedef struct
{
    /** Pointer to root session */
    kss_session_t *session;
    /** KeyObject used for Asymmetric operation */
    kss_object_t *keyObject;
    /** Algorithm to be applied, e.g. ECDSA */
    kss_algorithm_t algorithm;
    /** Mode of operation for the Asymmetric operation.
     *  e.g. Sign/Verify/Encrypt/Decrypt */
    kss_mode_t mode;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_ASYMMETRIC_MAX_CONTEXT_SIZE];
    } extension;
} kss_asymmetric_t;
/** @} */
/** Header for a IS716 APDU */
typedef struct
{
    /** ISO 7816 APDU Header */
    uint8_t hdr[0   /* For Indentation */
                + 1 /* CLA */
                + 1 /* INS */
                + 1 /* P1 */
                + 1 /* P2 */
    ];
} tlvHeader_t;

/**
 * @addtogroup kss_crypto_tunnel
 * @{
 */

/** Tunneling
 *
 * Used for communication via another system.
 */
typedef struct
{
    /** Pointer to the session */
    kss_session_t *session;
    /** Tunnel to which Applet (Currently unused) */
    uint32_t tunnelType;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_TUNNEL_MAX_CONTEXT_SIZE];
    } extension;
} kss_tunnel_t;

/** @} */

/**
 * @addtogroup kss_crypto_derive_key
 * @{
 */

/** Key derivation */
typedef struct
{
    /** Pointer to the session */
    kss_session_t *session;
    /** KeyObject used to derive key s*/
    kss_object_t *keyObject;
    /** Algorithm to be applied, e.g. ... */
    kss_algorithm_t algorithm;
    /** Mode of operation for .... e.g. ... */
    kss_mode_t mode;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_DERIVE_KEY_MAX_CONTEXT_SIZE];
    } extension;
} kss_derive_key_t;
/** @} */

/**
 * @addtogroup kss_rng
 * @{
 */

/** Random number generator context */
typedef struct
{
    /** Pointer to the session */
    kss_session_t *session;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_RNG_MAX_CONTEXT_SIZE];
    } context;

} kss_rng_context_t;

/**
 * @addtogroup kss_session
 * @{
 */

/**
 * Same as @ref kss_session_open but to support sub systems
 * that explictily need a create before opening.
 *
 * For the sake of portabilty across various sub systems,
 * the applicaiton has to call @ref kss_session_create
 * before calling @ref kss_session_open.
 *
 *
 * @param[in,out] session Pointer to session context
 * @param[in] subsystem See @ref kss_session_open
 * @param[in] application_id See @ref kss_session_open
 * @param[in] connection_type See @ref kss_session_open
 * @param[in] connectionData See @ref kss_session_open
 */
kss_status_t kss_session_create(kss_session_t *session,
    kss_type_t subsystem,
    uint32_t application_id,
    kss_connection_type_t connection_type,
    void *connectionData);

/**
 * @brief         Open session between application and a security subsystem.
 *
 *                Open virtual session between application (user context) and a
 *                security subsystem and function thereof. Pointer to session
 *                shall be supplied to all SSS APIs as argument. Low level SSS
 *                functions can provide implementation specific behaviour based
 *                on the session argument.
 *                Note: kss_session_open() must not be called concurrently from
 *                multiple threads. The application must ensure this.
 *
 * @param[in,out] session          Session context.
 * @param[in]     subsystem        Indicates which security subsystem is
 *                                 selected to be used.
 * @param[in]     application_id   ObjectId/AuthenticationID Connecting to:
 *          - ``application_id`` == 0 => Super use / Plaform user
 *          - Anything else => Authenticated user
 * @param[in]     connection_type  How are we connecting to the system.
 * @param[in,out] connectionData   subsystem specific connection parameters.
 *
 * @return        status
 */
kss_status_t kss_session_open(kss_session_t *session,
    kss_type_t subsystem,
    uint32_t application_id,
    kss_connection_type_t connection_type,
    void *connectionData);



#if 0
/** Random number generator context */
typedef struct
{
    /** Pointer to the session */
    kss_session_t *session;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_RNG_MAX_CONTEXT_SIZE];
    } context;

} kss_rng_context_t;

kss_status_t kss_rng_context_init(kss_rng_context_t *context, kss_session_t *session);

/**
 * @brief Generate random number.
 *
 * @param   context random generator context.
 * @param   random_data buffer to hold random data.
 * @param   dataLen required random number length
 * @return  status
 */
kss_status_t kss_rng_get_random(kss_rng_context_t *context, uint8_t *random_data, size_t dataLen);

/**
 * @brief free random genertor context.
 *
 * @param   context generator context.
 * @return  status
 */
kss_status_t kss_rng_context_free(kss_rng_context_t *context);

#endif
#if 0
/**
 * @brief Get an underlying property of the crypto sub system
 *
 * This API is used to get values that are
 * numeric in nature.
 *
 * Property can be either fixed value that is
 * calculated at compile time and returned
 * directly, or it may involve some access to the
 * underlying system.
 *
 * For applicable properties see @ref kss_session_prop_u32_t
 *
 * @param[in] session Session context
 * @param[in] property Value that is part of @ref kss_session_prop_u32_t
 * @param[out] pValue
 *
 * @return
 */
kss_status_t kss_session_prop_get_u32(kss_session_t *session, uint32_t property, uint32_t *pValue);

/**
 * @brief Get an underlying property of the crypto sub system
 *
 * This API is used to get values that are
 * numeric in nature.
 *
 * Property can be either fixed value that is
 * calculated at compile time and returned
 * directly, or it may involve some access to the
 * underlying system.
 *
 * @param[in] session Session context
 * @param[in] property Value that is part of @ref kss_session_prop_au8_t
 * @param[out] pValue Output buffer array
 * @param[in,out] pValueLen Count of values thare are/must br read
 * @return
 */
kss_status_t kss_session_prop_get_au8(kss_session_t *session, uint32_t property, uint8_t *pValue, size_t *pValueLen);
#endif
#if 1
/**
 * @brief Close session between application and security subsystem.
 *
 * This function closes a session which has been opened with a security subsystem.
 * All commands within the session must have completed before this function can be called.
 * The implementation must do nothing if the input ``session`` parameter is NULL.
 *
 *
 * @param   session Session context.
 */
void kss_session_close(kss_session_t *session);
#endif
#if 1
/** Counterpart to @ref kss_session_create
 *
 * Similar to contraint on @ref kss_session_create, application
 * may call @ref kss_session_delete to explicitly release all
 * underlying/used session specific resoures of that implementation.
 */
void kss_session_delete(kss_session_t *session);

/**
 *@}
 */ /* end of kss_session */

/**
 * @addtogroup kss_key_store
 * @{
 */

/** @brief Constructor for the key store context data structure.
 *
 * @param[out] keyStore Pointer to key store context. Key store context is updated on function return.
 * @param session Session context.
 */
kss_status_t kss_key_store_context_init(kss_key_store_t *keyStore, kss_session_t *session);

/** @brief Get handle to key store.
 *  If the key store already exists, nothing is allocated.
 *  If the key store does not exists, new empty key store is created and initialized.
 *  Key store context structure is updated with actual information.
 *
 * @param[out] keyStore Pointer to key store context. Key store context is updated on function return.
 * @param keyStoreId Implementation specific ID, can be used in case security subsystem manages multiple different
 * key stores.
 */
kss_status_t kss_key_store_allocate(kss_key_store_t *keyStore, uint32_t keyStoreId);

/** @brief Save all cached persistent objects to persistent memory.
 */
kss_status_t kss_key_store_save(kss_key_store_t *keyStore);

/** @brief Load from persistent memory to cached objects.
 */
kss_status_t kss_key_store_load(kss_key_store_t *keyStore);

/** @brief This function moves data[] from memory to the destination key store.
 *
 * @param keyStore Key store context
 * @param keyObject Reference to a key and it's properties
 * @param data Data to be stored in Key. When setting ecc private key only, do not include key header.
 * @param dataLen Length of the data
 * @param keyBitLen Crypto algorithm key bit length
 * @param options Pointer to implementation specific options
 * @param optionsLen Length of the options in bytes
 *
 * @return
 */
kss_status_t kss_key_store_set_key(kss_key_store_t *keyStore,
    kss_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen);

/** @brief This function generates key[] in the destination key store. */
kss_status_t kss_key_store_generate_key(
    kss_key_store_t *keyStore, kss_object_t *keyObject, size_t keyBitLen, void *options);

/** @brief This function exports plain key[] from key store (if constraints and user id allows reading) */
kss_status_t kss_key_store_get_key(
    kss_key_store_t *keyStore, kss_object_t *keyObject, uint8_t *data, size_t *dataLen, size_t *pKeyBitLen);

/**
 * @brief      Access key store using one more level of encryption
 *
 * e.g. Access keys / encryption key during storage
 *
 * @param      keyStore   The key store
 * @param      keyObject  The key object that is to be used as a KEK (Key Encryption Key)
 *
 * @return     The kss status.
 */
kss_status_t kss_key_store_open_key(kss_key_store_t *keyStore, kss_object_t *keyObject);

/**
 * @brief      The referenced key cannot be updated any more.
 *
 * @param      keyStore   The key store
 * @param      keyObject  The key object to be locked / frozen.
 *
 * @return     The kss status.
 */
kss_status_t kss_key_store_freeze_key(kss_key_store_t *keyStore, kss_object_t *keyObject);

/**
 * @brief      Delete / destroy allocated keyObect .
 *
 * @param      keyStore   The key store
 * @param      keyObject  The key object to be deleted
 *
 * @return     The kss status.
 */
kss_status_t kss_key_store_erase_key(kss_key_store_t *keyStore, kss_object_t *keyObject);

// kss_status_t kss_key_store_clear_all(kss_key_store_t *keyStore);

/** @brief Destructor for the key store context. */
void kss_key_store_context_free(kss_key_store_t *keyStore);

/**
 *@}
 */ /* end of kss_key_store */

/**
 * @addtogroup kss_key_object
 * @{
 */

/** @brief Constructor for a key object data structure
 *  The function initializes keyObject data structure and associates it with a key store
 *  in which the plain key and other attributes are stored.
 *
 * @param keyObject
 * @param keyStore
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_key_object_init(kss_object_t *keyObject, kss_key_store_t *keyStore);

/**
 * @brief         Allocate / pre-provision memory for new key
 *
 *                This API allows underlying cryptographic subsystems to perform
 *                preconditions of before creating any cryptographic key object.
 *
 * @param[in,out] keyObject      The object If required, update implementation
 *                               defined values inside the keyObject
 * @param         keyId          External Key ID.  Later on this may be used by
 *                               @ref kss_key_object_get_handle
 * @param         keyPart        See @ref kss_key_part_t
 * @param         cipherType     See @ref kss_cipher_type_t
 * @param         keyByteLenMax  Maximum storage this type of key may need. For
 *                               systems that have their own internal allocation
 *                               table this would help
 * @param         options        0 = Persistant Key (Default) or Transient Key.
 *                               See kss_key_object_mode_t
 *
 * @return        Status of object allocation.
 */
kss_status_t kss_key_object_allocate_handle(kss_object_t *keyObject,
    uint32_t keyId,
    kss_key_part_t keyPart,
    kss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options); /* Check if this can be made kss_key_object_mode_t */

 /**
 * @brief      Get handle to an existing allocated/provisioned/created Object
 *
 *             See @ref kss_key_object_allocate_handle.
 *
 *             After calling this API, Ideally keyObject should become equivlant
 *             to as set after the calling of @ref
 *             kss_key_object_allocate_handle api.
 *
 * @param      keyObject  The key object
 * @param[in]  keyId      The key identifier
 *
 * @return     The kss status.
 */
kss_status_t kss_key_object_get_handle(kss_object_t *keyObject, uint32_t keyId);

/**
 * @brief      Get handle to an existing allocated/provisioned/created Object
 *
 *             See @ref kss_key_object_allocate_handle.
 *
 *             After calling this API, Ideally keyObject should become equivlant
 *             to as set after the calling of @ref
 *             kss_key_object_allocate_handle api.
 *
 * @param      keyObject  The key object
 * @param[in]  objectId   The object identifier
 *
 * @return     The kss status.
 */
kss_status_t kss_key_object_get_data(kss_object_t *keyObject, uint32_t objectId);

/** @brief Assign user to a key object.
 *
 * @param keyObject the object where permission restrictions are applied
 *
 * @param user Assign User id for a key object. The user is kept in the key
 *        store along with the key data and other properties.
 * @param options Transient or persistent update. Allows for transient update
 * of persistent attributes.
 */
kss_status_t kss_key_object_set_user(kss_object_t *keyObject, uint32_t user, uint32_t options);

/** @brief Assign purpose to a key object.
 *
 *  @param keyObject the object where permission restrictions are applied
 *  @param purpose Usage of the key.
 *  @param options Transient or persistent update. Allows for transient update of persistent attributes.
 */
kss_status_t kss_key_object_set_purpose(kss_object_t *keyObject, kss_mode_t purpose, uint32_t options);

/** @brief Assign access permissions to a key object.
 *
 *  @param keyObject the object where permission restrictions are applied
 *  @param access Logical OR of read, write, delete, use, change attributes defined by enum _kss_access_permission.
 *  @param options Transient or persistent update. Allows for transient update of persistent attributes.
 */
kss_status_t kss_key_object_set_access(kss_object_t *keyObject, uint32_t access, uint32_t options);

/** @brief Set elliptic curve domain parameters over Fp for a key object
 *
 *  When the key object is a reference to one of ECC Private, ECC Public or ECC Pair key types,
 *  this function shall be used to specify the exact domain parameters prior to using the key object
 *  for ECDSA or ECDH algorithms.
 *
 *  @param keyObject The destination key object
 *  @param group Pointer to elliptic curve domain parameters over Fp (sextuple p,a,b,G,n,h)
 */
kss_status_t kss_key_object_set_eccgfp_group(kss_object_t *keyObject, kss_eccgfp_group_t *group);

/** @brief get attributes */
kss_status_t kss_key_object_get_user(kss_object_t *keyObject, uint32_t *user);

/** Check what is purpose restrictions on an object
 *
 * @param keyObject Object to be checked
 * @param purpose Know what is permitted.
 * @return
 */
kss_status_t kss_key_object_get_purpose(kss_object_t *keyObject, kss_mode_t *purpose);

/** Check what are access restrictions on an object
 *
 * @param keyObject Object
 * @param access What is permitted
 * @return
 */
kss_status_t kss_key_object_get_access(kss_object_t *keyObject, uint32_t *access);

/** @brief Destructor for the key object.
 *  The function frees key object context.
 *
 * @param keyObject Pointer to key object context.
 */
void kss_key_object_free(kss_object_t *keyObject);

/**
 *@}
 */ /* end of kss_key_object */

/**
 * @addtogroup kss_crypto_symmetric
 * @{
 */

/** @brief Symmetric context init.
 *  The function initializes symmetric context with initial values.
 *
 * @param context Pointer to symmetric crypto context.
 * @param session Associate SSS session with symmetric context.
 * @param keyObject Associate SSS key object with symmetric context.
 * @param algorithm One of the symmetric algorithms defined by @ref kss_algorithm_t.
 * @param mode One of the modes defined by @ref kss_mode_t.
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_symmetric_context_init(kss_symmetric_t *context,
    kss_session_t *session,
    kss_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode);

/** @brief Symmetric cipher in one blocking function call.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param context Pointer to symmetric crypto context.
 * @param iv Buffer containing the symmetric operation Initialization Vector. When using internal IV algorithms (only encrypt)
 * for SE051, iv buffer will be filled with genereted Initialization Vector.
 * @param ivLen Length of the Initialization Vector in bytes.
 * @param srcData Buffer containing the input data (block aligned).
 * @param destData Buffer containing the output data.
 * @param dataLen Size of input and output data buffer in bytes.
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_cipher_one_go(
    kss_symmetric_t *context, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen);

/** @brief Symmetric cipher in one blocking function call.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param context Pointer to symmetric crypto context.
 * @param iv Buffer containing the symmetric operation Initialization Vector. When using internal IV algorithms (only encrypt)
 * for SE051, iv buffer will be filled with genereted Initialization Vector.
 * @param ivLen Length of the Initialization Vector in bytes.
 * @param srcData Buffer containing the input data (block aligned).
 * @param srcLen  Length of buffer srcData.
 * @param destData Buffer containing the output data.
 * @param dataLen Pointer to Size of buffer destData in bytes.
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_cipher_one_go_v2(kss_symmetric_t *context,
    uint8_t *iv,
    size_t ivLen,
    const uint8_t *srcData,
    const size_t srcLen,
    uint8_t *destData,
    size_t *dataLen);

/** @brief Symmetric cipher init.
 *  The function starts the symmetric cipher operation.
 *
 * @param context Pointer to symmetric crypto context.
 * @param iv Buffer containing the symmetric operation Initialization Vector. When using internal IV algorithms (only encrypt)
 * for SE051, iv buffer will be filled with genereted Initialization Vector.
 * @param ivLen Length of the Initialization Vector in bytes.
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_cipher_init(kss_symmetric_t *context, uint8_t *iv, size_t ivLen);

/** @brief Symmetric cipher update.
 * Input data does not have to be a multiple of block size. Subsequent calls to this function are possible.
 * Unless one or more calls of this function have supplied sufficient input data, no output is generated.
 * The cipher operation is finalized with a call to @ref kss_cipher_finish().
 *
 * @param context Pointer to symmetric crypto context.
 * @param srcData Buffer containing the input data.
 * @param srcLen Length of the input data in bytes.
 * @param destData Buffer containing the output data.
 * @param[in,out] destLen Length of the output data in bytes. Buffer length on entry, reflects actual output size on
 * return.
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_cipher_update(
    kss_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @brief Symmetric cipher finalize.
 *
 * @param context Pointer to symmetric crypto context.
 * @param srcData Buffer containing final chunk of input data.
 * @param srcLen Length of final chunk of input data in bytes.
 * @param destData Buffer containing output data.
 * @param[in,out] destLen Length of output data in bytes. Buffer length on entry, reflects actual output size on
 * return.
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_cipher_finish(
    kss_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @brief Symmetric AES in Counter mode in one blocking function call.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param context Pointer to symmetric crypto context.
 * @param srcData Buffer containing the input data.
 * @param destData Buffer containing the output data.
 * @param size Size of source and destination data buffers in bytes.
 * @param[in,out] initialCounter Input counter (Always 16 bytes) (updates on return). When using internal IV algorithms (only encrypt)
 * for SE051, initialCounter buffer will be filled with genereted Initial counter.
 * @param[out] lastEncryptedCounter Output cipher of last counter, for chained CTR calls. NULL can be passed if
 * chained calls are not used.
 * @param[out] szLeft Output number of bytes in left unused in lastEncryptedCounter block. NULL can be passed if
 * chained calls are not used.
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_cipher_crypt_ctr(kss_symmetric_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *initialCounter,
    uint8_t *lastEncryptedCounter,
    size_t *szLeft);

/** @brief Symmetric context release.
 *  The function frees symmetric context.
 *
 * @param context Pointer to symmetric crypto context.
 */
void kss_symmetric_context_free(kss_symmetric_t *context);
/**
 *@}
 */ /* end of kss_crypto_symmetric */

/**
 * @addtogroup kss_crypto_aead
 * @{
 */

/** @brief AEAD context init.
 *  The function initializes aead context with initial values.
 *
 * @param context Pointer to aead crypto context.
 * @param session Associate SSS session with aead context.
 * @param keyObject Associate SSS key object with aead context.
 * @param algorithm One of the aead algorithms defined by @ref kss_algorithm_t.
 * @param mode One of the modes defined by @ref kss_mode_t.
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_aead_context_init(
    kss_aead_t *context, kss_session_t *session, kss_object_t *keyObject, kss_algorithm_t algorithm, kss_mode_t mode);

/** @brief AEAD in one blocking function call.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param context Pointer to aead crypto context.
 * @param srcData Buffer containing the input data.
 * @param destData Buffer containing the output data.
 * @param size Size of input and output data buffer in bytes.
 * @param nonce The operation nonce or IV. When using internal IV algorithms (only encrypt) for SE051,
 * iv buffer will be filled with genereted Initialization Vector.
 * @param nonceLen The length of nonce in bytes. For AES-GCM it must be >= 1. For AES-CCM it must be 7, 8, 9, 10,
 * 11, 12, or 13.
 * @param aad Input additional authentication data AAD
 * @param aadLen Input size in bytes of AAD
 * @param tag Encryption: Output buffer filled with computed tag (Default value is 16 bytes).
 *            Decryption: Input buffer filled with received tag
 * @param tagLen Length of the tag in bytes.
 *               For AES-GCM it must be 4,8,12,13,14,15 or 16.
 *               For AES-CCM it must be 4,6,8,10,12,14 or 16.
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_aead_one_go(kss_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen);

/** @brief AEAD init.
 *  The function starts the aead operation.
 *
 * @param context Pointer to aead crypto context.
 * @param nonce The operation nonce or IV. When using internal IV algorithms (only encrypt) for SE051,
 * iv buffer will be filled with genereted Initialization Vector.
 * @param nonceLen The length of nonce in bytes. For AES-GCM it must be >= 1. For AES-CCM it must be 7, 8, 9, 10,
 * 11, 12, or 13.
 * @param tagLen Length of the computed or received tag in bytes.
 *               For AES-GCM it must be 4,8,12,13,14,15 or 16.
 *               For AES-CCM it must be 4,6,8,10,12,14 or 16.
 * @param aadLen Input size in bytes of AAD. Used only for AES-CCM. Ignored for AES-GCM.
 * @param payloadLen Length in bytes of the payload. Used only for AES-CCM. Ignored for AES-GCM.
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_aead_init(
    kss_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen);

/** @brief Feeds a new chunk of the AAD.
 *  Subsequent calls of this function are possible.
 *
 * @param context Pointer to aead crypto context
 * @param aadData Input buffer containing the chunk of AAD
 * @param aadDataLen Length of the AAD data in bytes.
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_aead_update_aad(kss_aead_t *context, const uint8_t *aadData, size_t aadDataLen);

/** @brief AEAD data update.
 * Feeds a new chunk of the data payload.
 * Input data does not have to be a multiple of block size. Subsequent calls to this function are possible.
 * Unless one or more calls of this function have supplied sufficient input data, no output is generated.
 * The integration check is done by @ref kss_aead_finish(). Until then it is not sure if the decrypt data is
 * authentic.
 *
 * @param context Pointer to aead crypto context.
 * @param srcData Buffer containing the input data.
 * @param srcLen Length of the input data in bytes.
 * @param destData Buffer containing the output data.
 * @param[in,out] destLen Length of the output data in bytes. Buffer length on entry, reflects actual output size on
 * return.
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_aead_update(
    kss_aead_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @brief Finalize AEAD.
 * The functions processes data that has not been processed by previous calls to kss_aead_update() as well as
 * srcData. It finalizes the AEAD operations and computes the tag (encryption) or compares the computed tag with the
 * tag supplied in the parameter (decryption).
 *
 * @param context Pointer to aead crypto context.
 * @param srcData Buffer containing final chunk of input data.
 * @param srcLen Length of final chunk of input data in bytes.
 * @param destData Buffer containing output data.
 * @param[in,out] destLen Length of output data in bytes. Buffer length on entry, reflects actual output size on
 * return.
 * @param tag Encryption: Output buffer filled with computed tag
 *            Decryption: Input buffer filled with received tag
 * @param tagLen Length of the computed or received tag in bytes.
 *               For AES-GCM it must be 4,8,12,13,14,15 or 16.
 *               For AES-CCM it must be 4,6,8,10,12,14 or 16.
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_aead_finish(kss_aead_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen,
    uint8_t *tag,
    size_t *tagLen);

/** @brief AEAD context release.
 *  The function frees aead context.
 *
 * @param context Pointer to aead context.
 */
void kss_aead_context_free(kss_aead_t *context);
/**
 *@}
 */ /* end of kss_crypto_aead */

/**
 * @addtogroup kss_crypto_digest
 * @{
 */

/** @brief Digest context init.
 *  The function initializes digest context with initial values.
 *
 * @param context Pointer to digest context.
 * @param session Associate SSS session with digest context.
 * @param algorithm One of the digest algorithms defined by @ref kss_algorithm_t.
 * @param mode One of the modes defined by @ref kss_mode_t.
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_digest_context_init(
    kss_digest_t *context, kss_session_t *session, kss_algorithm_t algorithm, kss_mode_t mode);

/** @brief Message digest in one blocking function call.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param context Pointer to digest context.
 * @param message Input message
 * @param messageLen Length of the input message in bytes
 * @param digest Output message digest
 * @param digestLen Message digest byte length
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_digest_one_go(
    kss_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen);

/** @brief Init digest for a message.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param context Pointer to digest context.
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_digest_init(kss_digest_t *context);

/** @brief Update digest for a message.
 *
 * The function blocks current thread until the operation completes or an error occurs.
 *
 * @param context Pointer to digest context.
 * @param message Buffer with a message chunk.
 * @param messageLen Length of the input buffer in bytes.
 * @returns Status of the operation
 *
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_digest_update(kss_digest_t *context, const uint8_t *message, size_t messageLen);

/** @brief Finish digest for a message.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param context Pointer to digest context.
 * @param digest Output message digest
 * @param digestLen Message digest byte length
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_digest_finish(kss_digest_t *context, uint8_t *digest, size_t *digestLen);

/** @brief Digest context release.
 *  The function frees digest context.
 *
 * @param context Pointer to digest context.
 */
void kss_digest_context_free(kss_digest_t *context);

/**
 *@}
 */ /* end of kss_crypto_digest */

/**
 * @addtogroup kss_crypto_mac
 * @{
 */

/** @brief MAC context init.
 *  The function initializes mac context with initial values.
 *
 * @param context Pointer to mac context.
 * @param session Associate SSS session with mac context.
 * @param keyObject Associate SSS key object with mac context.
 * @param algorithm One of the mac algorithms defined by @ref kss_algorithm_t.
 * @param mode One of the modes defined by @ref kss_mode_t.
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_mac_context_init(
    kss_mac_t *context, kss_session_t *session, kss_object_t *keyObject, kss_algorithm_t algorithm, kss_mode_t mode);

/** @brief Message MAC in one blocking function call.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param context Pointer to mac context.
 * @param message Input message
 * @param messageLen Length of the input message in bytes
 * @param mac Output message MAC
 * @param macLen Computed MAC byte length
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_mac_one_go(
    kss_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen);

/** @brief Init mac for a message.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param context Pointer to mac context.
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_mac_init(kss_mac_t *context);

/** @brief Update mac for a message.
 *
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param context Pointer to mac context.
 * @param message Buffer with a message chunk.
 * @param messageLen Length of the input buffer in bytes.
 * @returns Status of the operation
 *
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_mac_update(kss_mac_t *context, const uint8_t *message, size_t messageLen);

/** @brief Finish mac for a message.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param context Pointer to mac context.
 * @param mac Output message MAC
 * @param macLen Computed MAC byte length
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 */
kss_status_t kss_mac_finish(kss_mac_t *context, uint8_t *mac, size_t *macLen);

/** @brief MAC context release.
 *  The function frees mac context.
 *
 * @param context Pointer to mac context.
 */
void kss_mac_context_free(kss_mac_t *context);
/**
 *@}
 */ /* end of kss_crypto_mac */

/**
 * @addtogroup kss_crypto_asymmetric
 * @{
 */

/** @brief Asymmetric context init.
 *  The function initializes asymmetric context with initial values.
 *
 * @param context Pointer to asymmetric crypto context.
 * @param session Associate SSS session with asymmetric context.
 * @param keyObject Associate SSS key object with asymmetric context.
 * @param algorithm One of the asymmetric algorithms defined by @ref kss_algorithm_t.
 * @param mode One of the modes defined by @ref kss_mode_t.
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_asymmetric_context_init(kss_asymmetric_t *context,
    kss_session_t *session,
    kss_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode);

/** @brief Asymmetric encryption
 *  The function uses asymmetric algorithm to encrypt data. Public key portion of a key pair is used for encryption.
 *
 * @param context Pointer to asymmetric context.
 * @param srcData Input buffer
 * @param srcLen Length of the input in bytes
 * @param destData Output buffer
 * @param destLen Length of the output in bytes
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_asymmetric_encrypt(
    kss_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @brief Asymmetric decryption
 *  The function uses asymmetric algorithm to decrypt data. Private key portion of a key pair is used for
 * decryption.
 *
 * @param context Pointer to asymmetric context.
 * @param srcData Input buffer
 * @param srcLen Length of the input in bytes
 * @param destData Output buffer
 * @param destLen Length of the output in bytes
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_asymmetric_decrypt(
    kss_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @brief Asymmetric signature of a message digest
 *  The function signs a message digest.
 *
 * @param context Pointer to asymmetric context.
 * @param digest Input buffer containing the input message digest
 * @param digestLen Length of the digest in bytes
 * @param signature Output buffer written with the signature of the digest
 * @param signatureLen Length of the signature in bytes
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_asymmetric_sign_digest(
    kss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);

/** @brief Asymmetric verify of a message digest
 *  The function verifies a message digest.
 *
 * @param context Pointer to asymmetric context.
 * @param digest Input buffer containing the input message digest
 * @param digestLen Length of the digest in bytes
 * @param signature Input buffer containing the signature to verify
 * @param signatureLen Length of the signature in bytes
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_asymmetric_verify_digest(
    kss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen);

/** @brief Asymmetric context release.
 *  The function frees asymmetric context.
 *
 * @param context Pointer to asymmetric context.
 */
void kss_asymmetric_context_free(kss_asymmetric_t *context);
/**
 *@}
 */ /* end of kss_crypto_asymmetric */

#endif

/**
 * @addtogroup kss_crypto_derive_key
 * @{
 */

/** @brief Derive key context init.
 *  The function initializes derive key context with initial values.
 *
 * @param context Pointer to derive key context.
 * @param session Associate SSS session with the derive key context.
 * @param keyObject Associate SSS key object with the derive key context.
 * @param algorithm One of the derive key algorithms defined by @ref kss_algorithm_t.
 * @param mode One of the modes defined by @ref kss_mode_t.
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_derive_key_context_init(kss_derive_key_t *context,
    kss_session_t *session,
    kss_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode);

/** @brief Symmetric key derivation
 *  The function cryptographically derives a key from another key.
 *  For example MIFARE key derivation, PRF, HKDF-Extract.
 *
 * @deprecated Please use ::kss_derive_key_one_go instead
 *
 * @param context Pointer to derive key context.
 * @param saltData Input data buffer, typically with some random data.
 * @param saltLen Length of saltData buffer in bytes.
 * @param info Input data buffer, typically with some fixed info.
 * @param infoLen Length of info buffer in bytes.
 * @param[in,out] derivedKeyObject Reference to a derived key
 * @param deriveDataLen Requested length of output
 * @param hkdfOutput Output buffer containing key derivation output
 * @param hkdfOutputLen Output containing length of hkdfOutput
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_derive_key_go(kss_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    kss_object_t *derivedKeyObject,
    uint16_t deriveDataLen,
    uint8_t *hkdfOutput,
    size_t *hkdfOutputLen);

/** @brief Symmetric key derivation (replaces the deprecated function ::kss_derive_key_go)
 *  The function cryptographically derives a key from another key.
 *  For example MIFARE key derivation, PRF, HKDF-Extract-Expand, HKDF-Expand.
 *  Refer to ::kss_derive_key_sobj_one_go in case the Salt is available as a key object.
 *
 * @param context Pointer to derive key context.
 * @param saltData Input data buffer, typically with some random data.
 * @param saltLen Length of saltData buffer in bytes.
 * @param info Input data buffer, typically with some fixed info.
 * @param infoLen Length of info buffer in bytes.
 * @param[in,out] derivedKeyObject Reference to a derived key
 * @param[in] deriveDataLen Expected length of derived key.
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_derive_key_one_go(kss_derive_key_t *context,
    const uint8_t *saltData,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    kss_object_t *derivedKeyObject,
    uint16_t deriveDataLen);

/**
 * @brief      Symmetric key derivation (salt in key object)
 * Refer to ::kss_derive_key_one_go in case the salt is not available as a key object.
 *
 * @param      context           Pointer to derive key context
 * @param      saltKeyObject     Reference to salt. The salt key object must reside in the same keystore as the derive key context.
 * @param[in]  info              Input data buffer, typically with some fixed info.
 * @param[in]  infoLen           Length of info buffer in bytes.
 * @param      derivedKeyObject  Reference to a derived key
 * @param[in]  deriveDataLen     The derive data length
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_derive_key_sobj_one_go(kss_derive_key_t *context,
    kss_object_t *saltKeyObject,
    const uint8_t *info,
    size_t infoLen,
    kss_object_t *derivedKeyObject,
    uint16_t deriveDataLen);

/** @brief Asymmetric key derivation Diffie-Helmann
 *  The function cryptographically derives a key from another key.
 *  For example Diffie-Helmann.
 *
 * @param context Pointer to derive key context.
 * @param otherPartyKeyObject Public key of the other party in the Diffie-Helmann algorithm
 * @param[in,out] derivedKeyObject Reference to a derived key
 *
 * @returns Status of the operation
 * @retval #kStatus_KSS_Success The operation has completed successfully.
 * @retval #kStatus_KSS_Fail The operation has failed.
 * @retval #kStatus_KSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
kss_status_t kss_derive_key_dh(
    kss_derive_key_t *context, kss_object_t *otherPartyKeyObject, kss_object_t *derivedKeyObject);

/** @brief Derive key context release.
 *  The function frees derive key context.
 *
 * @param context Pointer to derive key context.
 */
void kss_derive_key_context_free(kss_derive_key_t *context);
/**
 *@}
 */ /* end of kss_crypto_derive_key */

/**
 * @addtogroup kss_rng
 * @{
 */

/**
 * @brief Initialise random generator context between application and a security subsystem.
 *
 *
 * @warning API Changed
 *
 *      Earlier:
 *          kss_status_t kss_rng_context_init(
 *              kss_session_t *session, kss_rng_context_t *context);
 *
 *      Now: Parameters are swapped
 *       kss_status_t kss_rng_context_init(
 *           kss_rng_context_t *context, kss_session_t *session);
 *
 * @param   session Session context.
 * @param   context random generator context.
 * @return  status
 */
kss_status_t kss_rng_context_init(kss_rng_context_t *context, kss_session_t *session);

/**
 * @brief Generate random number.
 *
 * @param   context random generator context.
 * @param   random_data buffer to hold random data.
 * @param   dataLen required random number length
 * @return  status
 */
kss_status_t kss_rng_get_random(kss_rng_context_t *context, uint8_t *random_data, size_t dataLen);

/**
 * @brief free random genertor context.
 *
 * @param   context generator context.
 * @return  status
 */
kss_status_t kss_rng_context_free(kss_rng_context_t *context);
#endif
