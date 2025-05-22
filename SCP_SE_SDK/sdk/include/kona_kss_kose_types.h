/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef KSS_APIS_INC_KONA_KSS_KOSE_TYPES_H_
#define KSS_APIS_INC_KONA_KSS_KOSE_TYPES_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "kose_tlv.h"
#include "kona_kss_api.h"
#include "kose_enums.h"

#include "scp03_Types.h"
#include "kose_const.h"
#include "sm_api.h"

#if (__GNUC__ && !AX_EMBEDDED)
#include <pthread.h>
/* Only for base session with os */
#endif
/* FreeRTOS includes. */
#if defined(USE_RTOS) && (USE_RTOS == 1)
#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"
#endif

#if defined(USE_THREADX_RTOS)
#include "tx_api.h"
#endif
/*!
 * @addtogroup kss_sw_kose
 * @{
 */

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/** Are we using KOSE as crypto subsystem? */
#define KSS_SUBSYSTEM_TYPE_IS_KOSE(subsystem) (subsystem == kType_KSS_SecureElement)

/** Are we using KOSE as crypto subsystem? */
#define KSS_SESSION_TYPE_IS_KOSE(session) (session && KSS_SUBSYSTEM_TYPE_IS_KOSE(session->subsystem))

/** Are we using KOSE as crypto subsystem? */
#define KSS_KEY_STORE_TYPE_IS_KOSE(keyStore) (keyStore && KSS_SESSION_TYPE_IS_KOSE(keyStore->session))

/** Are we using KOSE as crypto subsystem? */
#define KSS_OBJECT_TYPE_IS_KOSE(pObject) (pObject && KSS_KEY_STORE_TYPE_IS_KOSE(pObject->keyStore))

/** Are we using KOSE as crypto subsystem? */
#define KSS_ASYMMETRIC_TYPE_IS_KOSE(context) (context && KSS_SESSION_TYPE_IS_KOSE(context->session))

/** Are we using KOSE as crypto subsystem? */
#define KSS_DERIVE_KEY_TYPE_IS_KOSE(context) (context && KSS_SESSION_TYPE_IS_KOSE(context->session))

/** Are we using KOSE as crypto subsystem? */
#define KSS_SYMMETRIC_TYPE_IS_KOSE(context) (context && KSS_SESSION_TYPE_IS_KOSE(context->session))

/** Are we using KOSE as crypto subsystem? */
#define KSS_MAC_TYPE_IS_KOSE(context) (context && KSS_SESSION_TYPE_IS_KOSE(context->session))

/** Are we using KOSE as crypto subsystem? */
#define KSS_RNG_CONTEXT_TYPE_IS_KOSE(context) (context && KSS_SESSION_TYPE_IS_KOSE(context->session))

/** Are we using KOSE as crypto subsystem? */
#define KSS_DIGEST_TYPE_IS_KOSE(context) (context && KSS_SESSION_TYPE_IS_KOSE(context->session))

/** Are we using KOSE as crypto subsystem? */
#define KSS_AEAD_TYPE_IS_KOSE(context) (context && KSS_SESSION_TYPE_IS_KOSE(context->session))

/** Are we using KOSE as crypto subsystem? */
#define KSS_TUNNEL_CONTEXT_TYPE_IS_KOSE(context) (context && KSS_SESSION_TYPE_IS_KOSE(context->session))

/** Are we using KOSE as crypto subsystem? */
#define KSS_TUNNEL_TYPE_IS_KOSE(context) (context && KSS_SESSION_TYPE_IS_KOSE(context->session))

#define assert_static(e)                    \
    {                                       \
        char assert_static__[(e) ? 1 : -1]; \
    }

/** Compile time assert */
#define KSS_ASSERT(condition) assert_static(condition)

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

struct _kss_kose_session;

/** @copydoc kss_tunnel_t */
typedef struct _kss_kose_tunnel_context
{
    /** Pointer to the base SE050 SEssion */
    struct _kss_kose_session *kose_session;
    /** Where exactly this tunnel terminates to */
    kss_tunnel_dest_t tunnelDest;
/** For systems where we potentially have multi-threaded operations, have a lock */
#if defined(USE_THREADX_RTOS)
    TX_MUTEX channelLock;
#elif (defined(USE_RTOS) && (USE_RTOS == 1))
    SemaphoreHandle_t channelLock;
#elif (__GNUC__ && !AX_EMBEDDED)
    pthread_mutex_t channelLock;
#endif
} kss_kose_tunnel_context_t;

/** @copydoc kss_session_t */
typedef struct _kss_kose_session
{
    /** Indicates which security subsystem is selected to be used. */
    
    kss_type_t subsystem;
    /** Connection context to SE050 */

    KoseSession_t s_ctx;

    /** In case connection is tunneled, context to the tunnel */

    kss_kose_tunnel_context_t *ptun_ctx;
} kss_kose_session_t;

struct _kss_kose_object;

/** @copydoc kss_key_store_t */
typedef struct
{
    /** Pointer to the session */
    kss_kose_session_t *session;
    /** In case the we are using Key Wrapping while injecting the keys, pointer to key used for wrapping */
    struct _kss_kose_object *kekKey;

} kss_kose_key_store_t;

/** @copydoc kss_object_t */
typedef struct _kss_kose_object
{
    /** key store holding the data and other properties */
    kss_kose_key_store_t *keyStore;
    /** @copydoc kss_object_t::objectType */
    uint32_t objectType;
    /** @copydoc kss_object_t::cipherType */
    uint32_t cipherType;
    /** Application specific key identifier. The keyId is kept in the key  store
     * along with the key data and other properties. */
    uint32_t keyId;

    /** If this is an ECC Key, the Curve ID of the key */
    KOSE_ECCurve_t curve_id;

    /** Whether this is a persistant or tansient object */
    uint8_t isPersistant : 1;

} kss_kose_object_t;

/** @copydoc kss_derive_key_t */
typedef struct
{
    /** @copydoc kss_derive_key_t::session */
    kss_kose_session_t *session;
    /** @copydoc kss_derive_key_t::keyObject */
    kss_kose_object_t *keyObject;
    /** @copydoc kss_derive_key_t::algorithm */
    kss_algorithm_t algorithm;
    /** @copydoc kss_derive_key_t::mode */
    kss_mode_t mode;

} kss_kose_derive_key_t;

/** @copydoc kss_asymmetric_t */
typedef struct
{
    /** @copydoc kss_asymmetric_t::session */
    kss_kose_session_t *session;
    /** @copydoc kss_asymmetric_t::keyObject */
    kss_kose_object_t *keyObject;
    /** @copydoc kss_asymmetric_t::algorithm */
    kss_algorithm_t algorithm;
    /** @copydoc kss_asymmetric_t::mode */
    kss_mode_t mode;

} kss_kose_asymmetric_t;

/** @copydoc kss_symmetric_t */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    kss_kose_session_t *session;
    /** Reference to key and it's properties. */
    kss_kose_object_t *keyObject;
    /** @copydoc kss_symmetric_t::algorithm */
    kss_algorithm_t algorithm;
    /** @copydoc kss_symmetric_t::mode */
    kss_mode_t mode;

    /* Implementation specific part */

    /** Used crypto object ID for this operation */
    KOSE_CryptoObjectID_t cryptoObjectId;
    /** Since underlying system conly only process in fixed chunks, chache them on host
     * to complete the operation sanely */
    uint8_t cache_data[16];
    /** Length of bytes cached on host */
    size_t cache_data_len;
} kss_kose_symmetric_t;

/** @copydoc kss_mac_t */
typedef struct
{
    /** copydoc kss_mac_t::session */
    kss_kose_session_t *session;
    /** copydoc kss_mac_t::keyObject */
    kss_kose_object_t *keyObject;

    /** copydoc kss_mac_t::algorithm */
    kss_algorithm_t algorithm;
    /** copydoc kss_mac_t::mode */
    kss_mode_t mode;
    /* Implementation specific part */

    /** Used crypto object ID for this operation */
    KOSE_CryptoObjectID_t cryptoObjectId;
} kss_kose_mac_t;

/** @copydoc kss_aead_t */
typedef struct
{
    /** @copydoc kss_aead_t::session */
    kss_kose_session_t *session;
    /** @copydoc kss_aead_t::keyObject */
    kss_kose_object_t *keyObject;
    /** @copydoc kss_aead_t::algorithm */
    kss_algorithm_t algorithm;
    /** @copydoc kss_aead_t::mode */
    kss_mode_t mode;

    /** Implementation specific part */
    KOSE_CryptoObjectID_t cryptoObjectId;
    /** Cache in case of un-alined inputs */
    uint8_t cache_data[16];
    /** How much we have cached  */
    size_t cache_data_len;
} kss_kose_aead_t;

/** @copydoc kss_digest_t */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    kss_kose_session_t *session;
    /** @copydoc kss_digest_t::algorithm */
    kss_algorithm_t algorithm;
    /** @copydoc kss_digest_t::mode */
    kss_mode_t mode;
    /** @copydoc kss_digest_t::digestFullLen */
    size_t digestFullLen;
    /** Implementation specific part */

    KOSE_CryptoObjectID_t cryptoObjectId;
} kss_kose_digest_t;

/** @copydoc kss_rng_context_t */
typedef struct
{
    /** @copydoc kss_rng_context_t::session */
    kss_kose_session_t *session;
} kss_kose_rng_context_t;

/** SE050 Properties that can be represented as an array */
typedef enum
{
    kKSS_KOSE_SessionProp_CertUID = kKSS_SessionProp_au8_Proprietary_Start + 1,
} kss_s05x_sesion_prop_au8_t;

/** SE050 Properties that can be represented as 32bit numbers */
typedef enum
{
    kKSS_KOSE_SessionProp_CertUIDLen = kKSS_SessionProp_u32_Optional_Start + 1,
} kss_s05x_sesion_prop_u32_t;

/** deprecated : Used only for backwards compatibility */
#define KOSE_Connect_Ctx_t SE_Connect_Ctx_t
/** deprecated : Used only for backwards compatibility */
#define kose_auth_context_t SE_Connect_Ctx_t




#if 1
/** Used to enable Applet Features via ``kss_kose_set_feature`` */
typedef struct
{
    /** EC DSA and DH support */
    uint8_t AppletConfig_ECDSA_ECDH_ECDHE : 1;
    /** Use of curve RESERVED_ID_ECC_ED_25519 */
    uint8_t AppletConfig_EDDSA : 1;
    /** Use of curve RESERVED_ID_ECC_MONT_DH_25519 */
    uint8_t AppletConfig_DH_MONT : 1;
    /** Writing HMACKey objects */
    uint8_t AppletConfig_HMAC : 1;
    /** Writing RSAKey objects */
    uint8_t AppletConfig_RSA_PLAIN : 1;
    /** Writing RSAKey objects */
    uint8_t AppletConfig_RSA_CRT : 1;
    /** Writing AESKey objects */
    uint8_t AppletConfig_AES : 1;
    /** Writing DESKey objects */
    uint8_t AppletConfig_DES : 1;
    /** PBKDF2 */
    uint8_t AppletConfig_PBKDF : 1;
    /** TLS Handshake support commands (see 4.16) in APDU Spec*/
    uint8_t AppletConfig_TLS : 1;
    /** Mifare DESFire support (see 4.15)  in APDU Spec*/
    uint8_t AppletConfig_MIFARE : 1;
    /** Allocated value undefined and reserved for future use */
    uint8_t AppletConfig_RFU1 : 1;
    /** I2C Master support (see 4.17)  in APDU Spec*/
    uint8_t AppletConfig_I2CM : 1;
    /** RFU */
    uint8_t AppletConfig_RFU21 : 1;
} KOSE_Applet_Feature_t;

/** Used to disable Applet Features via ``kss_kose_set_feature`` */
typedef struct
{
    /** Disable feature ECDH B2b8 */
    uint8_t EXTCFG_FORBID_ECDH : 1;
    /** Disable feature RSA_LT_2K B6b8 */
    uint8_t EXTCFG_FORBID_RSA_LT_2K : 1;
    /** Disable feature RSA_SHA1 B6b7 */
    uint8_t EXTCFG_FORBID_RSA_SHA1 : 1;
    /** Disable feature AES_GCM B8b8 */
    uint8_t EXTCFG_FORBID_AES_GCM : 1;
    /** Disable feature AES_GCM_EXT_IV B8b7 */
    uint8_t EXTCFG_FORBID_AES_GCM_EXT_IV : 1;
    /** Disable feature HKDF_EXTRACT B10b7 */
    uint8_t EXTCFG_FORBID_HKDF_EXTRACT : 1;
} KOSE_Applet_Feature_Disable_t;

/** @} */

/** @addtogroup kose_attest
 *
 * @{ */

/** Attestation data */
typedef struct
{
#if !KSS_HAVE_KOSE_VER_GTE_07_02
    /** Random used during attestation */
    uint8_t outrandom[16];
    /** length of outrandom */
    size_t outrandomLen;
#endif
    /** time stamp */
    Kose_TimeStamp_t timeStamp;
    /** Length of timeStamp */
    size_t timeStampLen;
    /** Uinquie ID of SE050 */
    uint8_t chipId[KOSE_MODULE_UNIQUE_ID_LEN];
    /** Lenght of the Unique ID */
    size_t chipIdLen;
    /** Attributes */
    uint8_t attribute[MAX_POLICY_BUFFER_SIZE + 15];
    /** Length of Attribute */
    size_t attributeLen;
#if KSS_HAVE_KOSE_VER_GTE_07_02
    /** capdu for attestation */
    uint8_t cmd[100];
    /** capdu Length of attestation */
    size_t cmdLen;
    /** object size */
    uint8_t objSize[2];
    /** object size Length */
    size_t objSizeLen;
#endif
    /** Signature for attestation */
    uint8_t signature[512];
    /** Length of signature */
    size_t signatureLen;
} kss_kose_attst_comp_data_t;

/** Data to be read with attestation */
typedef struct
{
    /** Whle reading RSA Objects, modulus and public exporent get attested separately, */
    kss_kose_attst_comp_data_t data[KOSE_MAX_ATTST_DATA];
    /** How many entries to attest */
    uint8_t valid_number;
} kss_kose_attst_data_t;

/** @} */

/** @addtogroup se050_i2cm
 *
 * @{ */

/** Types of entries in an I2CM Transaction */
typedef enum
{
    /** Do nothing */
    kKOSE_I2CM_None = 0,
    /** Configure the address, baudrate  */
    kKOSE_I2CM_Configure,
    /** Write to I2C Slave  */
    kKOSE_I2CM_Write = 3,
    /** Read from I2C Slave  */
    kKOSE_I2CM_Read,

    /** Response from KOSE that there is something wrong */
    kKOSE_I2CM_StructuralIssue = 0xFF
} KOSE_I2CM_TLV_type_t;

/** Status of I2CM Transaction */
typedef enum
{
    kKOSE_I2CM_Success               = 0x5A,
    kKOSE_I2CM_I2C_Nack_Fail         = 0x01,
    kKOSE_I2CM_I2C_Write_Error       = 0x02,
    kKOSE_I2CM_I2C_Read_Error        = 0x03,
    kKOSE_I2CM_I2C_Time_Out_Error    = 0x05,
    kKOSE_I2CM_Invalid_Tag           = 0x11,
    kKOSE_I2CM_Invalid_Length        = 0x12,
    kKOSE_I2CM_Invalid_Length_Encode = 0x13,
    kKOSE_I2CM_I2C_Config            = 0x21
} KOSE_I2CM_status_t;

/** Additional operation on data read by I2C */
typedef enum
{
    kKOSE_Security_None = 0,
    kKOSE_Sign_Request,
    kKOSE_Sign_Enc_Request,
} KOSE_I2CM_securityReq_t;

/** Configuration for I2CM */
typedef enum
{
    kKOSE_I2CM_Baud_Rate_100Khz = 0,
    kKOSE_I2CM_Baud_Rate_400Khz,
} KOSE_I2CM_Baud_Rate_t;

/** Data Configuration for I2CM */
typedef struct
{
    /** 7 Bit address of I2C slave */
    uint8_t I2C_addr;
    /** What baud rate */
    KOSE_I2CM_Baud_Rate_t I2C_baudRate;
    /** return status  of the config operation */
    KOSE_I2CM_status_t status;
} KOSE_I2CM_configData_t;

/** @brief Security Configuration for I2CM */
typedef struct
{
    /**  @copydoc KOSE_I2CM_securityReq_t */
    KOSE_I2CM_securityReq_t operation;
    /** object used for the operation */
    uint32_t keyObject;
} KOSE_I2CM_securityData_t;

/** @brief Write From I2CM to I2C Slave */
typedef struct
{
    /** How many bytes to write */
    uint8_t writeLength;
    /** [Out] status of the operation */
    KOSE_I2CM_status_t wrStatus;
    /** Buffer to be written */
    uint8_t *writebuf; /* Input */
} KOSE_I2CM_writeData_t;

/**  Read to I2CM from I2C Slave */
typedef struct
{
    /** How many bytes to read */
    uint16_t readLength;
    /** [Out] status of the operation */
    KOSE_I2CM_status_t rdStatus;
    /** Output. rdBuf will point to Host buffer.  */
    uint8_t *rdBuf;
} KOSE_I2CM_readData_t;

/** Used to report error response, not for outgoing command */
typedef struct
{
    /** [Out] In case there is any structural issue */
    KOSE_I2CM_status_t issueStatus;
} KOSE_I2CM_structuralIssue_t;

/** @brief Individual entry in array of TLV commands */
typedef union {
    /** @copydoc KOSE_I2CM_configData_t */
    KOSE_I2CM_configData_t cfg;
    /** @copydoc KOSE_I2CM_securityData_t */
    KOSE_I2CM_securityData_t sec;
    /** @copydoc KOSE_I2CM_writeData_t */
    KOSE_I2CM_writeData_t w;
    /** @copydoc KOSE_I2CM_readData_t */
    KOSE_I2CM_readData_t rd;
    /** @copydoc KOSE_I2CM_structuralIssue_t */
    KOSE_I2CM_structuralIssue_t issue;
} KOSE_I2CM_INS_type_t;

/** Individual entry in array of TLV commands, with type
 *
 * @ref Kose_i2c_master_txn would expect an array of these.
 */
typedef struct _KOSE_I2CM_cmd
{
    /** @copybrief KOSE_I2CM_TLV_type_t */
    KOSE_I2CM_TLV_type_t type;
    /** @copybrief KOSE_I2CM_INS_type_t */
    KOSE_I2CM_INS_type_t cmd;
} KOSE_I2CM_cmd_t;

/*!
 *@}
 */ /* end of se050_i2cm */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

/**
 * @addtogroup kss_kose_mac
 * @{
 */

/** MAC Validate
 *
 */
kss_status_t kss_kose_mac_validate_one_go(
    kss_kose_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t macLen);

/*! @} */ /* end of : kss_kose_mac */

/**
 * @addtogroup kss_kose_asym
 * @{
 */
/** Similar to @ref kss_kose_asymmetric_sign_digest,
 *
 * but hashing/digest done by SE
 */
kss_status_t kss_kose_asymmetric_sign(
    kss_kose_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen);

/** Similar to @ref kss_kose_asymmetric_verify_digest,
 * but hashing/digest done by SE
 *
 */
kss_status_t kss_kose_asymmetric_verify(kss_kose_asymmetric_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    const uint8_t *signature,
    size_t signatureLen);

/*! @} */ /* end of : kss_kose_asym */

/** @addtogroup kose_attest
 *
 * @{ */

/** Read with attestation
 *
 */
kss_status_t kss_kose_key_store_get_key_attst(kss_kose_key_store_t *keyStore,
    kss_kose_object_t *keyObject,
    uint8_t *key,
    size_t *keylen,
    size_t *pKeyBitLen,
    kss_kose_object_t *keyObject_attst,
    kss_algorithm_t algorithm_attst,
    uint8_t *random_attst,
    size_t randomLen_attst,
    kss_kose_attst_data_t *attst_data);

/*!
 *@}
 */ /* end of kose_attest */

uint32_t kose_kssKeyTypeLenToCurveId(kss_cipher_type_t keyType, size_t keyBits);

/** @addtogroup se050_i2cm
 *
 * @{
*/

/** @brief Kose_i2c_master_txn
*
* I2CM Transaction
*
* @param[in] sess session identifier
* @param[in,out] cmds Array of structure type capturing a sequence of i2c master cmd/rsp transactions.
* @param[in] cmdLen Amount of structures contained in cmds
*
* @pre p describes I2C master commands.
* @post p contains execution state of I2C master commands, the I2C master commands can be overwritten to report on execution failure.
*/
smStatus_t Kose_i2c_master_txn(kss_session_t *sess, KOSE_I2CM_cmd_t *cmds, uint8_t cmdLen);

/** @brief Kose_i2c_master_attst_txn
 *
 * I2CM Read With Attestation
 *
 * @param[in] sess session identifier
 * @param[in] keyObject Keyobject which contains  4 byte attestaion KeyId
 * @param[in,out] p Array of structure type capturing a sequence of i2c master cmd/rsp transactions.
 * @param[in] random_attst 16-byte freshness random
 * @param[in] random_attstLen length of freshness random
 * @param[in] attst_algo 1 byte attestationAlgo
 * @param[in] pattest_data Data Related to Attestation process
 * @param[out] rspbuffer  The read response
 * @param[out] rspbufferLen Length of the response
 * @param[in] noOftags Amount of structures contained in ``p``
 *
 * @pre p describes I2C master commands.
 * @post p contains execution state of I2C master commands, the I2C master commands can be overwritten to report on execution failure.
 */
smStatus_t Kose_i2c_master_attst_txn(kss_session_t *sess,
    kss_object_t *keyObject,
    KOSE_I2CM_cmd_t *p,
    uint8_t *random_attst,
    size_t random_attstLen,
    KOSE_AttestationAlgo_t attst_algo,
    kss_kose_attst_comp_data_t *pattest_data,
    uint8_t *rspbuffer,
    size_t *rspbufferLen,
    uint8_t noOftags);

/*!
 *@}
 */ /* end of se050_i2cm */

/**
 * Returns the applet version compiled by MW
 */
uint32_t kose_GetAppletVersion(void);
#endif

#endif /* KSS_APIS_INC_FSL_KSS_KOSE_TYPES_H_ */
