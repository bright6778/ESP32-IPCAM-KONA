/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

#ifndef KOSE_TLV_H_INC
#define KOSE_TLV_H_INC

#include <string.h>
#include <limits.h>
#include "sm_api.h"
#include "kose_enums.h"
#include "koScp_Types.h"

#define AX_UNUSED_ARG(x) (void)(x)

#define kKOSE_CLA 0x80
#define kKOSE_CLA_00 0x00

typedef enum
{
    SM_NOT_OK = 0xFFFF,                         // Error
    SM_OK = 0x9000,                             // No Error
    SM_ERR_WRONG_LENGTH = 0x6700,               // Wrong length (e.g. C-APDU does not fit into APDU buffer)
    SM_ERR_CONDITIONS_NOT_SATISFIED = 0x6985,   // Conditions not satisfied
    SM_ERR_COMMAND_NOT_ALLOWED = 0x6986,        // Command not allowed - access denied based on object policy
    SM_ERR_SECURITY_STATUS = 0x6982,            // Security status not satisfied
    SM_ERR_WRONG_DATA = 0x6A80,                 // Wrong data provided
    SM_ERR_DATA_INVALID = 0x6984,               // Data invalid - policy set invalid for the given object
    SM_ERR_INCORRECT_DATA_OBJECT = 0x6988,      // Incorrect messaging DOs
    SM_ERR_FILE_FULL = 0x6A84,                  // Not enough memory space available (either transient or persistent memory)
    SM_ERR_APDU_THROUGHPUT = 0x66A6,            // APDU Throughput error
    SM_WRN_RESPONSE_DATA_INCOMPLETE = 0x6100,   // Response data incomplete, 'xx' more bytes available
} smStatus_t;

typedef enum
{
    CRED_DEFAULT = 0x00,
    CRED_EC = 0x01,
    CRED_RSA = 0x02,
    CRED_AES = 0x03,
    CRED_DES = 0x04,
    CRED_BINARY = 0x05,
    CRED_PIN = 0x06,
    CRED_COUNTER = 0x07,
    CRED_PCR = 0x08,
    CRED_OBJECT = 0x09,

    CRED_PUB_EC,
    CRED_PUB_RSA
} eKoseType_t;

/** struct KoseSession represnting a session in KOSE
*
*/
typedef struct KoseSession
{
    /** Array of 8 bytes represnting session value.*/
    uint8_t value[8];
    /** Indicating session is active*/
    uint8_t hasSession : 1;
    /** Type of authentication for the session*/
    SE_AuthType_t authType;
    /** auth ID associated with session*/
    uint32_t auth_id;
    /** Meta Funciton
     *
     * Internall first calls fp_Transform
     * Then calls fp_RawTXn
     * Then calls fp_DeCrypt
     */
    smStatus_t(*fp_TXn)(struct KoseSession * pSession, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rsp, size_t *rspLen);

    /** API called by fp_TXn. Helps handle UserID/Applet/ECKey to transform buffer.
     *
     * But this API never sends any data out over any communication link. */
    smStatus_t(*fp_Transform)(struct KoseSession * pSession,
        /** IN */
        //const tlvHeader_t *inHdr,
        /** IN */
        uint8_t *inCmdBuf,
        /** IN */
        size_t inCmdBufLen,
        /** OUT:
         *  For Session less,
         *      For Platform SCP this will be copy of,  inHDR, with outHdr[0] = outHdr[0] | 0x04
         *      For Plain Session: Same as inHDR
         *
         *  For With Session:
         *      This will be with TLV Header for Wrapped Session Command
         */
        tlvHeader_t *outHdr,
        /** OUT: For Session less, this will be copy of inCmdBuf
         *
         * For session based impelementation, this will have
         * TAG=Session, L=8,V=Session,TAG=TAG1,L=inCmdBufLen,inCmdBuf */
        uint8_t * pTxBuf,
        /** IN,OUT: */
        //size_t * pTxBufLen,
        /** IN */
        uint8_t hasle);

    /** API called by fp_TXn. Helps handle Applet/Fast SCP to decrypt buffer.
    *
    * But this API never reads any data */
    smStatus_t(*fp_DeCrypt)(struct KoseSession * pSession,
        //size_t prevCmdBufLen,
        uint8_t *pInRxBuf,
        //size_t *pInRxBufLen,
        uint8_t hasle);

    /** pdynScp03Ctx holds the dynamic context information for SCP03 channel */
    //NXSCP03_DynCtx_t *pdynScp03Ctx;

    /**Connection Type */
    KSS_Conn_Type_t connType;

    /**Connection data context */
    void *conn_ctx;
    /** Connection data for I2C*/
    int i2c_addr;
    /** applet version*/
    uint32_t applet_version;
} KoseSession_t;

/** KosePolicy_t representing policy in Kose
* KosePolicy_t structure defines a policy in Kose with a policy value
* and its length
*/
typedef struct
{
    /** policy value */
    uint8_t *value;
    /** Length of Policy value */
    size_t value_len;
} KosePolicy_t;

/**Kose_TimeStamp_t Representing timestamp in Kose
*/
typedef struct
{
    /** TimeStamp Array */
    uint8_t ts[12];
} Kose_TimeStamp_t;

/**Kose_ExtendedFeatures_t Representing Extended feature in Kose
*/
typedef struct
{
    /** Extended feature array */
    uint8_t features[30];
} Kose_ExtendedFeatures_t;

/**Kose_AppletFeatures_t Representing features of Kose applet
*/
typedef struct
{
    /** Variant of the Kose applet features. */
    KOSE_Variant_t variant;
    /** Pointer to extended_features. */
    Kose_ExtendedFeatures_t *extended_features;
} Kose_AppletFeatures_t;

typedef Kose_AppletFeatures_t *pKoseAppletFeatures_t;
typedef KoseSession_t *pKoseSession_t;
typedef KosePolicy_t *pKosePolicy_t;

#if defined(VERBOSE_APDU_LOGS) && (VERBOSE_APDU_LOGS == 1)
#define DO_LOG_V(TAG, DESCRIPTION, VALUE) nLog("APDU", NX_LEVEL_DEBUG, #TAG " [" DESCRIPTION "] = 0x%X", VALUE);
#define DO_LOG_A(TAG, DESCRIPTION, ARRAY, ARRAY_LEN) \
    nLog_au8("APDU", NX_LEVEL_DEBUG, #TAG " [" DESCRIPTION "]", ARRAY, ARRAY_LEN);
#else
#define DO_LOG_V(TAG, DESCRIPTION, VALUE)
#define DO_LOG_A(TAG, DESCRIPTION, ARRAY, ARRAY_LEN)
#endif

/** Creates a TLV set for Kose Session*/
#define TLVSET_KoseSession(DESCRIPTION, PBUF, PBUFLEN, TAG, SESSIONID) \
    TLVSET_u8buf(DESCRIPTION, PBUF, PBUFLEN, TAG, SESSIONID->value, sizeof(SESSIONID->value))

/** Creates a TLV set using parameters for KosePolicy information*/
#define TLVSET_KosePolicy(DESCRIPTION, PBUF, PBUFLEN, TAG, POLICY) \
    tlvSet_KosePolicy(DESCRIPTION, PBUF, PBUFLEN, TAG, POLICY)

/** Creates a TLV set with 8-bit unsigned integer value*/
#define TLVSET_U8(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_U8(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

/** Creates a TLV set with -bit unsigned integer value*/
#define TLVSET_U16(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_U16(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

/** Creates a TLV set with 16-bit unsigned integer value*/
#define TLVSET_U16Optional(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_U16Optional(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

/** Creates a TLV set with 32-bit unsigned integer value*/
#define TLVSET_U32(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_U32(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

/** Creates a TLV set with 64-bit unsigned integer value and a specified size*/
#define TLVSET_U64_SIZE(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE,SIZE) \
    tlvSet_U64_size(PBUF, PBUFLEN, TAG, VALUE,SIZE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

/** Creates a TLV set with KeyID*/
#define TLVSET_KeyID(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_KeyID(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

/** Creates a TLV set with maximum attempts value*/
#define TLVSET_MaxAttemps(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_MaxAttemps(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

/** See @ref TLVSET_U8 */
#define TLVSET_AttestationAlgo TLVSET_U8
/** See @ref TLVSET_U8 */
#define TLVSET_CipherMode TLVSET_U8

/** Creates a TLV set with EC Curve value*/
#define TLVSET_ECCurve(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_ECCurve(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

/** See @ref TLVSET_U8 */
#define TLVSET_ECCurveParam TLVSET_U8
/** See @ref TLVSET_U8 */
#define TLVSET_ECSignatureAlgo TLVSET_U8
/** See @ref TLVSET_U8 */
#define TLVSET_EDSignatureAlgo TLVSET_U8
/** See @ref TLVSET_U8 */
#define TLVSET_MacOperation TLVSET_U8
/** See @ref TLVSET_U8 */
#define TLVSET_RSAEncryptionAlgo TLVSET_U8
/** See @ref TLVSET_U8 */
#define TLVSET_RSAKeyComponent TLVSET_U8
/** See @ref TLVSET_U8 */
#define TLVSET_RSASignatureAlgo TLVSET_U8
/** See @ref TLVSET_U8 */
#define TLVSET_DigestMode TLVSET_U8
/** See @ref TLVSET_U8 */
#define TLVSET_Variant tlvSet_u8buf_features
/** See @ref TLVSET_U8 */
#define TLVSET_RSAPubKeyComp TLVSET_U8
/** See @ref TLVSET_U8 */
#define TLVSET_PlatformSCPRequest TLVSET_U8
/** See @ref TLVSET_U8 */
#define TLVSET_MemoryType TLVSET_U8

/** See @ref TLVSET_U8 */
#define TLVSET_CryptoContext TLVSET_U8
/** See @ref TLVSET_U8 */
#define TLVSET_CryptoModeSubType(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    TLVSET_U8(DESCRIPTION, PBUF, PBUFLEN, TAG, ((VALUE).union_8bit))

/** See @ref TLVSET_U16 */
#define TLVSET_CryptoObjectID TLVSET_U16

#define TLVSET_pVoid(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) (0)
#define tlvGet_pVoid(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) (0)

#define TLVSET_u8buf(DESCRIPTION, PBUF, PBUFLEN, TAG, CMD, CMDLEN) \
    tlvSet_u8buf(PBUF, PBUFLEN, TAG, CMD, CMDLEN);                 \
    DO_LOG_A(TAG, DESCRIPTION, CMD, CMDLEN)

#define TLVSET_u8bufOptional(DESCRIPTION, PBUF, PBUFLEN, TAG, CMD, CMDLEN) \
    tlvSet_u8bufOptional(PBUF, PBUFLEN, TAG, CMD, CMDLEN);                 \
    DO_LOG_A(TAG, DESCRIPTION, CMD, CMDLEN)

#define TLVSET_u8bufOptional_ByteShift(DESCRIPTION, PBUF, PBUFLEN, TAG, CMD, CMDLEN) \
    tlvSet_u8bufOptional_ByteShift(PBUF, PBUFLEN, TAG, CMD, CMDLEN);                 \
    DO_LOG_A(TAG, DESCRIPTION, CMD, CMDLEN)


#define TLVSET_u8buf_I2CM(DESCRIPTION, PBUF, PBUFLEN, TAG, CMD, CMDLEN) \
    tlvSet_u8buf_I2CM(PBUF, PBUFLEN, TAG, CMD, CMDLEN);                 \
    DO_LOG_A(TAG, DESCRIPTION, CMD, CMDLEN)


int tlvSet_U8(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint8_t value);
int tlvSet_U16(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint16_t value);
int tlvSet_U16Optional(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint16_t value);
int tlvSet_U32(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint32_t value);
int tlvSet_U64_size(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint64_t value,uint16_t size);
int tlvSet_u8buf(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, const uint8_t *cmd, size_t cmdLen);
int tlvSet_u8bufOptional(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, const uint8_t *cmd, size_t cmdLen);
/* Same as tlvSet_u8bufOptional, but some time, Most Significant Byte needs to be shifted and Plus by 1 */
int tlvSet_u8bufOptional_ByteShift(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, const uint8_t *cmd, size_t cmdLen);
int tlvSet_KosePolicy(const char *description, uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, KosePolicy_t *policy);
int tlvSet_KeyID(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint32_t keyID);
int tlvSet_MaxAttemps(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint16_t maxAttemps);
int tlvSet_ECCurve(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, KOSE_ECCurve_t value);
int tlvSet_u8buf_features(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, pKoseAppletFeatures_t appletVariant);

int tlvGet_U8(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, KOSE_TAG_t tag, uint8_t *pRsp);
int tlvGet_U16(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, KOSE_TAG_t tag, uint16_t *pRsp);
int tlvGet_U32(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, KOSE_TAG_t tag, uint32_t *pRsp);

int tlvGet_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, KOSE_TAG_t tag, uint8_t *rsp, size_t *pRspLen);
int tlvGet_ValueIndex(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, KOSE_TAG_t tag);
int tlvGet_KoseSession(
    uint8_t *buf, size_t *pBufIndex, const size_t bufLen, KOSE_TAG_t tag, pKoseSession_t *pSessionId);
int tlvGet_TimeStamp(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, KOSE_TAG_t tag, Kose_TimeStamp_t *pTs);

//int tlvSet_u8buf_I2CM(uint8_t **buf, size_t *bufLen, Kose_I2CM_TAG_t tag, const uint8_t *cmd, size_t cmdLen);

int tlvGet_SecureObjectType(uint8_t *buf, size_t *pBufIndex, size_t bufLen, KOSE_TAG_t tag, KOSE_SecObjTyp_t *pType);

int tlvGet_Result(uint8_t *buf, size_t *pBufIndex, size_t bufLen, KOSE_TAG_t tag, KOSE_Result_t *presult);

typedef KoseSession_t *pKoseSession_t;

int tlvSet_U8(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint8_t value);
int tlvSet_U16Optional(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint16_t value);
int tlvSet_U16(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint16_t value);
int tlvSet_U32(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint32_t value);
int tlvSet_U64_size(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, uint64_t value, uint16_t size);

int tlvGet_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, KOSE_TAG_t tag, uint8_t *rsp, size_t *pRspLen);
int tlvDataSet_u8buf(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, const uint8_t *cmd, size_t cmdLen);
int tlvDataSet_u8buf_setLength(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, const uint8_t *cmd, size_t cmdLen);
int tlvDataSet_u8buf_len2byte(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, const uint8_t *cmd, size_t cmdLen);
int tlvDataSet_u8buf_len2byte_setLen(uint8_t **buf, size_t *bufLen, KOSE_TAG_t tag, const uint8_t *cmd, size_t cmdLen, size_t setDataLen);
int lvDataSet_u8buf(uint8_t **buf, size_t *bufLen, const uint8_t *cmd, size_t cmdLen);
int DataSet_u8buf(uint8_t **buf, const uint8_t *data, size_t dataLen);
int get_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint8_t *rsp, size_t *pRspLen);

smStatus_t DoAPDUTx_s_Case3(KoseSession_t *pSessionCtx, uint8_t *cmdBuf, size_t cmdBufLen);
smStatus_t DoAPDUTxRx_s_Case2(KoseSession_t *pSessionCtx, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rspBuf, size_t *pRspBufLen);
smStatus_t DoAPDUTxRx_s_Case4(KoseSession_t *pSessionCtx, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rspBuf, size_t *pRspBufLen);

#endif // !KOSE_TLV_H_INC