/*
*
* Copyright 2018,2020 NXP
* SPDX-License-Identifier: Apache-2.0
* Modifications Copyright 2025 KONA I
*/

#ifndef SCP03_TYPES_H_
#define SCP03_TYPES_H_

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */
/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "sm_api.h"
#include "kona_kss_api.h"

/** @addtogroup KOSE_scp03
 *
 * @{ */

/** Defining authentication types in KOSE
*/
typedef enum
{
    /** No authentication */
    kKSS_AuthType_None = 0,
    /** Global platform SCP03 */
    kKSS_AuthType_SCP03 = 1,
    /** (e.g. KOSE) UserID based connection */
    kKSS_AuthType_ID = 2,

    /** (e.g. KOSE) Use AESKey for user authentication
     *
     *  Earlier this was called  kKSS_AuthType_AppletSCP03
     */
    kKSS_AuthType_AESKey = 3,
    /** (e.g. KOSE) Use ECKey for user authentication
     *
     *  Earlier this was called  kKSS_AuthType_FastSCP
     */
    kKSS_AuthType_ECKey = 4,

    /* ================ Internal ======================= */
    /* Not to be selected by end user... directly */

    /**
     * Used internally, not to be set/used by user.
     *
     * For the versions of the applet where we have to add
     * the a counter during KDF.
     */
    kKSS_AuthType_INT_ECKey_Counter = 0x14,

    kKSS_SIZE = 0x7FFFFFFF,
} SE_AuthType_t;

/** @} */

#define kKSS_AuthType_INT_FastSCP_Counter kKSS_AuthType_INT_ECKey_Counter
#define kKSS_AuthType_FastSCP_Counter kKSS_AuthType_INT_ECKey_Counter
#define kKSS_AuthType_FastSCP         kKSS_AuthType_ECKey
#define kKSS_AuthType_AppletSCP03     kKSS_AuthType_AESKey

/** @addtogroup Kose_scp03
 *
 * @{ */

/**
 * Dynamic SCP03 Context.
 *
 * This structure is filled **after** establishing
 * an SCP03 session.
 */
typedef struct
{
    kss_object_t Enc;  //!< session channel encryption key
    kss_object_t Mac;  //!< session command authentication key
    kss_object_t Rmac; //!< session response authentication key
    uint8_t MCV[16];        //!<  MAC chaining value
    uint8_t cCounter[16];   //!<  command counter
    uint8_t SecurityLevel;  //!< security level set

    /** Handle differnt types of auth.. PlatformSCP / AppletSCP */
    SE_AuthType_t authType;
} SCP03_DynCtx_t;

/**
 * Static SCP03 Context.
 *
 * This structure is filled **before** establishing
 * an SCP03 session.
 *
 * Depending on system, these objects may point to keys
 * inside other security system.
 */
typedef struct
{
    /** Key version no to use for chanel
        authentication in SCP03     */
    uint8_t keyVerNo;
    /** Encryption key object */
    kss_object_t Enc;
    kss_object_t Mac; //!< static secure channel authentication key obj
    kss_object_t Dek; //!< data encryption key obj
} SCP03_StaticCtx_t;

/**
* Static and  Dynamic Context in one Context.
*
*
* Depending on system, these objects may point to keys
* inside other security system.
*/
typedef struct
{
    SCP03_StaticCtx_t *pStatic_ctx; //!< .static keys data
    SCP03_DynCtx_t *pDyn_ctx;       //!<  session keys data
} SCP03_AuthCtx_t;

/** Static part of keys for FAST SCP */
typedef struct
{
    /** Host ECDSA Private key */
    kss_object_t HostEcdsaObj;
    /** Host ephemeral ECC key pair */
    kss_object_t HostEcKeypair;
    /** SE ECC public key */
    kss_object_t SeEcPubKey;
    /** Host master Secret */
    kss_object_t masterSec;
} NXECKey03_StaticCtx_t;

/** Keys to connect for a ECKey Connection */
typedef struct
{
    /** The Input/Static part of the ECKey Authentication
     *
     * We start/initiate a session with the keys here.
     */
    NXECKey03_StaticCtx_t *pStatic_ctx;
    /** The Dynamic part of the ECKey Authentication
     *
     * We derive/compute the session keys based on the
     * ``pStatic_ctx``.
     */
    SCP03_DynCtx_t  *pDyn_ctx;   // session keys data
} KOSE_AuthCtx_ECKey_t;

/** UseID / PIN baed authentication object
 *
 * This is required to open an UserID / PIN based session to the SE.
 */
typedef struct
{
    /** The corresponding authentication object on the Host */
    kss_object_t * pObj;
} KOSE_AuthCtx_ID_t;


/** Legacy, only for A71CH with Host Crypto */
typedef struct
{
    kss_object_t pKeyEnc; //!< SSS AES Enc Key object
    kss_object_t pKeyMac; //!< SSS AES Mac Key object
    kss_object_t pKeyDek; //!< SSS AES Dek Key object
} SM_SECURE_SCP03_KEYOBJ;

/** Authentication mechanims */
typedef struct _SE_AuthCtx
{
    /** How exactly we are going to authenticat ot the system.
     *
     * Since ``ctx`` is a union, this is needed to know exactly how
     * we are going to authenticate.
     */

    SE_AuthType_t authType;

    /** Depending on ``authType``, the input and output parameters.
     *
     * This has both input and output parameters.
     *
     * Input is for Keys that are used to initiate the connection.
     * While connecting, session keys/parameters are generated and they
     * are also part of this context.
     *
     * In any case, we connect to only one type
     */
    union {
        /** For PlatformSCP / Applet SCP.
         *
         * Same SCP context will be used for platform and applet scp03 */
        SCP03_AuthCtx_t scp03;

        /** For ECKey  */
        KOSE_AuthCtx_ECKey_t eckey;

        /** For UserID/PIN based based Authentication */
        KOSE_AuthCtx_ID_t idobj;

        /** Legacy, only for A71CH with Host Crypto */
        SM_SECURE_SCP03_KEYOBJ a71chAuthKeys;

        /** Reserved memory for implementation specific extension */
        struct
        {
            uint8_t data[KSS_AUTH_MAX_CONTEXT_SIZE];
        } extension;
    } ctx;
} SE_AuthCtx_t;

/**
 * When connecting to a secure element,
 *
 * Extension of kss_connect_ctx_t
 */
typedef struct
{
    /** to support binary compatibility/check, sizeOfStucture helps */
    //uint16_t sizeOfStucture;
    /** If we need to authenticate, add required objects for authentication */
    SE_AuthCtx_t auth;
    /** If some policy restrictions apply when we connect, point it here */
    //kss_policy_session_u *session_policy;

    /* =================================== */
    /* Implementation specific part starts */
    /* =================================== */

    /** If we connect logically, via some software layer */
    //kss_tunnel_t *tunnelCtx;

    /** How exactly are we going to connect physically */
    KSS_Conn_Type_t connType;

    /** Connection port name for Socket names, etc. */
    const char *portName;

    /** 12C address on embedded devices. */
    //U32 i2cAddress;

    /** UART */
    //kss_kose_uart_ctx_t conn_ctx;
    void* conn_ctx;

    /** Set to 1 if we should resume a session already open with SE */
    uint8_t sessionResume;

    /** If we need to refresh session, KOSE specific */
    //uint8_t refresh_session : 1;

    /** In the case of Key Rotation, and other use cases
     * where we do not select the IoT Applet and skip
     * the selection of the IoT Applet.
     *
     * One of the use cases is to do platform SCP
     * key rotation.
     *
     * When set to 0:
     *  Do not skip IoT Applet selection and run as-is.
     *
     * When set to 1:
     *  Skip selection of card manager.
     *  Skip selection of Applet.
     *
     * Internally, if there is platform SCP selected as
     * Auth mechanism during compile time, the internal
     * logic would Select the card manager. But,
     * skip selection of the Applet.
     *
     */
    uint8_t skip_select_applet : 1;
} SE_Connect_Ctx_t;

/** Wrapper strucutre kss_connect_ctx_t */
typedef struct
{
    /** To support binary compatibility/check, sizeOfStucture helps */
    //uint16_t sizeOfStucture;
    /** If we need to authenticate, add required objects for authentication */
    SE_AuthCtx_t auth;
    /** If some policy restrictions apply when we connect, point it here */
    //kss_policy_session_u *session_policy;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[KSS_CONNECT_MAX_CONTEXT_SIZE];
    } extension;
} kss_connect_ctx_t;

/** @} */

/* Deprecated */

#define KOSE_AuthCtx_t SE_AuthCtx_t

#define kKOSE_AuthType_None kKSS_AuthType_None
#define kKOSE_AuthType_SCP03 kKSS_AuthType_SCP03
#define kKOSE_AuthType_UserID kKSS_AuthType_ID
#define kKOSE_AuthType_AESKey kKSS_AuthType_AESKey
#define kKOSE_AuthType_ECKey kKSS_AuthType_ECKey

/* For backwards compatibility */
#define KOSE_AuthType_t SE_AuthType_t

#endif /* SCP03_TYPES_H_ */
