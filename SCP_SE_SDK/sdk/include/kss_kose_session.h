/////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2025 Kona I Co., Ltd.
// 
// All rights are reserved.
// Proprietary and confidential.
// Unauthorized copying of this file, via any medium is strictly prohibited.
// Any use is subject to an appropriate license granted by Kona I Co., Ltd..
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
//! @file    kss_kose_session.h
//! @brief   SE Session module
/////////////////////////////////////////////////////////////////////////////

#ifndef __KSS_KOSE_SESSION_H
#define __KSS_KOSE_SESSION_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "kona_kss_kose_config.h"
#include "kona_kss_api.h"
#include "kose_tlv.h"
#include "kss_kose_uart.h"

#ifdef DEBUG_PRINT
#include "esp_log.h"
#include "debug.h"
#endif

#define AX_UNUSED_ARG(x) (void)(x)

//uint8_t kose_aid[] = "\x0F\x4B\x4F\x4E\x41\x01\xFF\x80\x00";

#if 0
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

/** Cryptographic sub system */
typedef enum
{
    kType_KSS_SubSystem_NONE,
    /** Software based */
    kType_KSS_mbedTLS
} kss_type_t;
#endif
typedef struct _kss_kose_session
{
    /** Indicates which security subsystem is selected to be used. */
    kss_type_t subsystem;

    /** Connection context to KOSE */

    KoseSession_t s_ctx;

    /** In case connection is tunneled, context to the tunnel */

    //kss_kose_tunnel_context_t *ptun_ctx;
} kss_kose_session_t;

#if 0
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
#endif

static kss_kose_uart_ctx_t se_uart_init;

// Function Declaration
kss_status_t kss_kose_session_create(kss_kose_session_t *session);
    
kss_status_t kss_kose_session_open(kss_kose_session_t *session,
    kss_type_t subsystem,
    uint32_t application_id,
    kss_connection_type_t connection_type,
    void *connectionData);

void kss_kose_session_close(kss_kose_session_t *session);
//void kss_kose_session_delete();


#ifdef __cplusplus
}
#endif
#endif