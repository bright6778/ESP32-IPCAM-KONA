/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

/** @file */
#ifdef __cplusplus
extern "C" {
#endif

#include "kona_kss_kose_types.h"
#include "kose_APDU_impl.h"
#include "kona_kss_api.h"
#include "kose_tlv.h"
#include "ensure.h"
#include "kona_kss_debug.h"
#include "scp03_Types.h"
#include "kona_kss_ftr_default.h"
#include "kss_kose_session.h"
#ifdef ESP_PLATFORM
#include "kss_kose_uart.h"
#endif


static const char *TAG = "kss_kose_session.c";

#ifdef ESP_PLATFORM
static smStatus_t kss_kose_TXn(struct KoseSession *pSession,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen)
{
    smStatus_t ret     = SM_NOT_OK;
    
    if (pSession->connType == kType_SE_Conn_Type_UART) {
        int rcvlen_int = (int)(*rspLen);
        ret = kss_kose_uart_transceive(cmdBuf, cmdBufLen, rsp, &rcvlen_int);
        *rspLen = (size_t)rcvlen_int;
    }
    
    return ret;
}
#endif

kss_status_t kss_kose_session_create(kss_kose_session_t *session)
{
    kss_status_t retval = kStatus_KSS_Success;
    AX_UNUSED_ARG(session);
    /* Nothing special to be handled */
    return retval;
}

kss_status_t kss_kose_session_open(kss_kose_session_t *session,
    kss_type_t subsystem,
    uint32_t application_id,
    kss_connection_type_t connection_type,
    void *connectionData)
{
    LOGD(TAG, "kss_kose_session_open start");
    kss_status_t retval             = kStatus_KSS_Success;
    SE_Connect_Ctx_t *pAuthCtx      = NULL;
    smStatus_t status               = SM_NOT_OK;
    pKoseSession_t koseSession;

    ENSURE_OR_RETURN_ON_ERROR(session, kStatus_KSS_Fail);
    koseSession = &session->s_ctx;
    memset(session, 0, sizeof(*session));
    
    pAuthCtx = (SE_Connect_Ctx_t *)connectionData;
    if (pAuthCtx->connType == kType_SE_Conn_Type_UART) {
        koseSession->conn_ctx = pAuthCtx->conn_ctx;
        koseSession->connType = pAuthCtx->connType;
#ifdef ESP_PLATFORM
        if(koseSession->conn_ctx == NULL){
            LOGD(TAG, "conn_ctx == NULL");
            koseSession->conn_ctx = calloc(1, sizeof(kss_kose_uart_ctx_t));
            set_se_uart_init_default(koseSession->conn_ctx);
        }
        if(kss_kose_uart_init(koseSession->conn_ctx) == false){
            retval = kStatus_KSS_Fail;
            return retval;
        }
        koseSession->fp_TXn = &kss_kose_TXn;
#else
    koseSession->fp_TXn = koseSession->conn_ctx;
#endif
    }

    uint8_t rcvbuf[256] = {0};
    size_t rcvlen;

    status = Kose_API_Select(koseSession, rcvbuf, &rcvlen);
    if (status == SM_OK) {
        session->subsystem = subsystem;
        retval             = kStatus_KSS_Success;
    }
    else {
        /* Retain the APDU throughput error. Any other error, pass generic kStatus_KSS_Fail */
        if (retval != kStatus_KSS_ApduThroughputError) {
            retval = kStatus_KSS_Fail;
        }
    }

    if (retval != kStatus_KSS_Success) {
        memset(koseSession, 0x00, sizeof(*koseSession));
    }

    return retval;
}

void kss_kose_session_close(kss_kose_session_t *session){
#ifdef ESP_PLATFORM
#ifdef CONNECT_SE_UART
   kss_kose_uart_close();
#endif  // CONNECT_SE_UART
#endif  // ESP_PLATFORM
   memset(session, 0, sizeof(*session));
}

#ifdef __cplusplus
}
#endif