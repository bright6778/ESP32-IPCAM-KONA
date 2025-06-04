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
#include "debug.h"
#include "scp03_Types.h"
#include "kona_kss_ftr_default.h"
#include "kss_kose_uart.h"
#include "kss_kose_session.h"

static const char *TAG = "kss_kose_session.c";

static smStatus_t kss_kose_TXn(struct KoseSession *pSession,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen)
{
    smStatus_t ret     = SM_NOT_OK;
    tlvHeader_t outHdr = {
        0,
    };
    uint8_t txBuf[KOSE_MAX_BUF_SIZE_CMD] = {
        0,
    };
    size_t txBufLen = sizeof(txBuf);

    const tlvHeader_t *sendHdr = NULL;
    uint8_t *sendBuf           = NULL;
    size_t sendBufLen          = 0;

    KoseSession_t koseSession;
    
    if (pSession->connType == kType_SE_Conn_Type_UART) {
        int rcvlen_int = (int)(*rspLen);  
        ret = kss_kose_uart_transceive(cmdBuf, cmdBufLen, rsp, &rcvlen_int);
        *rspLen = (size_t)rcvlen_int;
    }
    
    return ret;
}

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
    kss_status_t retval             = kStatus_KSS_Success;
    SE_Connect_Ctx_t *pAuthCtx      = NULL;
    SmCommState_t CommState         = {0};
    smStatus_t status               = SM_NOT_OK;
    //int sm_connected              = 0;
    pKoseSession_t koseSession;

    ENSURE_OR_RETURN_ON_ERROR(session, kStatus_KSS_Fail);
    koseSession = &session->s_ctx;
    memset(session, 0, sizeof(*session));
    
    pAuthCtx = (SE_Connect_Ctx_t *)connectionData;
    if (pAuthCtx->connType == kType_SE_Conn_Type_UART) {
        koseSession->conn_ctx = pAuthCtx->conn_ctx;
        koseSession->connType = pAuthCtx->connType;
        
        CommState.connType = pAuthCtx->connType;
        if (1 == pAuthCtx->sessionResume) {
            CommState.sessionResume = 1;
        }

        if(koseSession->conn_ctx == NULL){
            LOGD(TAG, "conn_ctx == NULL");
            koseSession->conn_ctx = calloc(1, sizeof(kss_kose_uart_ctx_t));
            set_se_uart_init_default(koseSession->conn_ctx);
        }
        if(kss_kose_uart_init(koseSession->conn_ctx) == false){
            retval = kStatus_KSS_Fail;
            goto exit;
        }
    }

    // KOSE Select
    koseSession->fp_TXn = &kss_kose_TXn;
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

exit:
    if (retval != kStatus_KSS_Success) {
        memset(koseSession, 0x00, sizeof(*koseSession));
    }

    return retval;
}

void kss_kose_session_close(kss_kose_session_t *session){
#ifdef CONNECT_SE_UART
   kss_kose_uart_close();
#endif
   memset(session, 0, sizeof(*session));
}

#ifdef __cplusplus
}
#endif