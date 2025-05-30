/*
 *
 * Copyright 2018-2020 NXP
 * Copyright 2025 KONA I
 * SPDX-License-Identifier: Apache-2.0
 */
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

/** @file */
#ifdef __cplusplus
extern "C" {
#endif

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
    
//#ifdef CONNECT_SE_UART
#if 0
    if(koseSession->conn_ctx == NULL){
        LOGD(TAG, "conn_ctx == NULL");
        koseSession->conn_ctx = calloc(1, sizeof(kss_kose_uart_ctx_t));
        set_se_uart_init_default(koseSession->conn_ctx);
    }
    if(kss_kose_uart_init(koseSession->conn_ctx) == false){
        retval = kStatus_KSS_Fail;
        goto exit;
    }
#endif
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
#if 0
        sm_connected = 1;

        if (1 == pAuthCtx->skip_select_applet) {
            status = (smStatus_t)status;
            /* Not selecting the applet, so we don't know whether it's old or new */
        }
        else {
            koseSession->applet_version = (0xFFFFFF00 & CommState.appletVersion);
#if ENABLE_APPLET_VERSION_CHECK
            if (HEX_EXPECTED_APPLET_VERSION == (0xFFFFFF00 & CommState.appletVersion)) {
                /* Fine */
            }
#if defined(HEX_EXPECTED_APPLET_VERSION_PATCH1)
            else if (HEX_EXPECTED_APPLET_VERSION_PATCH1 == (0xFFFFFF00 & CommState.appletVersion)) {
                /* Fine */
            }
#endif
            else if ((0xFFFFFF00 & CommState.appletVersion) < HEX_EXPECTED_APPLET_VERSION) {
                LOG_E("Mismatch Applet version.");
                LOG_E("Compiled for 0x%X. Got older 0x%X",
                    (HEX_EXPECTED_APPLET_VERSION) >> 8,
                    (CommState.appletVersion) >> 8);
                LOG_E("Aborting!!!");
                LOG_E("Use a library with adjusted PTMW_SE05X_Ver compile time setting");
                SM_Close(koseSession->conn_ctx, 0);
                sm_connected = 0;
                retval       = kStatus_KSS_Fail;
                goto exit;
            }
            else {
                LOG_I("Newer version of Applet Found");
                LOG_I("Compiled for 0x%X. Got newer 0x%X",
                    (HEX_EXPECTED_APPLET_VERSION) >> 8,
                    (CommState.appletVersion) >> 8);
            }
#else
            LOGD(TAG, "KONA secure element version");
#endif
        }
#endif
    }

    // KOSE Select
    koseSession->fp_TXn = &kss_kose_TXn;
    uint8_t rcvbuf[256] = {0};
    size_t rcvlen;

    if((Kose_API_Select(koseSession, rcvbuf, &rcvlen)) != SM_OK){
        retval = kStatus_KSS_Fail;
        goto exit;
    }
    
    status = SM_OK;

#ifdef KSS_USE_SCP03_THREAD_SAFETY /* Disabled by default. Enable in case of multiple applications access platform SCP03 session */
#if KSS_HAVE_SCP_SCP03_KSS
    if (pAuthCtx->auth.authType == kKSS_AuthType_SCP03) {
#if defined(USE_RTOS) && (USE_RTOS == 1)
        koseSession->scp03_lock = xSemaphoreCreateMutex();
        if (koseSession->scp03_lock == NULL) {
            LOG_E("xSemaphoreCreateMutex failed");
            return kStatus_KSS_Fail;
        }
        else {
            koseSession->scp03_lock_init = 1;
            LOG_D("Mutex Init successfull");
        }
#elif (__GNUC__ && !AX_EMBEDDED)
        if (pthread_mutex_init(&koseSession->scp03_lock, NULL) != 0) {
            LOG_E("\n mutex init has failed");
            return kStatus_KSS_Fail;
        }
        else {
            koseSession->scp03_lock_init = 1;
            LOG_D("Mutex Init successfull");
        }
#endif
    }
#endif //#if KSS_HAVE_SCP_SCP03_KSS
#endif //#if KSS_USE_SCP03_THREAD_SAFETY
#if 0
    if (pAuthCtx->auth.authType == kKSS_AuthType_ECKey) {
        ENSURE_OR_GO_EXIT(pAuthCtx->auth.ctx.eckey.pDyn_ctx);
        if (CommState.appletVersion == 0) {
            /*Get Applet version from previously opened session*/
            uint8_t appletVersion[32]          = {0};
            uint8_t versionIterator            = 0;
            size_t appletVersionLen            = sizeof(appletVersion);
            sss_kose_session_t *kose_session = (sss_kose_session_t *)pAuthCtx->tunnelCtx->session;
            status = Se05x_API_GetVersion(&kose_session->s_ctx, appletVersion, &appletVersionLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                retval = kStatus_KSS_ApduThroughputError;
                goto exit;
            }
            if (status != SM_OK) {
                LOG_E("Unable to retrive applet version");
                retval = kStatus_KSS_Fail;
                goto exit;
            }
            for (versionIterator = 0; versionIterator < 3; versionIterator++) {
                CommState.appletVersion = CommState.appletVersion << 8 | appletVersion[versionIterator];
            }
            CommState.appletVersion = CommState.appletVersion << 8;
        }
        if (CommState.appletVersion >= 0x03050000) {
            pAuthCtx->auth.ctx.eckey.pDyn_ctx->authType = kKSS_AuthType_INT_ECKey_Counter;
        }
        else {
            pAuthCtx->auth.ctx.eckey.pDyn_ctx->authType = kKSS_AuthType_ECKey;
        }
    }

    koseSession->fp_TXn    = &sss_kose_TXn;
    koseSession->fp_RawTXn = &sss_kose_channel_txn;

    /* Auth type is None */
    if (1 == pAuthCtx->skip_select_applet) {
        /* Not selecting the applet */
    }
    else {
        if ((pAuthCtx->auth.authType == kKSS_AuthType_None) && (connection_type == kKSS_ConnectionType_Plain)) {
            LOG_W("Communication channel is Plain.");
            LOG_W("!!!Not recommended for production use.!!!");
            koseSession->fp_Transform = &kose_Transform;
            koseSession->fp_DeCrypt   = &kose_DeCrypt;
            koseSession->authType     = kKSS_AuthType_None;
            status                     = SM_OK;
        }
    }
#endif

#if KSS_HAVE_SCP_SCP03_SSS
    /* Auth type is Platform SCP03 */
    if ((pAuthCtx->auth.authType == kKSS_AuthType_SCP03) && (connection_type == kKSS_ConnectionType_Encrypted)) {
        //koseSession->fp_Transform = &kose_Transform;
        //koseSession->fp_DeCrypt   = &kose_DeCrypt;
        koseSession->authType     = kKSS_AuthType_SCP03;
        status                     = SM_NOT_OK;
        //retval                     = scp03_AuthenticateChannel(koseSession, &pAuthCtx->auth.ctx.scp03);
        if (retval == kStatus_KSS_Success) {
            /* There is a differnet behaviour of Platform SCP between SE050 and future applet.
             * Here we switch make it clear. */
            /*
            if (CommState.appletVersion >= 0x04030000) {
                pAuthCtx->auth.ctx.scp03.pDyn_ctx->authType = (SE_AuthType_t)kKSS_AuthType_AESKey;
            }
            else {
                pAuthCtx->auth.ctx.scp03.pDyn_ctx->authType = (SE_AuthType_t)kKSS_AuthType_SCP03;
            }*/
            /*Auth type to Platform SCP03 again as channel authentication will modify it
            to auth type None*/
            koseSession->authType     = kKSS_AuthType_SCP03;
            //koseSession->pdynScp03Ctx = pAuthCtx->auth.ctx.scp03.pDyn_ctx;
            status                     = SM_OK;
            //koseSession->fp_Transform = &kose_Transform_scp;
        }
        else {
            LOGE(TAG, "Could not set SCP03 Secure Channel");
        }
    }
#else

#endif

#if KSSFTR_SE05X_AuthECKey || KSSFTR_SE05X_AuthSession
    if (pAuthCtx->connType == kType_SE_Conn_Type_Channel) {
        koseSession->pChannelCtx = (struct _sss_kose_tunnel_context *)pAuthCtx->tunnelCtx;
        if (koseSession->pChannelCtx->kose_session->subsystem == kType_KSS_SE_SE05x) {
            koseSession->applet_version = koseSession->pChannelCtx->kose_session->s_ctx.applet_version;
        }
    }

    if ((application_id != 0) &&
        ((connection_type == kKSS_ConnectionType_Password) || (connection_type == kKSS_ConnectionType_Encrypted))) {
#if defined(SMCOM_JRCP_V1_AM)
        {
            // Overwrite session_open_retry_cnt and session_open_retry_dly from env variables
            const char *retry_cnt = NULL;
            const char *retry_dly = NULL;

            retry_cnt = getenv("EX_KSS_SESSION_OPEN_RETRY_CNT");
            if (retry_cnt != NULL) {
                session_open_retry_cnt = atoi(retry_cnt);
                if (session_open_retry_cnt > session_open_retry_cnt_max) {
                    session_open_retry_cnt = session_open_retry_cnt_max;
                }
                LOG_I("Session Open Retry Count ='%d' ", session_open_retry_cnt);
            }

            retry_dly = getenv("EX_KSS_SESSION_OPEN_RETRY_DLY");
            if (retry_dly != NULL) {
                session_open_retry_dly = atoi(retry_dly);
                if (session_open_retry_dly < 1) {
                    session_open_retry_dly = 1;
                }
                if (session_open_retry_dly > session_open_retry_dly_max) {
                    session_open_retry_dly = session_open_retry_dly_max;
                }
                LOG_I("Session Open Retry Delay ='%d' ", session_open_retry_dly);
            }
        }

        do {
            if (session_open_retry_cnt > 0) {
                session_open_retry_cnt--;
            }
            SM_LOCK_CHANNEL();
            retval = sss_session_auth_open(session, subsystem, application_id, connection_type, connectionData);
            SM_UNLOCK_CHANNEL();
            if (retval == kStatus_KSS_Success) {
                break;
            }

            sm_sleep(session_open_retry_dly * 1000);

        } while (session_open_retry_cnt > 0);
#else
        SM_LOCK_CHANNEL();
        retval = sss_session_auth_open(session, subsystem, application_id, connection_type, connectionData);
        SM_UNLOCK_CHANNEL();
#endif

        if (retval == kStatus_KSS_Success) {
            status = SM_OK;
        }
        else {
            status = SM_NOT_OK;
        }
    }
#endif

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
        /*
        if ((sm_connected) && (pAuthCtx->connType != kType_SE_Conn_Type_Channel)) {
            SM_Close(koseSession->conn_ctx, 0);
        }*/

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