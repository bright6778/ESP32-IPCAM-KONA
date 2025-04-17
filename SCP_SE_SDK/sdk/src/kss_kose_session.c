/*
 *
 * Copyright 2018-2020 NXP
 * Copyright 2025 KONA I
 * SPDX-License-Identifier: Apache-2.0
 */

#include "kss_kose_session.h"
#include "debug.h"

/** @file */
#ifdef __cplusplus
extern "C" {
#endif

static const char *TAG = "kss_kose_session.c";

kss_status_t kss_kose_session_create(kss_kose_session_t *session,
    kss_type_t subsystem,
    uint32_t application_id,
    kss_connection_type_t connection_type,
    void *connectionData)
{
    kss_status_t retval = kStatus_KSS_Success;
    AX_UNUSED_ARG(session);
    AX_UNUSED_ARG(subsystem);
    AX_UNUSED_ARG(application_id);
    AX_UNUSED_ARG(connection_type);
    AX_UNUSED_ARG(connectionData);
    /* Nothing special to be handled */
    return retval;
}
#if 1
kss_status_t kss_kose_session_open(kss_kose_session_t *session,
    kss_type_t subsystem,
    uint32_t application_id,
    kss_connection_type_t connection_type,
    void *connectionData)
{
    kss_status_t retval           = kStatus_KSS_InvalidArgument;

    //Kose_Connect_Ctx_t *pAuthCtx = NULL;
    //SmCommState_t CommState       = {0};
    smStatus_t status             = SM_NOT_OK;
    int sm_connected              = 0;
    //U16 lReturn;
    pKoseSession_t koseSession;
    
#if defined(SMCOM_JRCP_V1_AM)
    int session_open_retry_cnt     = 1;
    int session_open_retry_dly     = 1; //seconds
    int session_open_retry_cnt_max = 50;
    int session_open_retry_dly_max = 10; //seconds
#endif

    ENSURE_OR_RETURN_ON_ERROR(session, kStatus_KSS_Fail);
    koseSession = &session->s_ctx;
    memset(session, 0, sizeof(*session));

#ifdef CONNECT_SE_UART
    //ENSURE_OR_GO_EXIT(connectionData);
    if(koseSession->conn_ctx == NULL){
        set_se_uart_init_default(koseSession->conn_ctx);
    }
    //kss_kose_uart_ctx_t se_uart_init;
    //set_se_uart_init_default(&se_uart_init);
    if(kss_kose_uart_init(koseSession->conn_ctx) == false){
        retval = kStatus_KSS_Fail;
        goto exit;
    }

    // Test Select
    uint8_t *rcvbuf = (uint8_t *)malloc(512); // Loopback + ProcedureBytes + TPDU;
    int rcvlen;
    if(kss_kose_uart_transceive((uint8_t *)"\x00\xa4\x04\x00\x01\xa0", 6, rcvbuf, &rcvlen) == false){
        retval = kStatus_KSS_Fail;
        goto exit;
    }
#endif
    #if 0

    pAuthCtx = (Kose_Connect_Ctx_t *)connectionData;

    if (pAuthCtx->connType != kType_SE_Conn_Type_Channel) {
        uint8_t atr[100];
        uint16_t atrLen    = ARRAY_SIZE(atr);
        CommState.connType = pAuthCtx->connType;
        if (1 == pAuthCtx->skip_select_applet) {
            if (pAuthCtx->auth.authType == kSSS_AuthType_None) {
                CommState.select = SELECT_NONE;
            }
            else if (pAuthCtx->auth.authType == kSSS_AuthType_SCP03) {
                CommState.select = SELECT_SSD;
            }
        }
        if (1 == pAuthCtx->sessionResume) {
            CommState.sessionResume = 1;
        }

        /* AX_EMBEDDED Or Native */
        lReturn = SM_I2CConnect(&(koseSession->conn_ctx), &CommState, atr, &atrLen, pAuthCtx->portName);
        if (lReturn == ERR_APDU_THROUGHPUT) {
            LOG_E("SM_I2CConnect Failed. Status %04X", lReturn);
            retval = kStatus_SSS_ApduThroughputError;
            goto exit;
        }
        if (lReturn != SW_OK) {
            LOG_E("SM_I2CConnect Failed. Status %04X", lReturn);
            retval = kStatus_SSS_Fail;
            goto exit;
        }
        if (atrLen != 0) {
            LOG_AU8_I(atr, atrLen);
        }

        sm_connected = 1;

        if (1 == pAuthCtx->skip_select_applet) {
            status = (smStatus_t)lReturn;
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
                retval       = kStatus_SSS_Fail;
                goto exit;
            }
            else {
                LOG_I("Newer version of Applet Found");
                LOG_I("Compiled for 0x%X. Got newer 0x%X",
                    (HEX_EXPECTED_APPLET_VERSION) >> 8,
                    (CommState.appletVersion) >> 8);
            }
#else
            LOG_I("Compiled for 0x%X. Connected applet Ver 0x%X",
                (HEX_EXPECTED_APPLET_VERSION) >> 8,
                (CommState.appletVersion) >> 8);
#endif
        }
    }
#endif
#if 0
#ifdef SSS_USE_SCP03_THREAD_SAFETY /* Disabled by default. Enable in case of multiple applications access platform SCP03 session */
#if SSS_HAVE_SCP_SCP03_SSS
    if (pAuthCtx->auth.authType == kSSS_AuthType_SCP03) {
#if defined(USE_RTOS) && (USE_RTOS == 1)
        koseSession->scp03_lock = xSemaphoreCreateMutex();
        if (koseSession->scp03_lock == NULL) {
            LOG_E("xSemaphoreCreateMutex failed");
            return kStatus_SSS_Fail;
        }
        else {
            koseSession->scp03_lock_init = 1;
            LOG_D("Mutex Init successfull");
        }
#elif (__GNUC__ && !AX_EMBEDDED)
        if (pthread_mutex_init(&koseSession->scp03_lock, NULL) != 0) {
            LOG_E("\n mutex init has failed");
            return kStatus_SSS_Fail;
        }
        else {
            koseSession->scp03_lock_init = 1;
            LOG_D("Mutex Init successfull");
        }
#endif
    }
#endif //#if SSS_HAVE_SCP_SCP03_SSS
#endif //#if SSS_USE_SCP03_THREAD_SAFETY

    if (pAuthCtx->auth.authType == kSSS_AuthType_ECKey) {
        ENSURE_OR_GO_EXIT(pAuthCtx->auth.ctx.eckey.pDyn_ctx);
        if (CommState.appletVersion == 0) {
            /*Get Applet version from previously opened session*/
            uint8_t appletVersion[32]          = {0};
            uint8_t versionIterator            = 0;
            size_t appletVersionLen            = sizeof(appletVersion);
            sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)pAuthCtx->tunnelCtx->session;
            status = Se05x_API_GetVersion(&se05x_session->s_ctx, appletVersion, &appletVersionLen);
            if (status == SM_ERR_APDU_THROUGHPUT) {
                retval = kStatus_SSS_ApduThroughputError;
                goto exit;
            }
            if (status != SM_OK) {
                LOG_E("Unable to retrive applet version");
                retval = kStatus_SSS_Fail;
                goto exit;
            }
            for (versionIterator = 0; versionIterator < 3; versionIterator++) {
                CommState.appletVersion = CommState.appletVersion << 8 | appletVersion[versionIterator];
            }
            CommState.appletVersion = CommState.appletVersion << 8;
        }
        if (CommState.appletVersion >= 0x03050000) {
            pAuthCtx->auth.ctx.eckey.pDyn_ctx->authType = kSSS_AuthType_INT_ECKey_Counter;
        }
        else {
            pAuthCtx->auth.ctx.eckey.pDyn_ctx->authType = kSSS_AuthType_ECKey;
        }
    }

    koseSession->fp_TXn    = &sss_se05x_TXn;
    koseSession->fp_RawTXn = &sss_se05x_channel_txn;

    /* Auth type is None */
    if (1 == pAuthCtx->skip_select_applet) {
        /* Not selecting the applet */
    }
    else {
        if ((pAuthCtx->auth.authType == kSSS_AuthType_None) && (connection_type == kSSS_ConnectionType_Plain)) {
            LOG_W("Communication channel is Plain.");
            LOG_W("!!!Not recommended for production use.!!!");
            koseSession->fp_Transform = &se05x_Transform;
            koseSession->fp_DeCrypt   = &se05x_DeCrypt;
            koseSession->authType     = kSSS_AuthType_None;
            status                     = SM_OK;
        }
    }

#if SSS_HAVE_SCP_SCP03_SSS
    /* Auth type is Platform SCP03 */
    if ((pAuthCtx->auth.authType == kSSS_AuthType_SCP03) && (connection_type == kSSS_ConnectionType_Encrypted)) {
        koseSession->fp_Transform = &se05x_Transform;
        koseSession->fp_DeCrypt   = &se05x_DeCrypt;
        koseSession->authType     = kSSS_AuthType_SCP03;
        status                     = SM_NOT_OK;
        retval                     = nxScp03_AuthenticateChannel(koseSession, &pAuthCtx->auth.ctx.scp03);
        if (retval == kStatus_SSS_Success) {
            /* There is a differnet behaviour of Platform SCP between SE050 and future applet.
             * Here we switch make it clear. */
            if (CommState.appletVersion >= 0x04030000) {
                pAuthCtx->auth.ctx.scp03.pDyn_ctx->authType = (SE_AuthType_t)kSSS_AuthType_AESKey;
            }
            else {
                pAuthCtx->auth.ctx.scp03.pDyn_ctx->authType = (SE_AuthType_t)kSSS_AuthType_SCP03;
            }
            /*Auth type to Platform SCP03 again as channel authentication will modify it
            to auth type None*/
            koseSession->authType     = kSSS_AuthType_SCP03;
            koseSession->pdynScp03Ctx = pAuthCtx->auth.ctx.scp03.pDyn_ctx;
            status                     = SM_OK;
            koseSession->fp_Transform = &se05x_Transform_scp;
        }
        else {
            LOG_E("Could not set SCP03 Secure Channel");
        }
    }
#else
    if (pAuthCtx->auth.authType != kSSS_AuthType_None && pAuthCtx->auth.authType != kSSS_AuthType_ID) {
        LOG_E(
            "Set the SCP to SCP03_SSS in the build configuration and "
            "recompile.!");
    }

#endif

#if SSSFTR_SE05X_AuthECKey || SSSFTR_SE05X_AuthSession
    if (pAuthCtx->connType == kType_SE_Conn_Type_Channel) {
        koseSession->pChannelCtx = (struct _sss_se05x_tunnel_context *)pAuthCtx->tunnelCtx;
        if (koseSession->pChannelCtx->se05x_session->subsystem == kType_SSS_SE_SE05x) {
            koseSession->applet_version = koseSession->pChannelCtx->se05x_session->s_ctx.applet_version;
        }
    }

    if ((application_id != 0) &&
        ((connection_type == kSSS_ConnectionType_Password) || (connection_type == kSSS_ConnectionType_Encrypted))) {
#if defined(SMCOM_JRCP_V1_AM)
        {
            // Overwrite session_open_retry_cnt and session_open_retry_dly from env variables
            const char *retry_cnt = NULL;
            const char *retry_dly = NULL;

            retry_cnt = getenv("EX_SSS_SESSION_OPEN_RETRY_CNT");
            if (retry_cnt != NULL) {
                session_open_retry_cnt = atoi(retry_cnt);
                if (session_open_retry_cnt > session_open_retry_cnt_max) {
                    session_open_retry_cnt = session_open_retry_cnt_max;
                }
                LOG_I("Session Open Retry Count ='%d' ", session_open_retry_cnt);
            }

            retry_dly = getenv("EX_SSS_SESSION_OPEN_RETRY_DLY");
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
            if (retval == kStatus_SSS_Success) {
                break;
            }

            sm_sleep(session_open_retry_dly * 1000);

        } while (session_open_retry_cnt > 0);
#else
        SM_LOCK_CHANNEL();
        retval = sss_session_auth_open(session, subsystem, application_id, connection_type, connectionData);
        SM_UNLOCK_CHANNEL();
#endif

        if (retval == kStatus_SSS_Success) {
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
        /* Retain the APDU throughput error. Any other error, pass generic kStatus_SSS_Fail */
        if (retval != kStatus_KSS_ApduThroughputError) {
            retval = kStatus_KSS_Fail;
        }
    }
        #endif
exit:
    if (retval != kStatus_KSS_Success) {
        /*
        if ((sm_connected) && (pAuthCtx->connType != kType_SE_Conn_Type_Channel)) {
            SM_Close(koseSession->conn_ctx, 0);
        }*/

        memset(session, 0x00, sizeof(*session));
    }

    return retval;
}
#endif

void kss_kose_session_close(kss_kose_session_t *session){

/*
    smStatus_t sm_status = SM_NOT_OK;
    sm_status = Se05x_API_CloseSession(&session->s_ctx);
    if (sm_status == SM_ERR_APDU_THROUGHPUT) {
        LOG_E("6a66 Error");
    }
    if (session->s_ctx.pChannelCtx == NULL) {
        SM_Close(session->s_ctx.conn_ctx, 0);
    }
    memset(session, 0, sizeof(*session));
    */
   kss_kose_uart_close();
   memset(session, 0, sizeof(*session));
}
#ifdef __cplusplus
}
#endif