/*
 *
 * Copyright 2025 KONA I
 * SPDX-License-Identifier: Apache-2.0
 */

 #if defined(NONSECURE_WORLD)
 #include "veneer_printf_table.h"
 #endif
 
 #if defined(NONSECURE_WORLD)
 #define NEWLINE() DbgConsole_Printf_NSE("\r\n")
 #else
 #define NEWLINE() printf("\r\n")
 #endif
 
 #include <string.h>
 #include <limits.h>
 #include "kose_APDU_impl.h"
 #include "kss_kose_uart.h"

#if 1
// SE Select
smStatus_t KOSE_API_CreateSession(
    pKoseSession_t session_ctx, uint32_t authObjectID, uint8_t *sessionId, size_t *psessionIdLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    //tlvHeader_t hdr      = {{kKOSE_CLA, kKOSE_INS_SELECT, kKOSE_P1_DEFAULT, kKOSE_P2_SESSION_CREATE}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_CMD] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    uint8_t *rcvbuf = (uint8_t *)malloc(512); // Loopback + ProcedureBytes + TPDU;
    int rcvlen;
    if(kss_kose_uart_transceive((uint8_t *)"\x00\xa4\x04\x00\x01\xa0", 6, pRspbuf, &rcvlen) == false){
        //retval = kStatus_KSS_Fail;
        //goto exit;
    }
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CreateSession []");
#endif /* VERBOSE_APDU_LOGS */
/*
    tlvRet = TLVSET_U32("auth", &pCmdbuf, &cmdbufLen, kKOSE_TAG_1, authObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        tlvRet    = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kKOSE_TAG_1, sessionId, psessionIdLen); 
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (smStatus_t)((pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]));
        }
    }

cleanup:
    */
    return retStatus;
}

// SE STORE CERT
smStatus_t KOSE_API_STORE_CERT(
    pKoseSession_t session_ctx, uint32_t authObjectID, uint8_t *sessionId, size_t *psessionIdLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    //tlvHeader_t hdr      = {{kKOSE_CLA, kKOSE_INS_SELECT, kKOSE_P1_DEFAULT, kKOSE_P2_SESSION_CREATE}};
    uint8_t cmdbuf[KOSE_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen                       = 0;
    uint8_t *pCmdbuf                       = &cmdbuf[0];
    int tlvRet                             = 0;
    uint8_t rspbuf[KOSE_MAX_BUF_SIZE_CMD] = {0};
    uint8_t *pRspbuf                       = &rspbuf[0];
    size_t rspbufLen                       = ARRAY_SIZE(rspbuf);
    size_t rspIndex                        = 0;

    uint8_t *rcvbuf = (uint8_t *)malloc(512); // Loopback + ProcedureBytes + TPDU;
    int rcvlen;
    if(kss_kose_uart_transceive((uint8_t *)"\x00\xa4\x04\x00\x01\xa0", 6, pRspbuf, &rcvlen) == false){
        //retval = kStatus_KSS_Fail;
        //goto exit;
    }
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CreateSession []");
#endif /* VERBOSE_APDU_LOGS */
/*
    tlvRet = TLVSET_U32("auth", &pCmdbuf, &cmdbufLen, kKOSE_TAG_1, authObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        tlvRet    = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kKOSE_TAG_1, sessionId, psessionIdLen); 
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (smStatus_t)((pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]));
        }
    }

cleanup:
    */
    return retStatus;
}
#endif
#if 0
smStatus_t Se05x_API_CloseSession(pSe05xSession_t session_ctx)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kKOSE_CLA, kKOSE_INS_MGMT, kKOSE_P1_DEFAULT, kKOSE_P2_SESSION_CLOSE}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t iCnt     = 0;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CloseSession []");
#endif /* VERBOSE_APDU_LOGS */

    if (session_ctx == NULL) {
        return retStatus;
    }

    if (((session_ctx->value[0] || session_ctx->value[1] || session_ctx->value[2] || session_ctx->value[3] ||
            session_ctx->value[4] || session_ctx->value[5] || session_ctx->value[6] || session_ctx->value[7])) &&
        (session_ctx->hasSession == 1)) {
        retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);
        if (retStatus == SM_OK) {
            for (iCnt = 0; iCnt < 8; iCnt++) {
                session_ctx->value[iCnt] = 0;
            }
            session_ctx->hasSession = 0;
        }
    }
    else {
        LOG_D("CloseSession command is sent only if valid Session exists!!!");
    }
    return retStatus;
}

#endif