
/*
 *
 * Copyright 2018-2020 NXP
 * Copyright 2025 KONA I
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file */
#ifdef __cplusplus
extern "C" {
#endif

#include "kona_kss_api.h"
#include "kss_kose_rng.h"
#include "kose_APDU_impl.h"
#include "ensure.h"
#include "debug.h"

static const char *TAG = "kss_kose_key_rng.c";

kss_status_t kss_kose_rng_context_init(kss_kose_rng_context_t *context, kss_kose_session_t *session)
{
    kss_status_t retval = kStatus_KSS_Success;
    context->session    = session;
    return retval;
}

kss_status_t kss_kose_rng_get_random(kss_kose_rng_context_t *context, uint8_t *random_data, size_t dataLen)
{
//    kss_status_t retval = kStatus_KSS_Fail;
//    smStatus_t status   = SM_NOT_OK;
//    uint8_t *rcvbuf     = NULL;
//    int rcvlen          = 0;

    LOGI(TAG, "kss_kose_rng_get_random");

    kss_status_t retval = kStatus_KSS_Fail;
    smStatus_t status   = SM_NOT_OK;
    size_t chunk        = 0;
    size_t offset       = 0;

    while (dataLen > 0) {
        /* TODO - Replace 512 with max rsp buffer size based on with/without SCP */
        if (dataLen > 250) {
            chunk = 250;
        }
        else {
            chunk = dataLen;
        }
    
        status = Kose_API_GetRandom(&context->session->s_ctx, (uint16_t)chunk, (random_data + offset), &chunk);
        if (status == SM_ERR_APDU_THROUGHPUT) {
            retval = kStatus_KSS_ApduThroughputError;
            goto exit;
        }
        ENSURE_OR_GO_EXIT(status == SM_OK);

        offset += chunk;
        dataLen -= chunk;
    }

    retval = kStatus_KSS_Success;
exit:
    return retval;

#if 0

       // 1. 세션 유효성 체크
       if (context == NULL || context->session == NULL) {
        return kStatus_KSS_Fail;
    }

    rcvbuf = (uint8_t *)malloc(512);
    if (rcvbuf == NULL) {
        retval = kStatus_KSS_Fail;
        goto exit;
    }

    // 2. KOSE Applet 선택
    const uint8_t select_applet_cmd[] = {
        0x00, 0xA4, 0x04, 0x00, 0x09, 0x0F, 0x4B, 0x4F, 0x4E, 0x41, 0x01, 0xFF, 0x80, 0x00
    };

    if (!kss_kose_uart_transceive(select_applet_cmd, sizeof(select_applet_cmd), rcvbuf, &rcvlen)) {
        retval = kStatus_KSS_Fail;
        goto exit;
    }

    // 3. 랜덤 넘버 요청 16바이트
    const uint8_t get_random_cmd[] = {
        0x00, 0x84, 0x00, 0x00, 0x00 
    };

    if (!kss_kose_uart_transceive(get_random_cmd, sizeof(get_random_cmd), rcvbuf, &rcvlen)) {
        retval = kStatus_KSS_Fail;
        goto exit;
    }

    // 4. 결과 복사
    if (rcvlen < dataLen) {
        retval = kStatus_KSS_Fail; // 받은 길이가 기대보다 작을 때
        goto exit;
    }

    memcpy(random_data, rcvbuf, dataLen);
    status = SM_OK;

    retval = kStatus_KSS_Success;

exit:
    if (rcvbuf != NULL) {
        free(rcvbuf);
    }

    return retval;
#endif
}


kss_status_t kss_kose_rng_context_free(kss_kose_rng_context_t *context)
{
    kss_status_t retval = kStatus_KSS_Success;
    memset(context, 0, sizeof(*context));
    return retval;
}

#ifdef __cplusplus
}
#endif