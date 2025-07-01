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

#include "kona_kss_api.h"
#include "kss_kose_rng.h"
#include "kose_APDU_impl.h"
#include "ensure.h"
#include "kona_kss_debug.h"

static const char *TAG = "kss_kose_key_rng.c";

kss_status_t kss_kose_rng_context_init(kss_kose_rng_context_t *context, kss_kose_session_t *session)
{
    kss_status_t retval = kStatus_KSS_Success;
    context->session    = session;
    return retval;
}

kss_status_t kss_kose_rng_get_random(kss_kose_rng_context_t *context, uint8_t *random_data, size_t dataLen)
{
    LOGD(TAG, "kss_kose_rng_get_random");

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