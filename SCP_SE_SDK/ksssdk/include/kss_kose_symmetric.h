/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

#ifndef __KSS_KOSE_SYMMETRIC_H
#define __KSS_KOSE_SYMMETRIC_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "kona_kss_kose_types.h"
#include "kona_kss_kose_config.h"
#include "kose_tlv.h"

#ifdef DEBUG_PRINT
#include "kona_kss_debug.h"
#endif

/**
 * @addtogroup kss_kose_sym
 * @{
 */
/** @copydoc kss_symmetric_context_init
 *
 */
kss_status_t kss_kose_symmetric_context_init(kss_kose_symmetric_t *context,
    kss_kose_session_t *session,
    kss_kose_object_t *keyObject,
    kss_algorithm_t algorithm);

/** @copydoc kss_symmetric_encrypt
 *
 */
kss_status_t kss_kose_symmetric_encrypt(
    kss_kose_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc kss_symmetric_decrypt
 *
 */
kss_status_t kss_kose_symmetric_decrypt(
    kss_kose_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc kss_symmetric_context_free
 *
 */
void kss_kose_symmetric_context_free(kss_kose_symmetric_t *context);

/*! @} */ /* end of : kss_kose_asym */

#ifdef __cplusplus
}
#endif
#endif