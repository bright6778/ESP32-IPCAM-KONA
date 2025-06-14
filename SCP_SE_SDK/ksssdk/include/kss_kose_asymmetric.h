/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

#ifndef __KSS_KOSE_ASYMMETRIC_H
#define __KSS_KOSE_ASYMMETRIC_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "kona_kss_kose_types.h"
#include "kona_kss_kose_config.h"
#include "kose_tlv.h"

#ifdef DEBUG_PRINT
#include "debug.h"
#endif

/**
 * @addtogroup kss_kose_asym
 * @{
 */
/** @copydoc kss_asymmetric_context_init
 *
 */
kss_status_t kss_kose_asymmetric_context_init(kss_kose_asymmetric_t *context,
    kss_kose_session_t *session,
    kss_kose_object_t *keyObject,
    kss_algorithm_t algorithm,
    kss_mode_t mode);

/** @copydoc kss_asymmetric_encrypt
 *
 */
kss_status_t kss_kose_asymmetric_encrypt(
    kss_kose_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc kss_asymmetric_decrypt
 *
 */
kss_status_t kss_kose_asymmetric_decrypt(
    kss_kose_asymmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @copydoc kss_asymmetric_sign_digest
 *
 */
kss_status_t kss_kose_asymmetric_sign_digest(
    kss_kose_asymmetric_t *context, const uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);

/** @copydoc kss_asymmetric_verify_digest
 *
 */
kss_status_t kss_kose_asymmetric_verify_digest(kss_kose_asymmetric_t *context,
    const uint8_t *digest,
    size_t digestLen,
    const uint8_t *signature,
    size_t signatureLen);

/** @copydoc kss_asymmetric_context_free
 *
 */
void kss_kose_asymmetric_context_free(kss_kose_asymmetric_t *context);

/*! @} */ /* end of : kss_kose_asym */

#ifdef __cplusplus
}
#endif
#endif