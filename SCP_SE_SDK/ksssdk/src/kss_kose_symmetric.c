/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

  /** @file */
#ifdef __cplusplus
extern "C" {
#endif

#include "kss_kose_symmetric.h"
#include "kona_kss_kose_types.h"
#include "kose_APDU_impl.h"
#include "kona_kss_ftr_default.h"
#if KSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "mbedtls/asn1.h"
#include "mbedtls/bignum.h"
#endif
static const char *TAG = "kss_kose_symmetric.c";

static KOSE_CipherMode_t kose_get_cipher_mode(kss_algorithm_t algorithm)
{
    KOSE_CipherMode_t mode;
    switch (algorithm) {
    case kAlgorithm_KSS_AES_ECB:
        mode = kKOSE_CipherMode_AES_ECB_NOPAD;
        break;
    case kAlgorithm_KSS_DES_ECB:
    case kAlgorithm_KSS_DES3_ECB:
        mode = kKOSE_CipherMode_DES_ECB_NOPAD;
        break;
    case kAlgorithm_KSS_AES_CBC:
        mode = kKOSE_CipherMode_AES_CBC_NOPAD;
        break;
    case kAlgorithm_KSS_DES_CBC:
    case kAlgorithm_KSS_DES3_CBC:
        mode = kKOSE_CipherMode_DES_CBC_NOPAD;
        break;
    case kAlgorithm_KSS_AES_CTR:
        mode = kKOSE_CipherMode_AES_CTR;
        break;
    case kAlgorithm_KSS_DES_CBC_ISO9797_M1:
    case kAlgorithm_KSS_DES3_CBC_ISO9797_M1:
        mode = kKOSE_CipherMode_DES_CBC_ISO9797_M1;
        break;
    case kAlgorithm_KSS_DES_CBC_ISO9797_M2:
    case kAlgorithm_KSS_DES3_CBC_ISO9797_M2:
        mode = kKOSE_CipherMode_DES_CBC_ISO9797_M2;
        break;
    default:
        mode = kKOSE_CipherMode_NA;
    }
    return mode;
}

/* ************************************************************************** */
/* Functions : kss_kose_sym                                                   */
/* ************************************************************************** */

kss_status_t kss_kose_symmetric_context_init(kss_kose_symmetric_t *context,
    kss_kose_session_t *session,
    kss_kose_object_t *keyObject,
    kss_algorithm_t algorithm)
{
    LOGD(TAG, "kss_kose_symmetric_context_init");

    kss_status_t retval = kStatus_KSS_Success;
    if (context == NULL) {
        return kStatus_KSS_Fail;
    }
    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    memset(context->iv, 0, sizeof(*context->iv));
    
    return retval;
}

void kss_kose_symmetric_context_free(kss_kose_symmetric_t *context)
{
    memset(context, 0, sizeof(*context));
}

kss_status_t kss_kose_symmetric_encrypt(
    kss_kose_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
#if KSSFTR_KOSE_AES
    
    smStatus_t status = SM_NOT_OK;
    if (context->keyObject == NULL) {
        return kStatus_KSS_Fail;
    }
    
    status = Kose_API_EncryptData(&context->session->s_ctx, context->keyObject->keyId, context->algorithm, context->iv, sizeof(context->iv), srcData, srcLen, destData, destLen);
    if (status == SM_ERR_APDU_THROUGHPUT) {
        retval = kStatus_KSS_ApduThroughputError;
    }
    else if (status == SM_OK) {
        retval = kStatus_KSS_Success;
    }
#else
    AX_UNUSED_ARG(context);
    AX_UNUSED_ARG(srcData);
    AX_UNUSED_ARG(srcLen);
    AX_UNUSED_ARG(destData);
    AX_UNUSED_ARG(destLen);
#endif
    return retval;
}

kss_status_t kss_kose_symmetric_decrypt(
    kss_kose_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    kss_status_t retval = kStatus_KSS_Fail;
#if KSSFTR_KOSE_AES
    smStatus_t status = SM_NOT_OK;

    if (context->keyObject == NULL) {
        return retval;
    }

    status = Kose_API_DecryptData(&context->session->s_ctx, context->keyObject->keyId, context->algorithm, context->iv, sizeof(context->iv), srcData, srcLen, destData, destLen);
    if (status == SM_ERR_APDU_THROUGHPUT) {
        retval = kStatus_KSS_ApduThroughputError;
    }
    else if (status == SM_OK) {
        retval = kStatus_KSS_Success;
    }
#else
    AX_UNUSED_ARG(context);
    AX_UNUSED_ARG(srcData);
    AX_UNUSED_ARG(srcLen);
    AX_UNUSED_ARG(destData);
    AX_UNUSED_ARG(destLen);
#endif
    return retval;
}

#ifdef __cplusplus
}
#endif