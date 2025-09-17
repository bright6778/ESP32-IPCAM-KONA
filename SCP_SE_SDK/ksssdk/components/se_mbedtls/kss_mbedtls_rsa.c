/*
 *
 * Copyright 2018-2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 * Modifications Copyright 2025 KONA I
 */

/**
 * @file kss_mbedtls_rsa.c
 *
 * @par Description
 * Implementation of key association between KSS and mbedtls.
 *
 *****************************************************************************/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/** @ingroup mbed_tls */
/** @{ */

//#if defined(MBEDTLS_RSA_ALT)

#include <kona_kss_util_asn1_der.h>
//#include <nxLog_kss.h>
#include <string.h>

#include "kona_kss_api.h"
//#include "mbedtls/pk_internal.h"
#include "mbedtls/platform.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ssl.h"
//#include "mbedtls/ssl_internal.h"
#include "mbedtls/version.h"
//#include "kss_mbedtls.h"
//#include "kss_mbedtls_rsa.h"
#include "kss_kose_mbedtls.h"
#include "kona_kss_debug.h"

static const char *TAG = "kss_mbedtls_rsa.c";

#if defined(FLOW_VERBOSE) && (FLOW_VERBOSE == 1)
#define LOG_API_CALLS 1
#else
#define LOG_API_CALLS 0
#endif /* FLOW_VERBOSE */

#ifndef LOG_API_CALLS
#define LOG_API_CALLS 1 /* Log by default */
#endif

static size_t kss_rsakey_get_bitlen(const void *ctx);
static int kss_rsakey_sign(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    unsigned char *sig,
    size_t sig_size,
    size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng);
static int kss_rsakey_verify(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    const unsigned char *sig,
    size_t sig_len);
static int kss_rsakey_check_pair(const void *pub, const void *prv);
static int kss_rsakeypair_can_do(mbedtls_pk_type_t type);
static int kss_rsapubkey_can_do(mbedtls_pk_type_t type);
static void kss_rsakeypair_free_func(void *ctx);
static void kss_rsapubkey_free_func(void *ctx);

//extern const mbedtls_pk_info_t kose_mbedtls_rsakeypair_info;
//extern const mbedtls_pk_info_t kose_mbedtls_rsapubkey_info;

int (*sign_func)(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                     const unsigned char *hash, size_t hash_len,
                     unsigned char *sig, size_t sig_size, size_t *sig_len,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng);

const mbedtls_pk_info_t kose_mbedtls_rsakeypair_info = {
    MBEDTLS_PK_RSA,
    "kose_RSA_Keypair",
    &kss_rsakey_get_bitlen,
    &kss_rsakeypair_can_do,
    NULL,
    &kss_rsakey_sign,
    NULL, // decrypt_func,
    NULL, // encrypt_func,
    &kss_rsakey_check_pair,
    NULL, //&ax_rsakey_alloc,
    &kss_rsakeypair_free_func,
    NULL, //&ax_rsakey_debug,
};

const mbedtls_pk_info_t kose_mbedtls_rsapubkey_info = {
    MBEDTLS_PK_RSA,
    "kose_RSA_pubkey",
    &kss_rsakey_get_bitlen,
    &kss_rsapubkey_can_do,
    &kss_rsakey_verify,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    &kss_rsapubkey_free_func,
    NULL,
};

static size_t kss_rsakey_get_bitlen(const void *ctx)
{
    mbedtls_rsa_context *pax_ctx = (mbedtls_rsa_context *)ctx;
    return pax_ctx->len;
}

static int kss_rsakey_verify(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    const unsigned char *sig,
    size_t sig_len)
{
    kss_status_t status = kStatus_KSS_Success;
    kss_asymmetric_t asymVerifyCtx;
    kss_object_t *kssObject = NULL;
    kss_algorithm_t algorithm;
    mbedtls_rsa_context *pax_ctx = (mbedtls_rsa_context *)ctx;

    switch (md_alg) {
    case MBEDTLS_MD_SHA1:
        algorithm = kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA1;
        break;
    case MBEDTLS_MD_SHA224:
        algorithm = kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA224;
        break;
    case MBEDTLS_MD_SHA256:
        algorithm = kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA256;
        break;
    case MBEDTLS_MD_SHA384:
        algorithm = kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA384;
        break;
    case MBEDTLS_MD_SHA512:
        algorithm = kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512;
        break;
    default:
        return 1;
    }
    kssObject = (kss_object_t *)pax_ctx->pKSSObject;

    //LOG_I("%s: Verify using key '0x%08lX'", __FUNCTION__, pax_ctx->pKSSObject->keyId);

    status = kss_asymmetric_context_init(
        &asymVerifyCtx, kssObject->keyStore->session, kssObject, algorithm, kMode_KSS_Verify);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, "kss_asymmetric_context_init verify context Failed.");
        return 1;
    }
    status = kss_asymmetric_verify_digest(&asymVerifyCtx, (uint8_t *)hash, hash_len, (uint8_t *)sig, sig_len);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, "kss_asymmetric_verify_digest Failed.");
        return 1;
    }

    return (0);
}

static int kss_rsakey_sign(void *ctx,
    mbedtls_md_type_t md_alg,
    const unsigned char *hash,
    size_t hash_len,
    unsigned char *sig,
    size_t sig_size,
    size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    int ret            = 0;
    size_t u16_sig_len = 1024;
    kss_asymmetric_t asymVerifyCtx;
    kss_status_t status          = kStatus_KSS_Success;
    kss_object_t *kssObject      = NULL;
    mbedtls_rsa_context *pax_ctx = NULL;
    kss_algorithm_t algorithm;

    pax_ctx   = (mbedtls_rsa_context *)ctx;
    kssObject = (kss_object_t *)pax_ctx->pKSSObject;
    
    switch (md_alg) {
    case MBEDTLS_MD_SHA1:
        algorithm = kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA1;
        break;
    case MBEDTLS_MD_SHA224:
        algorithm = kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA224;
        break;
    case MBEDTLS_MD_SHA256:
        algorithm = kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA256;
        break;
    case MBEDTLS_MD_SHA384:
        algorithm = kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA384;
        break;
    case MBEDTLS_MD_SHA512:
        algorithm = kAlgorithm_KSS_RSASSA_PKCS1_V1_5_SHA512;
        break;
    default:
        return 1;
    }

    status =
        kss_asymmetric_context_init(&asymVerifyCtx, kssObject->keyStore->session, kssObject, algorithm, kMode_KSS_Sign);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, "kss_asymmetric_context_init verify context Failed.");
        return 1;
    }

    status = kss_asymmetric_sign_digest(&asymVerifyCtx, (uint8_t *)hash, hash_len, sig, &u16_sig_len);
    if (status != kStatus_KSS_Success) {
        LOGE(TAG, "kss_asymmetric_sign_digest failed.");
        return 1;
    }

    *sig_len = u16_sig_len;

    return (ret);
}

static int kss_rsakey_check_pair(const void *pub, const void *prv)
{
    return 0;
}

static int kss_rsakeypair_can_do(mbedtls_pk_type_t type)
{
    return (type == MBEDTLS_PK_RSA || type == MBEDTLS_PK_RSASSA_PSS);
}

static int kss_rsapubkey_can_do(mbedtls_pk_type_t type)
{
    return (type == MBEDTLS_PK_RSA || type == MBEDTLS_PK_RSASSA_PSS);
}

static void kss_rsakeypair_free_func(void *ctx)
{
    mbedtls_rsa_context *pax_ctx = (mbedtls_rsa_context *)ctx;
    if (pax_ctx != NULL) {
        mbedtls_free(ctx);
    }
    return;
}

static void kss_rsapubkey_free_func(void *ctx)
{
    mbedtls_rsa_context *pax_ctx = (mbedtls_rsa_context *)ctx;
    if (pax_ctx != NULL) {
        mbedtls_free(ctx);
    }
    return;
}

//#endif /* MBEDTLS_RSA_ALT */

/** @} */
